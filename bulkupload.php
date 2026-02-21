<?php
// bulk_upload_fixed.php
// Ready-to-paste bulk upload handler for watchlist
// - parses uploaded CSV (expects header with "url" optionally)
// - validates URLs
// - deduplicates within CSV
// - checks existing watchlist (MySQL watchlist table OR watchlist_sample.json fallback)
// - inserts new rows (DB or JSON) and returns a detailed report and downloadable report CSV

error_reporting(E_ALL);
ini_set('display_errors', 1);

// ---- CONFIG ----
$db_host = 'localhost';
$db_user = 'root';
$db_pass = ''; // change if you use a password
$db_name = 'phishing_db';
$sample_json = __DIR__ . '/watchlist_sample.json';
$max_rows = 5000; // safety cap
$report_csv_file = __DIR__ . '/bulk_upload_report.csv';
// ----------------

session_start();

function normalize_url_cmp($u) {
    $u = trim(strtolower($u));
    // remove trailing slash
    $u = rtrim($u, "/");
    return $u;
}

function is_valid_url($u) {
    if (!is_string($u) || $u === '') return false;
    return filter_var($u, FILTER_VALIDATE_URL) !== false;
}

// Connect to DB if possible
$mysqli = @new mysqli($db_host, $db_user, $db_pass, $db_name);
$use_db = false;
if (!$mysqli->connect_errno) {
    $use_db = true;
    // ensure minimal table exists (non-destructive)
    $mysqli->query("CREATE TABLE IF NOT EXISTS watchlist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        url VARCHAR(2083) NOT NULL,
        schedule VARCHAR(32) DEFAULT 'Daily',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// Load existing URLs for duplicate check (from DB or JSON)
$existing_urls = []; // keys: normalized url
if ($use_db) {
    $res = $mysqli->query("SELECT url FROM watchlist");
    if ($res) {
        while ($r = $res->fetch_assoc()) {
            $existing_urls[ normalize_url_cmp($r['url']) ] = true;
        }
        $res->free();
    }
} else {
    if (file_exists($sample_json)) {
        $j = json_decode(@file_get_contents($sample_json), true) ?: [];
        foreach ($j as $entry) {
            if (isset($entry['url'])) $existing_urls[ normalize_url_cmp($entry['url']) ] = true;
        }
    }
}

$action_report = []; // array of ['url','action','reason']
$parsed_rows = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['csv_file'])) {
        $action_report[] = ['url'=>'','action'=>'error','reason'=>'No file uploaded.'];
    } else {
        $f = $_FILES['csv_file'];
        if ($f['error'] !== UPLOAD_ERR_OK) {
            $action_report[] = ['url'=>'','action'=>'error','reason'=>'Upload error code: '.$f['error']];
        } else {
            $tmp = $f['tmp_name'];
            $name = basename($f['name']);
            $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            if ($ext !== 'csv' && $ext !== 'txt') {
                $action_report[] = ['url'=>'','action'=>'error','reason'=>'Only .csv files allowed.'];
            } else {
                // parse CSV
                $rows = [];
                if (($h = fopen($tmp, 'r')) !== false) {
                    $rownum = 0;
                    while (($row = fgetcsv($h)) !== false) {
                        $rownum++;
                        // skip pure-empty
                        $allEmpty = true;
                        foreach ($row as $c) if (trim($c) !== '') { $allEmpty = false; break; }
                        if ($allEmpty) continue;
                        // handle header: if first row contains 'url' keyword, skip header
                        if ($rownum === 1 && preg_grep('/url/i', $row)) continue;

                        $url = isset($row[0]) ? trim($row[0]) : '';
                        $schedule = isset($row[1]) ? trim($row[1]) : 'Daily';
                        $rows[] = ['url'=>$url,'schedule'=> $schedule];
                        if (count($rows) >= $max_rows) break;
                    }
                    fclose($h);
                }

                if (count($rows) === 0) {
                    $action_report[] = ['url'=>'','action'=>'info','reason'=>'CSV parsed but no data rows found.'];
                } else {
                    // Deduplicate input CSV (keep first occurrence)
                    $unique_input = [];
                    foreach ($rows as $r) {
                        $key = normalize_url_cmp($r['url']);
                        if ($key === '') continue;
                        if (!isset($unique_input[$key])) $unique_input[$key] = $r;
                    }

                    // Prepare JSON fallback array if needed
                    if (!$use_db) {
                        $json_arr = file_exists($sample_json) ? (json_decode(@file_get_contents($sample_json), true) ?: []) : [];
                    }

                    // Process each unique row
                    foreach ($unique_input as $key => $row) {
                        $u = $row['url'];
                        $s = $row['schedule'] ?: 'Daily';

                        if (!is_valid_url($u)) {
                            $action_report[] = ['url'=>$u,'action'=>'skipped','reason'=>'invalid_url'];
                            continue;
                        }

                        if (isset($existing_urls[$key])) {
                            $action_report[] = ['url'=>$u,'action'=>'skipped','reason'=>'already_exists'];
                            continue;
                        }

                        // Insert
                        if ($use_db) {
                            $u_esc = $mysqli->real_escape_string($u);
                            $s_esc = $mysqli->real_escape_string($s);
                            $ok = $mysqli->query("INSERT INTO watchlist (url, schedule) VALUES ('".$u_esc."','".$s_esc."')");
                            if ($ok) {
                                $action_report[] = ['url'=>$u,'action'=>'inserted','reason'=>'db_insert'];
                                $existing_urls[$key] = true;
                            } else {
                                $action_report[] = ['url'=>$u,'action'=>'error','reason'=>'db_error: '.$mysqli->error];
                            }
                        } else {
                            // append to sample JSON array
                            $json_arr[] = [
                                'url' => $u,
                                'schedule' => $s,
                                'last_scan' => 'Never',
                                'verdict' => 'unknown',
                                'score' => '-',
                                'notes' => 'Added via bulk upload'
                            ];
                            // try to write back
                            if (@file_put_contents($sample_json, json_encode($json_arr, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) !== false) {
                                $action_report[] = ['url'=>$u,'action'=>'inserted','reason'=>'json_appended'];
                                $existing_urls[$key] = true;
                            } else {
                                $action_report[] = ['url'=>$u,'action'=>'error','reason'=>'could_not_write_json'];
                            }
                        }
                    }

                    // Save a copy of uploaded file for auditing
                    $safe_name = preg_replace('/[^a-z0-9_.-]/i','_', $name);
                    $save_to = __DIR__ . '/last_uploaded_' . $safe_name;
                    @move_uploaded_file($tmp, $save_to);

                    // build parsed rows for display
                    foreach ($unique_input as $k => $r) $parsed_rows[] = $r;
                }
            }
        }
    }

    // build report CSV for download
    $csv = "url,action,reason\n";
    foreach ($action_report as $ar) {
        $csv .= '"' . str_replace('"', '""', $ar['url']) . '",' . $ar['action'] . ',"' . str_replace('"', '""', $ar['reason']) . "\n";
    }
    @file_put_contents($report_csv_file, $csv);
}

// ---- HTML output ----
?><!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bulk Upload — Watchlist</title>
  <style>
    body{font-family:Arial,Helvetica,sans-serif;background:#f5f6f8;padding:18px}
    .card{background:#fff;padding:14px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.06);max-width:1000px;margin:auto}
    table{border-collapse:collapse;width:100%}
    th,td{padding:8px;border:1px solid #eee;font-size:14px}
    th{background:#222;color:#fff;text-align:left}
    .ok{color:green}.err{color:#c0392b}
    .small{font-size:13px;color:#666}
    .badge{display:inline-block;padding:4px 8px;border-radius:12px;color:#fff}
    .badge-insert{background:#27ae60}
    .badge-skip{background:#f39c12}
    .badge-err{background:#c0392b}
  </style>
</head>
<body>
  <div class="card">
    <h2>Bulk Upload — Watchlist</h2>
    <p class="small">Upload a CSV with columns: <code>url,schedule</code> (header optional). Duplicates are skipped (both inside CSV and against existing watchlist).</p>

    <form method="post" enctype="multipart/form-data">
      <input type="file" name="csv_file" accept=".csv" required>
      <button type="submit">Upload & Process</button>
      <?php if (file_exists($report_csv_file)): ?>
        <a href="<?php echo basename($report_csv_file); ?>" style="margin-left:12px">Download report CSV</a>
      <?php endif; ?>
    </form>

    <hr>

    <?php if (!empty($action_report)): ?>
      <h3>Upload Report</h3>
      <table>
        <thead><tr><th>#</th><th>URL</th><th>Action</th><th>Reason</th></tr></thead>
        <tbody>
          <?php $i=1; foreach ($action_report as $ar): ?>
            <tr>
              <td><?php echo $i++; ?></td>
              <td><?php echo htmlspecialchars($ar['url']); ?></td>
              <td>
                <?php
                  if ($ar['action'] === 'inserted') echo '<span class="badge badge-insert">Inserted</span>';
                  elseif ($ar['action'] === 'skipped') echo '<span class="badge badge-skip">Skipped</span>';
                  elseif ($ar['action'] === 'error') echo '<span class="badge badge-err">Error</span>';
                  else echo htmlspecialchars($ar['action']);
                ?>
              </td>
              <td><?php echo htmlspecialchars($ar['reason']); ?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>

    <?php if (!empty($parsed_rows)): ?>
      <hr>
      <h3>Parsed (unique) rows from CSV</h3>
      <table>
        <thead><tr><th>#</th><th>URL</th><th>Schedule</th><th>Valid</th></tr></thead>
        <tbody>
        <?php $k = 1; foreach ($parsed_rows as $pr): ?>
          <tr>
            <td><?php echo $k++; ?></td>
            <td><?php echo htmlspecialchars($pr['url']); ?></td>
            <td><?php echo htmlspecialchars($pr['schedule']); ?></td>
            <td><?php echo is_valid_url($pr['url']) ? '<span class="ok">OK</span>' : '<span class="err">INVALID</span>'; ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>

    <p class="small">Tip: If you see "already_exists" for many rows, either those URLs were already in DB/JSON or the CSV contained duplicates. To force re-insert/update, you'd need to change the script to perform UPDATEs or delete duplicates first.</p>
  </div>
</body>
</html>
