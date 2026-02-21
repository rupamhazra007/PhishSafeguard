<?php
// process_bulk_queue.php
// CLI worker: processes pending bulk_queue rows, reads CSV, inserts into url_checks
// Run manually or via cron. Use php CLI (not via webserver).

// Basic safety: ensure running from CLI
if (php_sapi_name() !== 'cli') {
    echo "Run from CLI only.\n";
    exit(1);
}

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phishing_db";
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    echo "DB connect failed\n"; exit(1);
}

// get one pending queue
$stmt = $conn->prepare("SELECT id, user_id, file_path FROM bulk_queue WHERE status='pending' ORDER BY created_at ASC LIMIT 1 FOR UPDATE");
$stmt->execute();
$res = $stmt->get_result();
$row = $res->fetch_assoc();
$stmt->close();

if (!$row) {
    echo "No pending queue items.\n";
    $conn->close();
    exit(0);
}

$qid = intval($row['id']);
$filepath = $row['file_path'];
echo "Processing queue id={$qid}, file={$filepath}\n";

// basic file check
if (!is_readable($filepath)) {
    // mark failed
    $stmt = $conn->prepare("UPDATE bulk_queue SET status='failed', processed_at=NOW(), notes=? WHERE id=?");
    $note = "File not readable";
    $stmt->bind_param('si', $note, $qid);
    $stmt->execute();
    $stmt->close();
    echo "File not readable\n";
    $conn->close();
    exit(1);
}

// open and parse CSV
$fp = fopen($filepath, 'r');
if (!$fp) {
    $stmt = $conn->prepare("UPDATE bulk_queue SET status='failed', processed_at=NOW(), notes=? WHERE id=?");
    $note = "Failed opening file";
    $stmt->bind_param('si', $note, $qid);
    $stmt->execute();
    $stmt->close();
    echo "Failed opening file\n";
    $conn->close();
    exit(1);
}

// read header to determine which column is 'url' (case-insensitive)
$header = fgetcsv($fp);
if ($header === false) $header = [];
$cols = array_map('strtolower', $header);
$urlIndex = null;
foreach ($cols as $i => $c) {
    if (trim($c) === 'url') { $urlIndex = $i; break; }
}
if ($urlIndex === null) {
    // fallback: assume first col
    $urlIndex = 0;
}

// prepared insert into url_checks
$ins = $conn->prepare("INSERT INTO url_checks (url, result, score, reasons, checked_at) VALUES (?, 'pending', NULL, 'Bulk import pending scan', NOW())
    ON DUPLICATE KEY UPDATE url=url"); // keep existing if present
if (!$ins) {
    fclose($fp);
    echo "Prepare insert failed\n";
    $conn->close();
    exit(1);
}

$inserted = 0;
$skipped = 0;
while (($rowData = fgetcsv($fp)) !== false) {
    if (!isset($rowData[$urlIndex])) { $skipped++; continue; }
    $u = trim($rowData[$urlIndex]);
    if (!$u) { $skipped++; continue; }
    // basic URL validation
    if (!filter_var($u, FILTER_VALIDATE_URL)) { $skipped++; continue; }
    $ins->bind_param('s', $u);
    if ($ins->execute()) $inserted++; else $skipped++;
}

$ins->close();
fclose($fp);

// mark queue processed
$stmt2 = $conn->prepare("UPDATE bulk_queue SET status='processed', processed_at=NOW(), processed_count=?, notes=? WHERE id=?");
$notes = "Inserted: $inserted, Skipped: $skipped";
$stmt2->bind_param('isi', $inserted, $notes, $qid);
$stmt2->execute();
$stmt2->close();

echo "Done. Inserted=$inserted, Skipped=$skipped\n";
$conn->close();
exit(0);
