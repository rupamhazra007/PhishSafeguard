<?php
// admin/users.php — users list with last login + masked identifier + counts + CSV export
// UI: Premium Glassmorphism with H.jpg background
session_start();
if (empty($_SESSION['is_admin']) || $_SESSION['is_admin'] != 1) {
    http_response_code(403);
    echo "Access denied.";
    exit;
}

// DB config
$servername="localhost"; $dbuser="root"; $dbpass=""; $dbname="phishing_db";
$conn = new mysqli($servername, $dbuser, $dbpass, $dbname);
if ($conn->connect_error) die("DB connection error: " . htmlspecialchars($conn->connect_error));

/*
  SAFE AUTO-UPDATE BLOCK
  ----------------------
  Ensures columns exist and updates sample data.
*/
try {
    $alter = "ALTER TABLE users
      ADD COLUMN IF NOT EXISTS last_ip VARCHAR(45) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS location VARCHAR(120) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS used VARCHAR(50) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS total_logins INT DEFAULT 0,
      ADD COLUMN IF NOT EXISTS last_login DATETIME DEFAULT NULL";
    $conn->query($alter); 

    $samples = [
      ['Gopal Hazra',    'hazragopal555@gmail.com', '182.73.21.55',    'Kolkata, India',      'EMAIL', 4, '2025-09-10 21:14:02'],
      ['Parag Chatterjee','prctech2012@gmail.com',   '117.205.43.87',   'Durgapur, India',     'EMAIL', 2, '2025-09-11 19:22:44'],
      ['Picklu',         null,                      '45.67.120.44',    'Dhaka, Bangladesh',   'PHONE', 1, '2025-09-08 16:09:11'],
      ['Picku',          null,                      '223.176.54.19',   'Siliguri, India',     'PHONE', 3, '2025-09-07 10:55:34'],
      ['Priyanka',       null,                      '49.37.202.111',   'Patna, India',        'EMAIL', 5, '2025-09-12 08:41:29'],
      ['Rekha',          null,                      '2405:201:ab::77', 'Asansol, India',      'PHONE', 2, '2025-09-09 11:22:15'],
      ['Rekha Bose',     'rekhasikder1943@gmail.com','103.15.220.73',  'Ranchi, India',       'EMAIL', 6, '2025-09-12 17:20:48'],
      ['Rekha Sikder',   null,                      '59.93.64.101',    'Howrah, India',       'EMAIL', 1, '2025-09-06 12:44:55'],
      ['Rupam Hazra',    'rupamhazra60@gmail.com',  '2401:4900:12::9', 'Kolkata, India',      'EMAIL', 7, '2025-09-12 18:33:47'],
      ['Rupam Hazzra',   'hazrarupam222@gmail.com', '::1',             'Localhost',           'EMAIL', 3, '2025-09-12 18:56:57'],
      ['Soumen Ghosh',   'soumengh97@gmail.com',    '157.40.98.23',    'Midnapore, India',    'EMAIL', 2, '2025-09-10 22:11:38']
    ];

    $conn->begin_transaction();
    $upd_sql = "UPDATE users SET 
                  last_ip = ?, location = ?, used = ?, total_logins = ?, last_login = ?
                WHERE (email IS NOT NULL AND LOWER(TRIM(email)) = ?) 
                   OR (LOWER(TRIM(username)) = ?)";
    $stmt = $conn->prepare($upd_sql);
    if ($stmt) {
        foreach ($samples as $row) {
            list($uname, $email, $lip, $loc, $used, $tlog, $ll) = $row;
            $email_norm = ($email !== null) ? mb_strtolower(trim($email)) : null;
            $uname_norm  = mb_strtolower(trim($uname));
            $stmt->bind_param('sssisss', $lip, $loc, $used, $tlog, $ll, $email_norm, $uname_norm);
            $stmt->execute();
        }
        $stmt->close();
    } else {
        foreach ($samples as $row) {
            list($uname, $email, $lip, $loc, $used, $tlog, $ll) = $row;
            $email_norm_q = $email !== null ? $conn->real_escape_string(mb_strtolower(trim($email))) : null;
            $uname_norm_q = $conn->real_escape_string(mb_strtolower(trim($uname)));
            $where = $email_norm_q ? "(email IS NOT NULL AND LOWER(TRIM(email)) = '{$email_norm_q}')" : "LOWER(TRIM(username)) = '{$uname_norm_q}'";
            $q = "UPDATE users SET last_ip = '{$conn->real_escape_string($lip)}', location = '{$conn->real_escape_string($loc)}', used = '{$conn->real_escape_string($used)}', total_logins = {$tlog}, last_login = '{$conn->real_escape_string($ll)}' WHERE {$where}";
            $conn->query($q);
        }
    }
    $conn->commit();
} catch (Exception $ex) {
    $conn->rollback();
}
/* end SAFE AUTO-UPDATE BLOCK */

/* helper: mask email / phone */
function mask_email($email) {
    if (!$email) return '';
    $parts = explode('@', $email);
    if (count($parts) !== 2) return substr($email,0,3) . '***';
    $name = $parts[0]; $domain = $parts[1];
    $name_mask = strlen($name) <= 2 ? str_repeat('*', strlen($name)) : substr($name,0,1) . str_repeat('*', max(1, strlen($name)-2)) . substr($name,-1);
    $dom_parts = explode('.', $domain);
    $dom_mask = $dom_parts[0][0] . str_repeat('*', max(2, strlen($dom_parts[0]) - 2)) . (strlen($dom_parts[0])>1?substr($dom_parts[0],-1):'');
    $remainder = count($dom_parts) > 1 ? '.' . implode('.', array_slice($dom_parts,1)) : '';
    return strtolower($name_mask . '@' . $dom_mask . $remainder);
}
function mask_phone($p) {
    if (!$p) return '';
    $plus = (strpos($p, '+') === 0) ? '+' : '';
    $digits = preg_replace('/\D/', '', $p);
    if (strlen($digits) <= 4) return $plus . str_repeat('*', strlen($digits));
    $keep = 3;
    $masked = substr($digits, 0, 2) . str_repeat('*', max(1, strlen($digits)- (2+$keep))) . substr($digits, -$keep);
    return $plus . $masked;
}

// CSV export
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $limitAll = (isset($_GET['all']) && $_GET['all']=='1') ? '' : ' LIMIT 50';
    $sqlr = "SELECT ul.id, ul.user_id, COALESCE(u.username, CONCAT('user#',ul.user_id)) AS username, ul.ip, ul.city, ul.region, ul.country, ul.identifier_type, ul.identifier_value, ul.login_at
              FROM user_logins ul LEFT JOIN users u ON u.id = ul.user_id
              ORDER BY ul.login_at DESC" . $limitAll;
    $resr = $conn->query($sqlr);
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=recent_logins.csv');
    $out = fopen('php://output','w');
    fputcsv($out, ['id','user_id','username','ip','identifier_type','identifier_value','city','region','country','login_at']);
    if ($resr) {
        while ($row = $resr->fetch_assoc()) {
            fputcsv($out, [
                $row['id'], $row['user_id'], $row['username'], $row['ip'],
                $row['identifier_type'], $row['identifier_value'],
                $row['city'], $row['region'], $row['country'], $row['login_at']
            ]);
        }
        $resr->free();
    }
    fclose($out);
    $conn->close();
    exit;
}

// 1) fetch users
$sql = "
SELECT u.id AS user_id,
       u.username, u.email, u.last_ip, u.location, u.used, u.total_logins, u.last_login,
       ul.ip, ul.city, ul.region, ul.country, ul.login_at,
       ul.identifier_type, ul.identifier_value,
       COALESCE(lc.cnt, 0) AS logins_count
FROM users u
LEFT JOIN (
    SELECT ul1.* FROM user_logins ul1
    JOIN ( SELECT user_id, MAX(id) AS maxid FROM user_logins GROUP BY user_id ) mx ON ul1.user_id = mx.user_id AND ul1.id = mx.maxid
) ul ON ul.user_id = u.id
LEFT JOIN (
    SELECT user_id, COUNT(*) AS cnt FROM user_logins GROUP BY user_id
) lc ON lc.user_id = u.id
ORDER BY u.username ASC
";
$res = $conn->query($sql);
$users = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];

// 2) recent logins
$recent = [];
$r2 = $conn->query("SELECT ul.*, u.username FROM user_logins ul LEFT JOIN users u ON u.id=ul.user_id ORDER BY ul.login_at DESC LIMIT 50");
if ($r2) $recent = $r2->fetch_all(MYSQLI_ASSOC);

$conn->close();

function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Users Dashboard | PhishSafeguard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<style>
:root {
    --glass-bg: rgba(17, 25, 40, 0.75);
    --glass-border: rgba(255, 255, 255, 0.125);
    --accent: #38bdf8;
    --primary: #6366f1;
    --text-main: #ffffff;
    --text-muted: #94a3b8;
    --radius: 16px;
    --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

* { box-sizing: border-box; }

body {
    margin: 0;
    font-family: 'Plus Jakarta Sans', sans-serif;
    min-height: 100vh;
    background-image: url('H.jpg'); /* Added H.jpg */
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
    color: var(--text-main);
    overflow-x: hidden;
}

/* Dark Overlay for readability */
body::before {
    content: '';
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: radial-gradient(circle at center, rgba(15, 23, 42, 0.5) 0%, rgba(3, 7, 18, 0.85) 100%);
    z-index: -1;
}

.container {
    max-width: 1400px;
    margin: 40px auto;
    padding: 0 20px;
    animation: fadeIn 0.8s ease-out;
}

/* Header */
.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding: 20px 30px;
    background: var(--glass-bg);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--glass-border);
    border-radius: var(--radius);
    box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
}

.header h2 {
    margin: 0;
    font-size: 24px;
    font-weight: 700;
    background: linear-gradient(90deg, #fff, #94a3b8);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.controls { display: flex; gap: 12px; }

/* Buttons */
.btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 20px;
    border-radius: 10px;
    text-decoration: none;
    font-weight: 600;
    font-size: 14px;
    transition: var(--transition);
    border: 1px solid transparent;
}

.btn-primary {
    background: linear-gradient(135deg, var(--primary), var(--accent));
    color: white;
    box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(99, 102, 241, 0.5);
}

.btn-ghost {
    background: rgba(255, 255, 255, 0.05);
    border-color: rgba(255, 255, 255, 0.2);
    color: var(--text-main);
}

.btn-ghost:hover {
    background: rgba(255, 255, 255, 0.15);
    border-color: #fff;
}

/* Glass Card */
.card {
    background: var(--glass-bg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--glass-border);
    border-radius: var(--radius);
    padding: 0; /* Removing padding for table fit */
    margin-bottom: 30px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
    overflow: hidden;
}

.card-title {
    padding: 20px 30px;
    border-bottom: 1px solid var(--glass-border);
    margin: 0;
    font-size: 18px;
    font-weight: 600;
    color: var(--accent);
    display: flex;
    align-items: center;
    gap: 10px;
}

/* Table */
.table-wrapper {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
    white-space: nowrap;
}

thead th {
    background: rgba(0, 0, 0, 0.2);
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 1px;
    padding: 16px 24px;
    text-align: left;
    border-bottom: 1px solid var(--glass-border);
}

tbody tr {
    transition: var(--transition);
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
}

tbody tr:last-child { border-bottom: none; }

tbody tr:hover {
    background: rgba(255, 255, 255, 0.05);
    transform: scale(1.002);
}

td {
    padding: 16px 24px;
    vertical-align: middle;
}

/* Elements */
.user-name {
    font-weight: 600;
    color: #fff;
    font-size: 15px;
}

.ip {
    font-family: 'Courier New', monospace;
    background: rgba(0, 0, 0, 0.3);
    padding: 4px 8px;
    border-radius: 6px;
    border: 1px solid rgba(255,255,255,0.05);
    font-size: 12px;
    color: #cbd5e1;
}

.badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.badge-email {
    background: rgba(99, 102, 241, 0.15);
    color: #818cf8;
    border: 1px solid rgba(99, 102, 241, 0.3);
}

.badge-phone {
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.kv {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 3px;
    opacity: 0.8;
}

.login-count {
    display: inline-block;
    width: 32px;
    height: 32px;
    line-height: 32px;
    text-align: center;
    border-radius: 50%;
    background: rgba(255,255,255,0.1);
    font-weight: 700;
    font-size: 12px;
}

/* Animations */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

@media (max-width: 768px) {
    .header { flex-direction: column; gap: 20px; text-align: center; }
    td, th { padding: 12px 16px; }
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h2><i class="fa fa-shield-halved" style="color: var(--accent); margin-right: 10px;"></i> User Management</h2>
            <div style="color: var(--text-muted); font-size: 14px; margin-top: 5px;">Monitor user activity and logins</div>
        </div>
        <div class="controls">
            <a class="btn btn-primary" href="?export=csv">
                <i class="fa fa-file-csv"></i> Recent CSV
            </a>
            <a class="btn btn-ghost" href="?export=csv&all=1">
                <i class="fa fa-download"></i> All CSV
            </a>
        </div>
    </div>

    <div class="card">
        <h3 class="card-title"><i class="fa fa-users"></i> Registered Users</h3>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>User Profile</th>
                        <th>Identifier</th>
                        <th>Network</th>
                        <th>Location</th>
                        <th>Activity</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($users)): ?>
                        <tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-muted);">No users found in database.</td></tr>
                    <?php else: foreach ($users as $u): 
                        $used_html = '<span style="opacity:0.3">—</span>';
                        $identifier_type = $u['identifier_type'] ?? $u['used'] ?? null;
                        $identifier_value = $u['identifier_value'] ?? $u['email'] ?? null;

                        if ($identifier_type) {
                            $itype = strtoupper($identifier_type);
                            $ival = $identifier_value;
                            $ival_mask = '—';
                            $badge_class = 'badge-email';
                            
                            if ($itype === 'EMAIL') {
                                $ival_mask = mask_email($ival);
                                $badge_class = 'badge-email';
                            } elseif ($itype === 'PHONE') {
                                $ival_mask = mask_phone($ival);
                                $badge_class = 'badge-phone';
                            }
                            
                            $used_html = "<span class=\"badge $badge_class\">".e($itype)."</span><div class=\"kv\">".e($ival_mask)."</div>";
                        }
                    ?>
                        <tr>
                            <td>
                                <div class="user-name"><?= e($u['username'] ?: 'User #'.$u['user_id']) ?></div>
                                <div class="kv"><?= e($u['email'] ?? 'No Email') ?></div>
                            </td>
                            <td><?= $used_html ?></td>
                            <td>
                                <?= !empty($u['ip']) ? '<span class="ip">'.e($u['ip']).'</span>' : (!empty($u['last_ip'])?'<span class="ip">'.e($u['last_ip']).'</span>':'<span style="opacity:0.3">—</span>') ?>
                            </td>
                            <td>
                                <div style="display:flex; align-items:center; gap:6px;">
                                    <i class="fa fa-location-dot" style="color: var(--accent); font-size: 12px;"></i>
                                    <?= e(trim(implode(', ', array_filter([$u['city'] ?? $u['location'] ?? null,$u['country']??null]))) ?: 'Unknown') ?>
                                </div>
                            </td>
                            <td>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <span class="login-count"><?= (int)($u['logins_count'] ?: $u['total_logins'] ?? 0) ?></span>
                                    <span class="kv">logins</span>
                                </div>
                            </td>
                            <td style="color: var(--accent); font-size: 13px;">
                                <i class="fa fa-clock" style="margin-right:5px; opacity:0.6;"></i>
                                <?= e($u['login_at'] ?? $u['last_login'] ?? 'Never') ?>
                            </td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h3 class="card-title"><i class="fa fa-history"></i> Recent Login Stream (Latest 50)</h3>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th width="50">#</th>
                        <th>User</th>
                        <th>IP Address</th>
                        <th>Used Method</th>
                        <th>Location</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($recent)): ?>
                        <tr><td colspan="6" style="text-align: center; padding: 40px;">No recent logins recorded.</td></tr>
                    <?php else: $i=0; foreach ($recent as $r): $i++; 
                        $r_type = strtoupper($r['identifier_type'] ?? '');
                        $r_val = $r['identifier_value'] ?? '';
                        if ($r_type === 'EMAIL') { $r_mask = mask_email($r_val); $b_cls = 'badge-email'; }
                        elseif ($r_type === 'PHONE') { $r_mask = mask_phone($r_val); $b_cls = 'badge-phone'; }
                        else { $r_mask = e($r_val); $b_cls = 'badge-email'; }
                    ?>
                        <tr>
                            <td style="color: var(--text-muted); font-size: 12px;"><?= $i ?></td>
                            <td>
                                <span style="font-weight: 600; color: #fff;"><?= e($r['username'] ?: 'User #'.$r['user_id']) ?></span>
                            </td>
                            <td><span class="ip"><?= e($r['ip']) ?></span></td>
                            <td>
                                <?php if ($r_type): ?>
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span class="badge <?= $b_cls ?>"><?= e($r_type) ?></span>
                                        <span style="font-size:13px; color:var(--text-muted);"><?= e($r_mask) ?></span>
                                    </div>
                                <?php else: ?>—<?php endif; ?>
                            </td>
                            <td><?= e(trim(implode(', ', array_filter([$r['city'],$r['country']]))) ?: '—') ?></td>
                            <td style="color: var(--text-muted); font-size: 13px;">
                                <?= e($r['login_at']) ?>
                            </td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
</html>