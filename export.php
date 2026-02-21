<?php
require_once __DIR__ . '/helpers_db.php'; // নিশ্চিত করো helpers_db.php একই ফোল্ডারে আছে
if (session_status() === PHP_SESSION_NONE) session_start();

// ---- CONFIG: অনুমোদিত টেবিল এবং mapping ----
$allowed = [
  // 'table_name' => ['col1','col2','col3']
  'url_checks' => ['url','result','checked_at'],
  // যদি তোমার টেবিল আলাদা থাকে, এখানে যোগ করো, উদাহরণ:
  // 'checks' => ['url','verdict','created_at'],
];

// কোন টেবিল এক্সপোর্ট করতে হবে — GET param ?t=tablename (optional)
$tbl = $_GET['t'] ?? 'url_checks';
if (!array_key_exists($tbl, $allowed)) {
    http_response_code(400);
    echo "Invalid table requested.";
    exit;
}

$cols = $allowed[$tbl];
$col_list = implode(', ', array_map(function($c){ return "`$c`"; }, $cols));

$conn = db();
$sql = "SELECT $col_list FROM `$tbl` ORDER BY " . $cols[count($cols)-1] . " DESC";
if (!$res = $conn->query($sql)) {
    http_response_code(500);
    echo "DB Query Error: " . $conn->error;
    exit;
}

$filename = $tbl . "_export_" . date('Ymd_His') . ".csv";
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');

$out = fopen('php://output', 'w');
fwrite($out, "\xEF\xBB\xBF"); // BOM for Excel

// Header row (human readable)
fputcsv($out, array_map('ucfirst', $cols));

// Rows
while ($row = $res->fetch_assoc()) {
    $line = [];
    foreach ($cols as $c) $line[] = $row[$c] ?? '';
    fputcsv($out, $line);
}

fclose($out);
$conn->close();
exit;
