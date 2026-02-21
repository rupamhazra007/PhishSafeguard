<?php
// watchlist.php
// Adds a watchlist entry for the logged-in user.
// POST params: csrf_token, watch_url, cron (daily|weekly|monthly)
// Returns JSON { success: bool, error?: string }

session_start();
header('Content-Type: application/json; charset=utf-8');
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success'=>false,'error'=>'Not authenticated']);
    exit();
}

// CSRF
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
    http_response_code(403);
    echo json_encode(['success'=>false,'error'=>'Invalid CSRF token']);
    exit();
}

$watch_url = trim($_POST['watch_url'] ?? '');
$cron = trim($_POST['cron'] ?? '');

if (!filter_var($watch_url, FILTER_VALIDATE_URL)) {
    echo json_encode(['success'=>false,'error'=>'Invalid URL']);
    exit();
}
$allowed = ['daily','weekly','monthly'];
if (!in_array($cron, $allowed, true)) {
    echo json_encode(['success'=>false,'error'=>'Invalid schedule']);
    exit();
}

$uid = intval($_SESSION['user_id']);

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phishing_db";
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['success'=>false,'error'=>'DB connection failed']);
    exit();
}

// Basic duplicate prevention: same user + url + cron
$stmt = $conn->prepare("SELECT id FROM watchlists WHERE user_id=? AND url=? AND cron=? LIMIT 1");
$stmt->bind_param('iss', $uid, $watch_url, $cron);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows > 0) {
    $stmt->close();
    echo json_encode(['success'=>false,'error'=>'Watch already exists']);
    exit();
}
$stmt->close();

$stmt = $conn->prepare("INSERT INTO watchlists (user_id, url, cron, last_run, created_at) VALUES (?, ?, ?, NULL, NOW())");
$stmt->bind_param('iss', $uid, $watch_url, $cron);
$res = $stmt->execute();
if (!$res) {
    http_response_code(500);
    echo json_encode(['success'=>false,'error'=>'Insert failed']);
    $stmt->close();
    $conn->close();
    exit();
}
$stmt->close();
$conn->close();

echo json_encode(['success'=>true]);
exit();
