<?php
// notifications_count.php
// returns { unread_count: n }

session_start();
header('Content-Type: application/json; charset=utf-8');
if (!isset($_SESSION['user_id'])) {
    echo json_encode(['unread_count'=>0]);
    exit();
}
$uid = intval($_SESSION['user_id']);

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phishing_db";
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    echo json_encode(['unread_count'=>0]);
    exit();
}
$stmt = $conn->prepare("SELECT COUNT(*) as cnt FROM notifications WHERE user_id=? AND is_read=0");
$stmt->bind_param('i', $uid);
$stmt->execute();
$r = $stmt->get_result()->fetch_assoc();
$unread = intval($r['cnt'] ?? 0);
$stmt->close();
$conn->close();
echo json_encode(['unread_count'=>$unread]);
exit();
