<?php
// notifications.php
// Returns JSON: { notifications: [ ... ], unread_count: n }
// GET only, uses session user_id

session_start();
header('Content-Type: application/json; charset=utf-8');
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['notifications'=>[], 'unread_count'=>0]);
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
    echo json_encode(['notifications'=>[], 'unread_count'=>0]);
    exit();
}

// fetch recent notifications for this user
$stmt = $conn->prepare("SELECT id, title, body, is_read, created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50");
$stmt->bind_param('i', $uid);
$stmt->execute();
$res = $stmt->get_result();
$notifs = [];
while ($row = $res->fetch_assoc()) {
    $notifs[] = [
        'id' => (int)$row['id'],
        'title' => $row['title'],
        'body' => $row['body'],
        'is_read' => (bool)$row['is_read'],
        'created_at' => $row['created_at'],
    ];
}
$stmt->close();

// unread count
$stmt2 = $conn->prepare("SELECT COUNT(*) as cnt FROM notifications WHERE user_id=? AND is_read=0");
$stmt2->bind_param('i', $uid);
$stmt2->execute();
$r2 = $stmt2->get_result()->fetch_assoc();
$unread = intval($r2['cnt'] ?? 0);
$stmt2->close();
$conn->close();

echo json_encode(['notifications'=>$notifs, 'unread_count'=>$unread]);
exit();
