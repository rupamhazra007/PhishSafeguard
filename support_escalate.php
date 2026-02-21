<?php
// support_escalate.php
session_start();
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success'=>false,'error'=>'Only POST']);
    exit;
}

$email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
$subject = trim($_POST['subject'] ?? 'Support request from site chat');
$body = trim($_POST['body'] ?? '');
$csrf = $_POST['csrf_token'] ?? '';

// CSRF check if used (optional)
// if (empty($_SESSION['csrf_token']) || $csrf !== $_SESSION['csrf_token']) { ... }

if (!$email) {
    echo json_encode(['success'=>false,'error'=>'Invalid email']);
    exit;
}

// Prepare message for support team
$admin_to = 'support@yourdomain.com'; // change to real support address
$fullBody = "From: {$email}\nUserID: ".($_SESSION['user_id'] ?? 'anon')."\n\nContext:\n".$body;

// Try to send email — fallback to file if mail() not configured
$mailSent = false;
if (function_exists('mail')) {
    $headers = "From: {$email}\r\nReply-To: {$email}\r\nContent-Type: text/plain; charset=utf-8";
    $mailSent = @mail($admin_to, $subject, $fullBody, $headers);
}

if ($mailSent) {
    echo json_encode(['success'=>true]);
    exit;
}

// fallback: save to escalations log (support team can review)
$entry = "[".date('Y-m-d H:i:s')."] email:{$email} subject:{$subject} uid:".($_SESSION['user_id'] ?? 'anon')."\n".$fullBody."\n\n";
file_put_contents(__DIR__ . '/escalations.txt', $entry, FILE_APPEND | LOCK_EX);

echo json_encode(['success'=>true, 'note'=>'Saved to escalations log (mail not sent).']);
