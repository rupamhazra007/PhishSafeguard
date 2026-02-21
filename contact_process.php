<?php
// contact_process_debug.php — temporary debug endpoint
// WARNING: verbose output/logging for debugging only. Remove or revert to production version after fixing.

header('Content-Type: application/json; charset=utf-8');
error_reporting(E_ALL);
ini_set('display_errors', '0'); // do not show raw warnings to browser; we return json instead

$logfile = '/tmp/contact_debug.log';
function dlog($msg) {
    global $logfile;
    file_put_contents($logfile, "[".date('c')."] ".$msg."\n", FILE_APPEND | LOCK_EX);
}

dlog("=== Request start ===");
dlog("REQUEST_METHOD: " . ($_SERVER['REQUEST_METHOD'] ?? ''));
dlog("REQUEST_URI: " . ($_SERVER['REQUEST_URI'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    dlog("Method not POST");
    http_response_code(405);
    echo json_encode(['success'=>false,'error'=>'Method not allowed','note'=>'Use POST']);
    exit;
}

// Read raw body (in case form-encoded vs JSON)
$raw = file_get_contents('php://input');
dlog("Raw body (first 1000 chars): " . substr($raw,0,1000));

$name = trim($_POST['name'] ?? '');
$email = trim($_POST['email'] ?? '');
$subject = trim($_POST['subject'] ?? '');
$message = trim($_POST['message'] ?? '');
dlog("Parsed fields: name=" . ($name?:'[EMPTY]') . " email=" . ($email?:'[EMPTY]') . " subject=" . ($subject?:'[EMPTY]') . " message_len=" . strlen($message));

if (!$name || !$email || !$message) {
    dlog("Validation failed - missing required fields");
    http_response_code(400);
    echo json_encode(['success'=>false,'error'=>'Missing required fields (name,email,message)','debug'=>['name'=>$name,'email'=>$email,'message_len'=>strlen($message)]]);
    exit;
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    dlog("Invalid email format: $email");
    http_response_code(400);
    echo json_encode(['success'=>false,'error'=>'Invalid email address','debug'=>['email'=>$email]]);
    exit;
}

// DB config — same as your app
$servername = "localhost";
$dbuser = "root";
$dbpass = "";
$dbname = "phishing_db";

$conn = @new mysqli($servername, $dbuser, $dbpass, $dbname);
if ($conn->connect_error) {
    dlog("DB connect error: " . $conn->connect_error);
    // fallback: write message to file
    $dir = __DIR__ . '/messages';
    if (!is_dir($dir)) @mkdir($dir,0755,true);
    $fname = $dir . '/msg_debug_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.txt';
    $body = "Time: " . date('c') . "\nFrom: $name <$email>\nSubject: $subject\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "\n\nMessage:\n$message\n";
    file_put_contents($fname, $body);
    dlog("Saved to file fallback: $fname");
    echo json_encode(['success'=>true,'note'=>'Saved locally (DB connect failed)','fallback_file'=>$fname,'db_error'=>$conn->connect_error]);
    exit;
}

$stmt = $conn->prepare("INSERT INTO contact_messages (name,email,subject,message,ip,user_agent) VALUES (?,?,?,?,?,?)");
if (!$stmt) {
    dlog("DB prepare failed: " . $conn->error);
    echo json_encode(['success'=>false,'error'=>'DB prepare failed','db_error'=>$conn->error]);
    exit;
}

$ip = $_SERVER['REMOTE_ADDR'] ?? null;
$ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 1000);
$stmt->bind_param('ssssss', $name, $email, $subject, $message, $ip, $ua);

if (!$stmt->execute()) {
    dlog("DB execute failed: " . $stmt->error);
    echo json_encode(['success'=>false,'error'=>'DB insert failed','db_error'=>$stmt->error]);
    exit;
}

$inserted_id = $stmt->insert_id;
dlog("Inserted message id: $inserted_id");
$stmt->close();
$conn->close();

echo json_encode(['success'=>true,'id'=>$inserted_id]);
dlog("=== Request end (success) ===");
exit;
