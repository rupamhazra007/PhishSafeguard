<?php
// otp_send.php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/config.php';

use Twilio\Rest\Client;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

header('Content-Type: application/json');

$inputIdentifier = trim($_POST['identifier'] ?? '');
$method = strtolower(trim($_POST['method'] ?? ''));

if (!$inputIdentifier || !in_array($method, ['sms','email'])) {
    http_response_code(400);
    echo json_encode(['success'=>false,'msg'=>'identifier and method (sms|email) required']);
    exit;
}

// normalize phone (basic) if method == sms: ensure starts with +
if ($method === 'sms') {
    // try to normalize Indian 10-digit to +91...
    if (preg_match('/^\d{10}$/', $inputIdentifier)) {
        $identifier = '+91' . $inputIdentifier;
    } else {
        $identifier = $inputIdentifier; // assume user supplied +country format
    }
} else {
    $identifier = $inputIdentifier; // email as provided
}

// db connect (PDO)
try {
    $pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
} catch (Exception $e) {
    error_log($e->getMessage(), 3, LOG_DIR.'/otp_error.log');
    http_response_code(500);
    echo json_encode(['success'=>false,'msg'=>'DB connection error']);
    exit;
}

// rate limit: count last 10 minutes attempts for this identifier
$limitWindow = time() - 600; // 10 minutes
$stmt = $pdo->prepare("SELECT COUNT(*) FROM otp_attempts WHERE identifier = :id AND created_at > :t");
$stmt->execute([':id'=>$identifier, ':t'=>$limitWindow]);
$recentCount = (int)$stmt->fetchColumn();
if ($recentCount >= 5) {
    echo json_encode(['success'=>false,'msg'=>'Too many OTP requests. Try later.']);
    exit;
}

// generate OTP
$otp = strval(rand(100000, 999999));
$now = time();
$expires = $now + 300; // 5 minutes
$ip = $_SERVER['REMOTE_ADDR'] ?? '';

// insert attempt (initially sent_status 0)
$ins = $pdo->prepare("INSERT INTO otp_attempts (identifier, method, otp, created_at, expires_at, ip) VALUES (:id,:method,:otp,:c,:e,:ip)");
$ins->execute([
    ':id'=>$identifier, ':method'=>$method, ':otp'=>$otp, ':c'=>$now, ':e'=>$expires, ':ip'=>$ip
]);
$attemptId = $pdo->lastInsertId();

// send according to method
$sent = false;
$messageSid = null;
$errorMsg = null;

if ($method === 'sms') {
    // Twilio send
    try {
        $twilio = new Client(TWILIO_SID, TWILIO_TOKEN);
        $body = "Your OTP is {$otp}. Valid for 5 minutes.";
        $msg = $twilio->messages->create($identifier, [
            'from' => TWILIO_FROM,
            'body' => $body
        ]);
        $messageSid = $msg->sid ?? null;
        $sent = true;
    } catch (Exception $e) {
        $errorMsg = "Twilio Error: ".$e->getMessage();
        error_log($errorMsg.PHP_EOL, 3, LOG_DIR.'/otp_error.log');
    }
} else {
    // Email send via PHPMailer
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USER;
        $mail->Password = SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME);
        $mail->addAddress($identifier);

        $mail->isHTML(true);
        $mail->Subject = 'Your OTP code';
        $mail->Body    = "<p>Your OTP is <strong>{$otp}</strong>. It expires in 5 minutes.</p>";

        $mail->send();
        $sent = true;
        $messageSid = 'email-sent';
    } catch (Exception $e) {
        $errorMsg = "Mail Error: ".$mail->ErrorInfo;
        error_log($errorMsg.PHP_EOL, 3, LOG_DIR.'/otp_error.log');
    }
}

// update attempt with status
$upd = $pdo->prepare("UPDATE otp_attempts SET sent_status = :s, message_sid = :ms, error_message = :err WHERE id = :id");
$upd->execute([':s'=> $sent?1:0, ':ms'=>$messageSid, ':err'=>$errorMsg, ':id'=>$attemptId]);

if ($sent) {
    echo json_encode(['success'=>true,'msg'=>'OTP sent']);
} else {
    echo json_encode(['success'=>false,'msg'=>'Failed to send OTP','detail'=>$errorMsg]);
}
