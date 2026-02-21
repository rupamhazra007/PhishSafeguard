<?php
// -------------------- Session --------------------
if (session_status() === PHP_SESSION_NONE) {
    // (optional hardening) set cookie params before session_start
    $secure   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $httponly = true;
    $samesite = 'Lax'; // or 'Strict' if you don't do cross-site embeds
    if (PHP_VERSION_ID >= 70300) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $secure,
            'httponly' => $httponly,
            'samesite' => $samesite,
        ]);
    }
    session_start();
}

// -------------------- Language switch --------------------
if (isset($_GET['lang']) && $_GET['lang'] !== '') {
    $_SESSION['lang'] = $_GET['lang'];
}
if (empty($_SESSION['lang'])) {
    $_SESSION['lang'] = 'en';
}
$lang_file = __DIR__ . '/languages/' . basename($_SESSION['lang']) . '.php';
if (is_file($lang_file)) {
    require_once $lang_file;
} else {
    require_once __DIR__ . '/languages/en.php';
}

// -------------------- General app settings --------------------
date_default_timezone_set('Asia/Kolkata');

// -------------------- Database (VERY IMPORTANT) --------------------
// NOTE: আপনার রিয়েল ক্রেডেনশিয়াল বসান বা .env থেকে নিন
$DB_HOST = getenv('DB_HOST') ?: 'localhost';
$DB_NAME = getenv('DB_NAME') ?: 'phisingh_db'; // <- আপনি আগেই এই নাম ব্যবহার করেছেন
$DB_USER = getenv('DB_USER') ?: 'root';
$DB_PASS = getenv('DB_PASS') ?: '';

// ---- PDO (used by payment.php, safer defaults) ----
$pdo = null;
try {
    $dsn = "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4";
    $pdo = new PDO(
        $dsn,
        $DB_USER,
        $DB_PASS,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_TIMEOUT            => 5,      // seconds
            // PDO::ATTR_PERSISTENT      => true,  // enable only if you know you need it
        ]
    );
} catch (Throwable $e) {
    // ডেভেলপমেন্টে দেখতে সুবিধা হয়—প্রোডাকশনে error_log ব্যবহার করুন
    // error_log('PDO connect failed: ' . $e->getMessage());
    $pdo = null;
    $_SESSION['db_error'] = 'DB connection failed';
}

// ---- mysqli (used by index.php badge/read) ----
$conn = null;
try {
    mysqli_report(MYSQLI_REPORT_OFF);
    $conn = @new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    if ($conn && !$conn->connect_errno) {
        $conn->set_charset('utf8mb4');
    } else {
        $conn = null;
    }
} catch (Throwable $e) {
    $conn = null;
}

// Global DB ready flag (বাইরে থেকে চেক করা সহজ)
define('DB_READY', $pdo instanceof PDO);

// -------------------- Small helpers --------------------
/**
 * Return current user id from session, or 0
 */
function current_user_id(): int {
    return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 0;
}

/**
 * Quick JSON response (for APIs if needed)
 */
function json_out($data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
