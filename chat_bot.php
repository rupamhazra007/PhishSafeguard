<?php
// chat_bot.php
// Lightweight, local FAQ assistant for Contact page.
// Accepts POST 'message' and returns JSON { success: true, reply: "...", intent: "..." }

session_start();
header('Content-Type: application/json; charset=utf-8');

// simple rate limiter per session (basic)
if (!isset($_SESSION['chat_count'])) $_SESSION['chat_count'] = 0;
$_SESSION['chat_count']++;
if ($_SESSION['chat_count'] > 120) { // limit ~120 messages per session
    echo json_encode(['success' => false, 'error' => 'Rate limit exceeded. Please try again later.']);
    exit;
}

// Accept only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Invalid method']);
    exit;
}

// Read input (application/x-www-form-urlencoded from widget)
$raw = $_POST['message'] ?? '';
$msg = trim((string)$raw);
if ($msg === '') {
    echo json_encode(['success' => false, 'error' => 'Empty message']);
    exit;
}

// sanitize for logs/display (we won't execute)
$clean = htmlspecialchars($msg, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

// simple intent/keyword matching
$lower = mb_strtolower($msg, 'UTF-8');

// Small FAQ / knowledge base (local)
$kb = [
    // key => [intent, answer]
    'how to scan' => ['scan_help', "To scan a URL, go to the Dashboard → Check a URL, paste the full URL (including http/https) and click 'Check'. We'll analyse SSL, domain reputation, content heuristics and return a risk score."],
    'how to report' => ['report_help', "To report a phishing site, use the 'Report' button on the scan results page or the Contact form. Provide the suspicious URL and a short description — we will review and add it to reputation lists if confirmed."],
    'otp' => ['otp_help', "If you're not receiving OTPs, check spam filters and ensure your registered email/phone is correct. OTP delivery issues are usually caused by provider delays — try again after a few minutes."],
    'login' => ['login_help', "For login problems: ensure cookies are enabled, try password reset using 'Forgot password', or contact support through the Contact form with your username (do not share your password)."],
    'api' => ['api_help', "Our API endpoint is /api/v1/check for programmatic scans. API keys are required. See Dashboard → Docs for usage examples and rate limits."],
    'privacy' => ['privacy', "We follow a privacy-first approach: personal browsing history is not stored by default. Only essential URL metadata is processed unless you opt in for debugging."],
    'what is phishsafeguard' => ['about', "PhishSafeguard is a next-generation phishing URL detection platform combining heuristics, reputation lookups and ML-based analysis to identify malicious sites in real-time."],
    'help' => ['help', "I can help with: how to scan, how to report, login/OTP issues, API info, and basic product info. Try asking 'how to scan' or 'how to report'."],
];

// keyword matching order: exact phrase keys then generic keywords
$reply = null;
$intent = 'unknown';

// 1) try phrase keys
foreach ($kb as $k => $v) {
    if (mb_stripos($lower, $k, 0, 'UTF-8') !== false) {
        $intent = $v[0];
        $reply = $v[1];
        break;
    }
}

// 2) keyword shortcuts
if ($reply === null) {
    if (mb_strpos($lower, 'scan') !== false || mb_strpos($lower, 'check url') !== false) {
        $intent = 'scan_help';
        $reply = $kb['how to scan'][1];
    } elseif (mb_strpos($lower, 'report') !== false || mb_strpos($lower, 'report phishing') !== false) {
        $intent = 'report_help';
        $reply = $kb['how to report'][1];
    } elseif (mb_strpos($lower, 'otp') !== false) {
        $intent = 'otp_help';
        $reply = $kb['otp'][1];
    } elseif (mb_strpos($lower, 'login') !== false || mb_strpos($lower, 'password') !== false) {
        $intent = 'login_help';
        $reply = $kb['login'][1];
    } elseif (mb_strpos($lower, 'api') !== false || mb_strpos($lower, '/api') !== false) {
        $intent = 'api_help';
        $reply = $kb['api'][1];
    } elseif (mb_strpos($lower, 'privacy') !== false) {
        $intent = 'privacy';
        $reply = $kb['privacy'][1];
    } elseif (mb_strpos($lower, 'what') !== false || mb_strpos($lower, 'who') !== false) {
        $intent = 'about';
        $reply = $kb['what is phishsafeguard'][1];
    }
}

// 3) fallback canned responses with suggestion
if ($reply === null) {
    $intent = 'fallback';
    $reply = "Sorry, I don't have a direct answer to that. I can help with basic items: 'how to scan', 'how to report', 'login/OTP', 'API'. If you need personal help, please use the Contact form on this page.";
}

// Return JSON
echo json_encode([
    'success' => true,
    'reply' => $reply,
    'intent' => $intent,
    'echo' => $clean
], JSON_UNESCAPED_UNICODE);
exit;
