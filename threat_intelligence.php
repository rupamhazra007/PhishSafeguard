<?php
/**
 * ======================================================
 * Threat Intelligence Engine – PhishSafeguard
 * Location: C:\xampp\htdocs\phish_safeguard\
 * API-less, DB + heuristic based
 * ======================================================
 */

header('Content-Type: application/json');

// 🔗 DB connection (index.php এর মতোই)
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phishing_db";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    echo json_encode(['error' => 'DB connection failed']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'Invalid request method']);
    exit;
}

$url = trim($_POST['url'] ?? '');
if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) {
    echo json_encode(['error' => 'Invalid URL']);
    exit;
}

$parsed = parse_url($url);
$domain = strtolower($parsed['host'] ?? '');
$scheme = strtolower($parsed['scheme'] ?? '');

/* ===================== RESPONSE STRUCT ===================== */
$intel = [
    'url' => $url,
    'domain' => $domain,
    'signals' => [],
    'risk_score' => 0,
    'verdict' => 'Safe'
];

/* ===========================================================
   1️⃣ INTERNAL BLACKLIST CHECK
=========================================================== */
$stmt = $conn->prepare("SELECT id FROM blacklist WHERE url = ? OR domain = ?");
$stmt->bind_param("ss", $url, $domain);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $intel['signals'][] = 'Listed in internal blacklist';
    $intel['risk_score'] += 60;
}
$stmt->close();

/* ===========================================================
   2️⃣ KEYWORD-BASED THREAT INTEL
=========================================================== */
$keywords = ['login','verify','update','secure','bank','account','confirm','signin'];
foreach ($keywords as $k) {
    if (stripos($url, $k) !== false) {
        $intel['signals'][] = "Suspicious keyword detected: {$k}";
        $intel['risk_score'] += 8;
    }
}

/* ===========================================================
   3️⃣ SSL / HTTP CHECK
=========================================================== */
if ($scheme === 'http') {
    $intel['signals'][] = 'Uses HTTP instead of HTTPS';
    $intel['risk_score'] += 15;
}

/* ===========================================================
   4️⃣ DNS / DOMAIN STABILITY CHECK
=========================================================== */
$dns = dns_get_record($domain, DNS_A);
if (!$dns) {
    $intel['signals'][] = 'DNS record missing or unstable';
    $intel['risk_score'] += 20;
}

/* ===========================================================
   5️⃣ HISTORICAL PHISHSafeguard DATA
=========================================================== */
$stmt = $conn->prepare("
    SELECT 
      SUM(result='phishing') AS phish_cnt,
      COUNT(*) AS total_cnt
    FROM url_checks
    WHERE url LIKE CONCAT('%', ?, '%')
");
$stmt->bind_param("s", $domain);
$stmt->execute();
$stmt->bind_result($phish_cnt, $total_cnt);
$stmt->fetch();
$stmt->close();

if ($total_cnt > 0 && $phish_cnt > 0) {
    $intel['signals'][] = "Previously flagged {$phish_cnt} time(s)";
    $intel['risk_score'] += min(30, $phish_cnt * 10);
}

/* ===========================================================
   FINAL VERDICT
=========================================================== */
$intel['risk_score'] = min(100, $intel['risk_score']);

if ($intel['risk_score'] >= 60) {
    $intel['verdict'] = 'Phishing';
} elseif ($intel['risk_score'] >= 30) {
    $intel['verdict'] = 'Suspicious';
}

echo json_encode([
    'success' => true,
    'threat_intelligence' => $intel
], JSON_PRETTY_PRINT);
