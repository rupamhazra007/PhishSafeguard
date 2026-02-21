<?php
// watchlist_worker_http.php
// Run a limited watchlist worker via HTTP (admin-only, CSRF-protected).
// Returns JSON { success: bool, messages: [ ... ] }
// Security: admin-only, CSRF required. Limit processing to avoid long runs.

session_start();
header('Content-Type: application/json; charset=utf-8');

// 1) Auth
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success'=>false, 'error'=>'Not authenticated']);
    exit();
}

// 2) CSRF check
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
    http_response_code(403);
    echo json_encode(['success'=>false, 'error'=>'Invalid CSRF token']);
    exit();
}

// 3) DB connect
$DB_HOST='localhost'; $DB_USER='root'; $DB_PASS=''; $DB_NAME='phishing_db';
$mysqli = new mysqli($DB_HOST,$DB_USER,$DB_PASS,$DB_NAME);
if ($mysqli->connect_error) {
    http_response_code(500);
    echo json_encode(['success'=>false,'error'=>'DB connect failed']);
    exit();
}

// 4) admin check
$uid = intval($_SESSION['user_id']);
$ust = $mysqli->prepare("SELECT is_admin, username FROM users WHERE id=? LIMIT 1");
$ust->bind_param('i',$uid);
$ust->execute();
$ur = $ust->get_result()->fetch_assoc();
$ust->close();
if (!$ur || intval($ur['is_admin']) !== 1) {
    http_response_code(403);
    echo json_encode(['success'=>false, 'error'=>'Admin access required']);
    $mysqli->close();
    exit();
}

// 5) worker limits (HTTP-safe)
$MAX_TO_PROCESS = 5;
$MAX_BODY = 128 * 1024; // 128 KB
$TIMEOUT = 8; // seconds
$USER_AGENT = 'PhishSafeguard-WebWorker/1.0';
set_time_limit(25);

// helper to fetch trimmed body
function fetch_body($url,$timeout,$ua,$max) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 4);
    curl_setopt($ch, CURLOPT_USERAGENT, $ua);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    $data = '';
    curl_setopt($ch, CURLOPT_WRITEFUNCTION, function($ch,$chunk) use (&$data,$max) {
        $remaining = $max - strlen($data);
        if ($remaining <= 0) return 0; // stop transfer
        $part = substr($chunk,0,$remaining);
        $data .= $part;
        return strlen($part);
    });
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $ok = curl_exec($ch);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    if ($errno) return ['error'=>"curl {$errno}: {$err}"];
    return ['body'=>$data,'http_code'=>$info['http_code'] ?? 0,'content_type'=>$info['content_type'] ?? ''];
}

// 6) fetch watchlists (limited)
$stmt = $mysqli->prepare("SELECT id, user_id, url, last_hash, last_status FROM watchlists ORDER BY id ASC LIMIT ?");
$stmt->bind_param('i',$MAX_TO_PROCESS);
$stmt->execute();
$res = $stmt->get_result();
$watchlists = $res->fetch_all(MYSQLI_ASSOC);
$stmt->close();

$insNotif = $mysqli->prepare("INSERT INTO notifications (user_id, title, body, is_read, payload, created_at) VALUES (?, ?, ?, 0, ?, NOW())");
$updWatch = $mysqli->prepare("UPDATE watchlists SET last_hash = ?, last_status = ?, last_run = NOW() WHERE id = ?");

$messages = [];
$created = 0;
$proc = 0;

foreach ($watchlists as $wl) {
    $proc++;
    $wid = intval($wl['id']);
    $wuid = intval($wl['user_id']);
    $url = $wl['url'];
    $prev_hash = $wl['last_hash'] ?? '';
    $prev_status = $wl['last_status'] ?? null;

    $messages[] = "Processing watchlist id={$wid} url={$url}";
    $out = fetch_body($url, $TIMEOUT, $USER_AGENT, $MAX_BODY);
    if (isset($out['error'])) {
        $messages[] = "  Fetch error: " . $out['error'];
        $status = 'fetch_error';
        $updWatch->bind_param('ssi', $prev_hash, $status, $wid);
        $updWatch->execute();
        continue;
    }
    $body = $out['body'] ?? '';
    $http = $out['http_code'] ?? 0;

    $body_hash = hash('sha256', $body);
    $low = strtolower($body);
    $is_cred = (strpos($low,'type="password"') !== false || strpos($low,"type='password'") !== false || preg_match('/<input[^>]+password/i',$low));
    $susp_terms = ['verify','confirm','bank','account','login','credential','secure-pay','update your','urgent'];
    $susp_count = 0;
    foreach ($susp_terms as $t) if (strpos($low,$t)!==false) $susp_count++;

    $should_notify = false;
    $current_status = 'unchanged';
    $title = ''; $body_msg = '';

    if ($body_hash !== $prev_hash) {
        $current_status = 'changed';
        $should_notify = true;
        $title = "Watchlist changed: {$url}";
        $body_msg = "Page changed (HTTP {$http}). Suspicious terms: {$susp_count}, credential_form=" . ($is_cred ? 'yes' : 'no');
    }

    if ($is_cred && $prev_status !== 'credential') {
        $should_notify = true;
        $current_status = 'credential';
        $title = "Credential-like form detected on {$url}";
        $body_msg = "Password/credential input fields detected on page.";
    }

    if (!$is_cred && $susp_count >= 2 && ($body_hash !== $prev_hash || $prev_status !== 'suspicious_terms')) {
        $should_notify = true;
        $current_status = 'suspicious_terms';
        $title = "Suspicious content on {$url}";
        $body_msg = "Found {$susp_count} suspicious keywords (HTTP {$http}).";
    }

    if ($should_notify) {
        $payload = json_encode(['watchlist_id'=>$wid,'url'=>$url,'http_code'=>$http,'suspicious_terms'=>$susp_count,'credential'=>$is_cred]);
        $insNotif->bind_param('isss', $wuid, $title, $body_msg, $payload);
        if ($insNotif->execute()) {
            $messages[] = "  -> Notification created for user {$wuid}";
            $created++;
        } else {
            $messages[] = "  -> Failed to create notification: " . $insNotif->error;
        }
    } else {
        $messages[] = "  -> No notification needed (status: {$current_status})";
    }

    // update watchlist
    $updWatch->bind_param('ssi', $body_hash, $current_status, $wid);
    $updWatch->execute();
}

// close
$insNotif->close();
$updWatch->close();
$mysqli->close();

$messages[] = "Done. Processed: {$proc}, Notifications created: {$created}";
echo json_encode(['success'=>true,'messages'=>$messages], JSON_PRETTY_PRINT);
exit();
