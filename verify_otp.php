<?php
// verify_otp.php (FINAL PREMIUM DESIGN - Deep Glassmorphism)
session_start();

$servername = "localhost";
$dbusername = "root";
$dbpassword = "";
$dbname = "phishing_db";
$conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

require_once __DIR__ . '/mail_helper.php';

define('OTP_MAX_ATTEMPTS', 3);
define('OTP_BLOCK_SECONDS', 60);
define('OTP_RESEND_COOLDOWN', 60);

$error = '';
$success = false;
$now = time();
$redirect_after_success = 'index.php';

if (!isset($_SESSION['pending_2fa_user'])) {
    header("Location: login.php");
    exit();
}
$user_id = intval($_SESSION['pending_2fa_user']);

if (!isset($_SESSION['otp_attempts'])) $_SESSION['otp_attempts'] = 0;
if (!isset($_SESSION['otp_block_until'])) $_SESSION['otp_block_until'] = 0;
if (!isset($_SESSION['last_resend'])) $_SESSION['last_resend'] = 0;

if (!empty($_SESSION['otp_block_until']) && $_SESSION['otp_block_until'] > $now) {
    $remaining = $_SESSION['otp_block_until'] - $now;
    $error = "Too many incorrect attempts. Please wait {$remaining} second(s).";
}

function use_twilio_verify(): bool {
    $verifySid = getenv('TWILIO_VERIFY_SID') ?: ($_ENV['TWILIO_VERIFY_SID'] ?? '');
    return !empty($verifySid);
}

function remember_requested(): bool {
    return !empty($_SESSION['pending_2fa_remember']) || !empty($_SESSION['remember_me_requested']);
}

// ... (Your Twilio send/check functions stay exactly here) ...

if (!function_exists('twilio_verify_send')) {
    function twilio_verify_send($dest) {
        global $conn, $user_id;
        $dest = trim((string)$dest);
        $accountSid = getenv('TWILIO_ACCOUNT_SID') ?: ($_ENV['TWILIO_ACCOUNT_SID'] ?? '');
        $authToken  = getenv('TWILIO_AUTH_TOKEN') ?: ($_ENV['TWILIO_AUTH_TOKEN'] ?? '');
        $serviceSid = getenv('TWILIO_VERIFY_SID') ?: ($_ENV['TWILIO_VERIFY_SID'] ?? '');

        if (!empty($accountSid) && !empty($authToken) && !empty($serviceSid) && class_exists('\Twilio\Rest\Client')) {
            try {
                $client = new \Twilio\Rest\Client($accountSid, $authToken);
                $client->verify->v2->services($serviceSid)->verifications->create($dest, 'sms');
                $_SESSION['pending_2fa_contact'] = $dest;
                $_SESSION['pending_2fa_sent_at'] = time();
                return true;
            } catch (Throwable $e) {
                error_log("[verify_otp] Twilio Verify send error: " . $e->getMessage());
            }
        }
        try {
            $otp = strval(random_int(100000, 999999));
            $expiry = date("Y-m-d H:i:s", strtotime("+5 minutes"));
            $update = $conn->prepare("UPDATE users SET otp_code = ?, otp_expires = ? WHERE id = ?");
            if (!$update) return false;
            $update->bind_param("ssi", $otp, $expiry, $user_id);
            $ok = $update->execute();
            $update->close();
            if (!$ok) return false;

            $sent = false;
            if (strpos($dest, '@') !== false && function_exists('sendOtpMail')) {
                $stmt = $conn->prepare("SELECT username FROM users WHERE id = ? LIMIT 1");
                if ($stmt) {
                    $stmt->bind_param("i", $user_id);
                    $stmt->execute();
                    $stmt->bind_result($dbUsername);
                    $stmt->fetch();
                    $stmt->close();
                } else { $dbUsername = $dest; }
                $sent = sendOtpMail($dest, $dbUsername ?? $dest, $otp);
            } else {
                $digits = preg_replace('/\D+/', '', $dest);
                if ($digits === null || $digits === '') return false;
                $toE164 = '+' . $digits;
                if (function_exists('send_programmable_sms')) {
                    $sent = send_programmable_sms($toE164, $otp);
                } elseif (function_exists('sendOtpSms')) {
                    $sent = sendOtpSms($toE164, $otp);
                }
            }
            if ($sent) {
                $_SESSION['pending_2fa_contact'] = $dest;
                $_SESSION['pending_2fa_sent_at'] = time();
                return true;
            }
            return false;
        } catch (Throwable $e) { return false; }
    }
}

if (!function_exists('twilio_verify_check')) {
    function twilio_verify_check($dest, $code) {
        global $conn, $user_id;
        $dest = trim((string)$dest);
        $accountSid = getenv('TWILIO_ACCOUNT_SID') ?: ($_ENV['TWILIO_ACCOUNT_SID'] ?? '');
        $authToken  = getenv('TWILIO_AUTH_TOKEN') ?: ($_ENV['TWILIO_AUTH_TOKEN'] ?? '');
        $serviceSid = getenv('TWILIO_VERIFY_SID') ?: ($_ENV['TWILIO_VERIFY_SID'] ?? '');

        if (!empty($accountSid) && !empty($authToken) && !empty($serviceSid) && class_exists('\Twilio\Rest\Client')) {
            try {
                $client = new \Twilio\Rest\Client($accountSid, $authToken);
                $result = $client->verify->v2->services($serviceSid)->verificationChecks->create(['to' => $dest, 'code' => $code]);
                if (!empty($result->status) && strtolower($result->status) === 'approved') return true;
                return false;
            } catch (Throwable $e) { error_log("[verify_otp] Twilio Verify check error: " . $e->getMessage()); }
        }
        try {
            $stmt = $conn->prepare("SELECT otp_code, otp_expires FROM users WHERE id = ? LIMIT 1");
            if (!$stmt) return false;
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->bind_result($dbOtp, $dbExpiry);
            $stmt->fetch();
            $stmt->close();
            if (!empty($dbOtp) && hash_equals((string)$dbOtp, (string)$code) && !empty($dbExpiry) && strtotime($dbExpiry) > time()) return true;
            return false;
        } catch (Throwable $e) { return false; }
    }
}

// ... (Your Main POST handling stays exactly here) ...
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    if (isset($_POST['otp'])) {
        $otp = trim($_POST['otp']);
        if (use_twilio_verify()) {
            $dest = $_SESSION['pending_2fa_contact'] ?? null;
            if (!$dest) {
                $stmt = $conn->prepare("SELECT email, phone FROM users WHERE id = ? LIMIT 1");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->bind_result($dbEmail, $dbPhone);
                $stmt->fetch();
                $stmt->close();
                $dest = $dbEmail ?: $dbPhone ?: null;
            }
            if (!$dest) {
                $error = "No verification contact found.";
                $verified = false;
            } else {
                $verified = (bool)twilio_verify_check($dest, $otp);
            }
        } else {
            $stmt = $conn->prepare("SELECT otp_code, otp_expires, username, is_admin, email FROM users WHERE id = ? LIMIT 1");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->bind_result($dbOtp, $dbExpiry, $dbUsername, $dbIsAdmin, $dbEmail);
            $stmt->fetch();
            $stmt->close();
            $verified = (!empty($dbOtp) && hash_equals((string)$dbOtp, (string)$otp) && strtotime($dbExpiry) > time());
        }

        if (!empty($verified)) {
            $clear = $conn->prepare("UPDATE users SET otp_code=NULL, otp_expires=NULL WHERE id=?");
            if ($clear) { $clear->bind_param("i", $user_id); $clear->execute(); $clear->close(); }

            $stmt = $conn->prepare("SELECT username, is_admin FROM users WHERE id = ? LIMIT 1");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->bind_result($finalUsername, $finalIsAdmin);
            $stmt->fetch();
            $stmt->close();

            session_regenerate_id(true);
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $finalUsername ?? '';
            $_SESSION['is_admin'] = (int)($finalIsAdmin ?? 0);

            $planName = $_SESSION['prelogin_plan_name']  ?? null;
            $isPremium = isset($_SESSION['prelogin_is_premium']) ? (int)$_SESSION['prelogin_is_premium'] : null;
            if ($planName === null || $isPremium === null) {
                $ps = $conn->prepare("SELECT plan_name, is_premium FROM users WHERE id = ? LIMIT 1");
                if ($ps) {
                    $ps->bind_param("i", $user_id);
                    $ps->execute();
                    $ps->bind_result($dbPlan, $dbPrem);
                    if ($ps->fetch()) {
                        $planName = $planName ?? ($dbPlan ?: 'Basic');
                        $isPremium = $isPremium ?? (int)($dbPrem ?? 0);
                    }
                    $ps->close();
                }
            }
            if ($planName === null) $planName = 'Basic';
            if ($isPremium === null) $isPremium = 0;

            $_SESSION['subscribed_plan'] = $planName;
            $_SESSION['user_tier']       = $planName;
            $_SESSION['is_premium']      = (int)$isPremium;

            unset($_SESSION['prelogin_plan_name'], $_SESSION['prelogin_is_premium']);
            unset($_SESSION['pending_2fa_user'], $_SESSION['pending_2fa_role'], $_SESSION['pending_2fa_contact'], $_SESSION['pending_2fa_channel'], $_SESSION['pending_2fa_sent_at']);
            unset($_SESSION['otp_attempts'], $_SESSION['otp_block_until'], $_SESSION['last_resend'], $_SESSION['pending_2fa_remember'], $_SESSION['remember_me_requested']);

            if (remember_requested()) {
                try {
                    $token = bin2hex(random_bytes(32));
                    $expiryTs = time() + (30 * 24 * 60 * 60);
                    $expirySql = date("Y-m-d H:i:s", $expiryTs);
                    $appSecret = getenv('APP_SECRET') ?: ($_ENV['APP_SECRET'] ?? '');
                    $dbToken = !empty($appSecret) ? hash_hmac('sha256', $token, $appSecret) : hash('sha256', $token);
                    $upd = $conn->prepare("UPDATE users SET remember_token = ?, remember_expiry = ? WHERE id = ?");
                    if ($upd) {
                        $upd->bind_param("ssi", $dbToken, $expirySql, $user_id);
                        $upd->execute();
                        $upd->close();
                        $cookieVal = $user_id . ":" . $token;
                        $secureFlag = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
                        setcookie('remember_token', $cookieVal, [ 'expires' => $expiryTs, 'path' => '/', 'domain' => '', 'secure' => $secureFlag, 'httponly' => true, 'samesite' => 'Lax' ]);
                    }
                } catch (Throwable $e) {}
            }

            if (!empty($_SESSION['pending_2fa_next'])) {
                $redirect_after_success = $_SESSION['pending_2fa_next'];
                unset($_SESSION['pending_2fa_next']);
            }
            $success = true;

        } else {
            $_SESSION['otp_attempts'] = ($_SESSION['otp_attempts'] ?? 0) + 1;
            $attempts_left = OTP_MAX_ATTEMPTS - $_SESSION['otp_attempts'];
            if ($attempts_left <= 0) {
                $_SESSION['otp_block_until'] = time() + OTP_BLOCK_SECONDS;
                $error = "Too many incorrect attempts. Blocked for " . OTP_BLOCK_SECONDS . "s.";
            } else {
                $error = "Invalid OTP. {$attempts_left} attempt(s) left.";
            }
        }
    } elseif (isset($_POST['resend'])) {
        $now = time();
        if (!isset($_SESSION['last_resend']) || ($now - $_SESSION['last_resend']) > OTP_RESEND_COOLDOWN) {
            // Re-send logic
            if (use_twilio_verify()) {
                $dest = $_SESSION['pending_2fa_contact'] ?? null;
                if (!$dest) {
                    $stmt = $conn->prepare("SELECT email, phone FROM users WHERE id = ? LIMIT 1");
                    $stmt->bind_param("i", $user_id);
                    $stmt->execute();
                    $stmt->bind_result($dbEmail, $dbPhone);
                    $stmt->fetch();
                    $stmt->close();
                    $dest = $dbEmail ?: $dbPhone ?: null;
                }
                if ($dest && twilio_verify_send($dest)) {
                    $_SESSION['last_resend'] = time();
                    $_SESSION['otp_attempts'] = 0;
                    $success = "A new code has been sent.";
                    $_SESSION['pending_2fa_contact'] = $dest;
                } else { $error = "Failed to resend code."; }
            } else {
                $otp = strval(random_int(100000, 999999));
                $expiry = date("Y-m-d H:i:s", strtotime("+5 minutes"));
                $update = $conn->prepare("UPDATE users SET otp_code = ?, otp_expires = ? WHERE id = ?");
                $update->bind_param("ssi", $otp, $expiry, $user_id);
                $update->execute();
                $update->close();

                $stmt = $conn->prepare("SELECT username, email, phone FROM users WHERE id = ? LIMIT 1");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->bind_result($dbUsername, $dbEmail, $dbPhone);
                $stmt->fetch();
                $stmt->close();

                $sent = false;
                if (!empty($dbPhone)) {
                    $to = '+' . preg_replace('/\D+/', '', $dbPhone);
                    $sent = function_exists('send_programmable_sms') ? send_programmable_sms($to, $otp) : (function_exists('sendOtpSms') ? sendOtpSms($to, $otp) : false);
                }
                if (!$sent && !empty($dbEmail)) {
                    if (function_exists('sendOtpMail')) $sent = sendOtpMail($dbEmail, $dbUsername ?: $dbEmail, $otp);
                }
                if ($sent) {
                    $_SESSION['last_resend'] = time();
                    $_SESSION['otp_attempts'] = 0;
                    $success = "A new code has been sent.";
                } else { $error = "Failed to resend code."; }
            }
        } else {
            $wait = OTP_RESEND_COOLDOWN - ($now - $_SESSION['last_resend']);
            $error = "Wait {$wait}s before requesting a new OTP.";
        }
    }
}
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify Identity - PhishSafeguard</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@800;900&display=swap" rel="stylesheet">
<style>
    :root {
        --primary: #10b981; /* Emerald Green */
        --primary-glow: rgba(16, 185, 129, 0.6);
        --primary-dark: #059669;
        
        /* Deep but not dark Glass Effect */
        --glass-bg: rgba(15, 23, 42, 0.55); 
        --glass-border: rgba(16, 185, 129, 0.25);
        
        --text-main: #f8fafc;
        --text-muted: #cbd5e1;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body, html {
        min-height: 100vh;
        font-family: 'Times New Roman', Times, serif; 
        display: flex;
        justify-content: center;
        align-items: center;
        overflow-y: auto; 
        /* The image background with a subtle deep-teal tint, not solid black */
        background: linear-gradient(135deg, rgba(8, 20, 35, 0.7) 0%, rgba(2, 40, 45, 0.4) 100%), 
                    url('AN.jpg') no-repeat center center fixed;
        background-size: cover;
        color: var(--text-main);
    }

    /* --- Ambient Animated Glow Orbs --- */
    .bg-shape {
        position: absolute; border-radius: 50%; filter: blur(70px);
        opacity: 0.5; z-index: 0;
        animation: floatShape 15s infinite alternate ease-in-out;
        mix-blend-mode: screen;
    }
    .shape1 { width: 400px; height: 400px; background: var(--primary); top: 10%; left: 10%; }
    .shape2 { width: 500px; height: 500px; background: #0ea5e9; bottom: 5%; right: 5%; animation-delay: -5s; opacity: 0.3; }

    @keyframes floatShape {
        0% { transform: translate(0, 0) scale(1); }
        50% { transform: translate(40px, -40px) scale(1.1); }
        100% { transform: translate(-30px, 50px) scale(0.9); }
    }

    /* --- Header & Logo exactly top-left --- */
    .main-header {
        position: absolute; top: 40px; left: 50px; z-index: 100;
        animation: slideDownFade 1.2s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }

    .brand-logo {
        font-family: 'Montserrat', sans-serif; font-weight: 900; 
        font-size: 2rem; color: var(--primary); 
        display: flex; align-items: center; gap: 12px; cursor: default;
        text-shadow: 0 0 15px var(--primary-glow); 
    }

    .brand-logo i {
        color: var(--primary);
        filter: drop-shadow(0 0 8px var(--primary-glow));
        animation: pulseIcon 3s infinite ease-in-out;
    }

    @keyframes pulseIcon { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.08); } }

    /* --- The Deep Glass Verification Card --- */
    .verify-card {
        position: relative; z-index: 10;
        background: var(--glass-bg);
        backdrop-filter: blur(20px) saturate(150%);
        -webkit-backdrop-filter: blur(20px) saturate(150%);
        border-radius: 24px;
        border: 1px solid var(--glass-border);
        border-top: 1px solid rgba(255,255,255,0.2);
        border-left: 1px solid rgba(255,255,255,0.1);
        padding: 4rem 3.5rem;
        width: 460px; max-width: 92%; text-align: center;
        box-shadow: 0 30px 60px rgba(0, 0, 0, 0.4), inset 0 0 20px rgba(16, 185, 129, 0.05);
        margin: 120px 20px 50px 20px;
        opacity: 0; transform: translateY(40px);
        animation: cardEntrance 1s cubic-bezier(0.2, 0.8, 0.2, 1) 0.2s forwards;
    }
    
    @keyframes cardEntrance { to { transform: translateY(0); opacity: 1; } }

    .verify-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 35px 70px rgba(0, 0, 0, 0.5), inset 0 0 30px rgba(16, 185, 129, 0.1);
        transition: all 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        border-color: rgba(16, 185, 129, 0.4);
    }

    /* --- Typography Animations --- */
    h2 { 
        margin-bottom: 0.5rem; color: var(--text-main); 
        font-size: 2.2rem; font-weight: 700; letter-spacing: 1px;
        overflow: hidden; white-space: nowrap; margin-inline: auto;
        border-right: 3px solid var(--primary);
        animation: typing 2.5s steps(30, end) forwards, blink-caret 0.8s step-end infinite;
    }
    @keyframes typing { from { width: 0 } to { width: 100% } }
    @keyframes blink-caret { from, to { border-color: transparent } 50% { border-color: var(--primary); } }

    .subtitle {
        color: var(--text-muted); font-size: 1.1rem; margin-bottom: 2.5rem;
        opacity: 0; transform: translateY(10px);
        animation: fadeUp 0.8s ease 1.5s forwards;
    }

    /* --- Premium Inputs --- */
    .input-group { opacity: 0; transform: translateY(20px); animation: fadeUp 0.8s ease 1.8s forwards; }

    input[type="text"] { 
        background: rgba(0, 0, 0, 0.25);
        border: 2px solid rgba(255, 255, 255, 0.1);
        padding: 1.2rem; border-radius: 14px; width: 100%; 
        font-size: 2rem; letter-spacing: 14px; text-align: center;
        font-family: 'Courier New', Courier, monospace;
        color: var(--primary); font-weight: 700;
        transition: all 0.4s ease;
        box-shadow: inset 0 4px 10px rgba(0,0,0,0.3);
    }

    input::placeholder { color: rgba(255,255,255,0.2); font-size: 1.2rem; letter-spacing: 4px; font-family: 'Times New Roman', serif; }
    
    input:focus { 
        background: rgba(0, 0, 0, 0.4);
        border-color: var(--primary); 
        box-shadow: 0 0 25px var(--primary-glow), inset 0 4px 10px rgba(0,0,0,0.5); 
        outline: none; transform: scale(1.02);
    }

    /* --- Animated Buttons --- */
    .anim-btn-wrap { opacity: 0; transform: translateY(20px); animation: fadeUp 0.8s ease 2s forwards; }

    .btn { 
        padding: 1.2rem; border: none; border-radius: 14px; width: 100%; 
        font-family: 'Times New Roman', Times, serif; font-size: 1.2rem; font-weight: 700;
        cursor: pointer; transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        position: relative; overflow: hidden; margin-top: 1rem;
    }

    .btn-primary { 
        background: linear-gradient(135deg, var(--primary), var(--primary-dark)); 
        color: #fff; box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3); 
        border-top: 1px solid rgba(255,255,255,0.3);
    }
    
    .btn-primary::before {
        content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
        transform: skewX(-25deg); transition: 0.7s ease;
    }
    .btn-primary:hover::before { left: 150%; }
    .btn-primary:hover { transform: translateY(-4px); box-shadow: 0 15px 30px rgba(16, 185, 129, 0.5); filter: brightness(1.1); }
    .btn-primary:active { transform: translateY(1px); }

    .btn-secondary { 
        background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.15);
        color: var(--text-muted); margin-top: 1.5rem; backdrop-filter: blur(5px);
    }
    .btn-secondary:hover:not(:disabled) { 
        background: rgba(16, 185, 129, 0.1); border-color: var(--primary); color: var(--primary);
        box-shadow: 0 0 20px var(--primary-glow);
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none !important; }

    /* --- Dynamic Messages --- */
    .error-message, .success-message {
        padding: 1.2rem; margin-bottom: 1.5rem; border-radius: 12px;
        font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 10px;
        animation: shake 0.6s cubic-bezier(.36,.07,.19,.97) both;
    }
    @keyframes shake { 0%, 100% { transform: translateX(0); } 20%, 60% { transform: translateX(-6px); } 40%, 80% { transform: translateX(6px); } }
    @keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes slideDownFade { from { transform: translateY(-30px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

    .error-message { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }
    .success-message { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.4); animation: slideDownFade 0.6s ease forwards; }
    
    .info-text { margin-top: 2rem; font-size: 1rem; color: var(--text-muted); line-height: 1.6; }
    .small-note { font-size: 0.9rem; color: rgba(255,255,255,0.4); margin-top: 15px; font-style: italic; }
    
    .redirect-link { color: var(--primary); text-decoration: none; font-weight: 700; transition: 0.3s; border-bottom: 1px dashed transparent; padding-bottom: 2px;}
    .redirect-link:hover { color: #fff; border-color: #fff; text-shadow: 0 0 10px var(--primary-glow); }

    @media (max-width: 850px) {
        .main-header { left: 25px; top: 25px; }
        .brand-logo { font-size: 1.5rem; }
        .verify-card { padding: 3rem 2rem; margin-top: 100px; width: 100%;}
        h2 { font-size: 1.8rem; }
        input[type="text"] { font-size: 1.5rem; letter-spacing: 8px; }
    }
</style>
</head>
<body>

    <header class="main-header">
        <div class="brand-logo">
            <i class="fa-solid fa-shield-halved"></i>
            <span>PhishSafeguard</span>
        </div>
    </header>

    <div class="bg-shape shape1"></div>
    <div class="bg-shape shape2"></div>

    <div class="verify-card" id="cardElement">
        
        <h2 id="headerText">Security Check</h2>
        <div class="subtitle">Please verify your identity</div>

        <?php if ($error): ?>
            <div class="error-message"><i class="fa-solid fa-circle-exclamation"></i> <?= htmlspecialchars($error) ?></div>
            <script>document.getElementById('cardElement').style.animation = "shake 0.5s";</script>
        <?php endif; ?>

        <?php if (is_string($success) && !empty($success)): ?>
            <div class="success-message"><i class="fa-solid fa-check-circle"></i> <?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <?php if ($success === true): ?>
            <div class="success-message" style="font-size: 1.3rem; padding: 1.5rem;"><i class="fa-solid fa-shield-check"></i> Verification Successful!</div>
            <p class="info-text" style="color: #fff;">You're securely logged in. Redirecting to your dashboard...</p>
            <p><a href="<?= htmlspecialchars($redirect_after_success) ?>" class="redirect-link">Click here if not redirected</a></p>

            <script>
            document.getElementById('headerText').innerText = "Secured.";
            document.querySelector('.subtitle').style.display = 'none';

            (async function(){
                try {
                    const pw = sessionStorage.getItem('ps_temp_pw');
                    const un = sessionStorage.getItem('ps_temp_un');
                    sessionStorage.removeItem('ps_temp_pw');
                    sessionStorage.removeItem('ps_temp_un');

                    if (!pw || !un) {
                        setTimeout(()=>{ window.location.href = '<?= htmlspecialchars($redirect_after_success) ?>'; }, 1500);
                        return;
                    }

                    if (window.PasswordCredential && navigator.credentials && navigator.credentials.store) {
                        try {
                            const cred = new PasswordCredential({ id: un, password: pw, name: un });
                            await navigator.credentials.store(cred);
                        } catch (err) { console.warn('Credential store failed:', err); }
                    } else if (navigator.credentials && navigator.credentials.create) {
                        try {
                            const created = await navigator.credentials.create({ password: true });
                            if (created) await navigator.credentials.store(created);
                        } catch (err) { console.warn('Credential API fallback failed', err); }
                    }
                } catch(e) {}
                finally { setTimeout(()=>{ window.location.href = '<?= htmlspecialchars($redirect_after_success) ?>'; }, 1800); }
            })();
            </script>

        <?php else: ?>

            <?php if (!empty($_SESSION['otp_block_until']) && $_SESSION['otp_block_until'] > $now):
                $remaining = $_SESSION['otp_block_until'] - $now;
            ?>
                <div class="error-message"><i class="fa-solid fa-lock"></i> Access Temporarily Blocked</div>
                <p class="info-text">Too many incorrect attempts. Please try again in <strong style="color:var(--primary); font-size:1.3rem;"><?= $remaining ?>s</strong>.</p>
            <?php else: ?>

                <form method="POST">
                    <div class="input-group">
                        <input type="text" name="otp" placeholder="••••••" required pattern="\d{6}" maxlength="6" inputmode="numeric" autocomplete="one-time-code" autofocus>
                    </div>
                    <div class="anim-btn-wrap">
                        <button type="submit" name="verify" class="btn btn-primary">Verify Identity</button>
                    </div>
                </form>

                <form method="POST" class="anim-btn-wrap" style="animation-delay: 2.2s;">
                    <?php
                        $canResend = (!isset($_SESSION['last_resend']) || ($now - $_SESSION['last_resend']) > OTP_RESEND_COOLDOWN);
                        $resend_label = $canResend ? 'Resend Secure Code' : 'Wait ' . (OTP_RESEND_COOLDOWN - ($now - $_SESSION['last_resend'])) . 's';
                    ?>
                    <button type="submit" name="resend" class="btn btn-secondary" <?= $canResend ? '' : 'disabled' ?>>
                        <i class="fa-solid fa-rotate-right" style="margin-right: 8px;"></i> <?= htmlspecialchars($resend_label) ?>
                    </button>
                </form>

                <div class="anim-btn-wrap" style="animation-delay: 2.4s;">
                    <p class="info-text">A 6-digit code has been sent to your registered contact.<br>Code expires in 5 minutes.</p>
                    <p class="small-note">After <?= OTP_MAX_ATTEMPTS ?> wrong attempts, your account will be locked for security.</p>
                </div>

            <?php endif; ?>

        <?php endif; ?>

    </div>
</body>
</html>