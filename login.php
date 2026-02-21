<?php
session_start();

// include mail helper (expects vendor/autoload + dotenv + sendOtpMail/sendOtpSms functions)
require_once __DIR__ . '/mail_helper.php'; 

// Database configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phishing_db";

// reCAPTCHA secret (server-side)
$RECAPTCHA_SECRET = '6LcmlcMrAAAAAG5RtMZLrcGT6B-oqT6Exj2auI65';
// reCAPTCHA site key (frontend)
$RECAPTCHA_SITEKEY = '6LcmlcMrAAAAAOvt17e9zB44xfYalFCpz6Sylcdp';

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Generate CSRF token if not set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Initialize Login Attempts Tracking
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}
if (!isset($_SESSION['lockout_time'])) {
    $_SESSION['lockout_time'] = 0;
}

$error = '';
$max_attempts = 5;
$remaining_attempts = $max_attempts - $_SESSION['login_attempts'];

// Check if user is temporarily locked out
if ($_SESSION['lockout_time'] > time()) {
    $lock_left = ceil(($_SESSION['lockout_time'] - time()) / 60);
    $error = "Account temporarily locked due to multiple failed attempts. Try again in $lock_left minute(s).";
}

$next_after_login = isset($_GET['next']) ? trim($_GET['next']) : 'index.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login']) && empty($error)) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid CSRF token.";
    } else {
        // inputs
        $identifier_raw = trim($_POST['identifier'] ?? '');
        $passwordInput = $_POST['password'] ?? '';
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
        $role_requested = isset($_POST['role']) && in_array($_POST['role'], ['user','admin']) ? $_POST['role'] : 'user';
        $remember_checked = isset($_POST['remember']) && $_POST['remember'] === '1';
        $trusted_device = isset($_POST['trusted_device']) && $_POST['trusted_device'] === '1';

        // detect identifier type
        $is_email = false;
        $is_phone = false;
        $email_val = null;
        $phone_val = null;

        if (filter_var($identifier_raw, FILTER_VALIDATE_EMAIL)) {
            $is_email = true;
            $email_val = $identifier_raw;
        } else {
            $digits = preg_replace('/\D/', '', $identifier_raw);
            if (strlen($digits) >= 7 && strlen($digits) <= 15) {
                $is_phone = true;
                $phone_val = $digits;
            }
        }

        if (!$is_email && !$is_phone) {
            $error = "Please enter a valid email or phone number.";
        } elseif (empty($passwordInput)) {
            $error = "Please enter your password.";
        } elseif (empty($recaptcha_response)) {
            $error = "Please complete the reCAPTCHA.";
        } else {
            // Verify reCAPTCHA
            $ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
                'secret' => $RECAPTCHA_SECRET,
                'response' => $recaptcha_response,
                'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
            ]));
            $verifyResp = curl_exec($ch);
            curl_close($ch);
            $verifyData = json_decode($verifyResp, true);

            if (empty($verifyData['success'])) {
                $error = 'reCAPTCHA verification failed.';
            } else {
                // DB check
                if ($is_email) {
                    $stmt = $conn->prepare("SELECT id, username, password, is_admin, email, phone FROM users WHERE email = ? LIMIT 1");
                    $stmt->bind_param("s", $email_val);
                } else {
                    $stmt = $conn->prepare("SELECT id, username, password, is_admin, email, phone FROM users WHERE phone = ? LIMIT 1");
                    $stmt->bind_param("s", $phone_val);
                }

                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 1) {
                    $stmt->bind_result($id, $username, $hashedPassword, $is_admin, $dbEmail, $dbPhone);
                    $stmt->fetch();

                    // Strict Role Enforcement
                    if ((int)$is_admin === 1 && $role_requested !== 'admin') {
                        $error = "Admin account — please select 'Admin' role.";
                        $_SESSION['login_attempts']++;
                    } elseif ((int)$is_admin === 0 && $role_requested === 'admin') {
                        $error = "Access denied: Not an admin account.";
                        $_SESSION['login_attempts']++;
                    } elseif (!password_verify($passwordInput, $hashedPassword)) {
                        $_SESSION['login_attempts']++;
                        $remaining = $max_attempts - $_SESSION['login_attempts'];
                        if ($_SESSION['login_attempts'] >= $max_attempts) {
                            $_SESSION['lockout_time'] = time() + (15 * 60);
                            $error = "Account locked for 15 minutes due to too many failed attempts.";
                        } else {
                            $error = "Incorrect password. $remaining attempt(s) remaining.";
                        }
                    } else {
                        $_SESSION['login_attempts'] = 0; 
                        
                        // Generate OTP
                        $otp = strval(random_int(100000, 999999));
                        $expiry = date("Y-m-d H:i:s", strtotime("+5 minutes"));

                        // Update DB with OTP
                        $u_stmt = $conn->prepare("UPDATE users SET otp_code=?, otp_expires=? WHERE id=?");
                        $u_stmt->bind_param("ssi", $otp, $expiry, $id);
                        $u_stmt->execute();

                        // Send OTP
                        $sent = false;
                        if ($is_email) {
                            $sent = sendOtpMail($dbEmail, $username, $otp);
                        } else {
                            $target = $dbPhone ? preg_replace('/\D/', '', $dbPhone) : $phone_val;
                            $sent = function_exists('sendOtpSms') ? sendOtpSms($target, $otp) : sendOtpMail($dbEmail, $username, $otp);
                        }

                        if ($sent) {
                            $_SESSION['pending_2fa_user'] = $id;
                            $_SESSION['pending_2fa_role'] = $role_requested;
                            $_SESSION['pending_2fa_next'] = $next_after_login;
                            $_SESSION['pending_2fa_remember'] = $remember_checked ? 1 : 0;
                            $_SESSION['trusted_device_requested'] = $trusted_device ? 1 : 0;
                            header("Location: verify_otp.php");
                            exit();
                        } else {
                            $error = "OTP delivery failed. Please try again.";
                        }
                    }
                } else {
                    $error = "Account not found.";
                }
                $stmt->close();
            }
        }
    }
}
$conn->close();
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - PhishSafeguard</title>
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;600;700&family=Poppins:wght@400;500;600&display=swap" rel="stylesheet">

<style>
    /* =========================================
       LIGHT MODE - PROFESSIONAL BLUE (100% CLEAR BG)
       ========================================= */
    :root {
        --brand-primary: #2563eb; 
        --brand-primary-hover: #1d4ed8;
        --brand-primary-glow: rgba(37, 99, 235, 0.15);
        
        --text-heading: #0f172a; 
        --text-main: #334155; 
        --text-muted: #64748b; 
        
        --card-bg: rgba(255, 255, 255, 0.35); 
        --card-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
        --card-border: rgba(255, 255, 255, 0.6);
        
        --input-bg: rgba(255, 255, 255, 0.95);
        --input-border: rgba(255, 255, 255, 0.9);
        --input-border-focus: #2563eb;
        
        --widget-bg: rgba(255, 255, 255, 0.6);
        --widget-border: rgba(255, 255, 255, 0.8);
        --widget-shadow: 0 8px 24px rgba(0,0,0,0.08);
        
        --btn-bg: #2563eb; 
        --btn-text: #ffffff;
        --role-pill-bg: rgba(255, 255, 255, 0.6);
        
        --dropdown-bg: #ffffff; 
        
        --page-overlay: transparent; 
        
        --danger: #ef4444;
        --warning: #f59e0b;
        --success: #10b981;
    }

    /* =========================================
       DARK MODE - CINEMATIC BLUE (100% CLEAR BG)
       ========================================= */
    [data-theme="dark"] {
        --brand-primary: #60a5fa; 
        --brand-primary-hover: #3b82f6;
        --brand-primary-glow: rgba(96, 165, 250, 0.25);
        
        --text-heading: #f8fafc; 
        --text-main: #cbd5e1; 
        --text-muted: #94a3b8; 
        
        --card-bg: rgba(15, 23, 42, 0.85); 
        --card-shadow: 0 30px 60px rgba(0, 0, 0, 0.6);
        --card-border: rgba(255, 255, 255, 0.15);
        
        --input-bg: rgba(0, 0, 0, 0.4);
        --input-border: rgba(255, 255, 255, 0.1);
        --input-border-focus: #60a5fa;
        
        --widget-bg: rgba(255, 255, 255, 0.05);
        --widget-border: rgba(255, 255, 255, 0.1);
        --widget-shadow: 0 8px 24px rgba(0,0,0,0.3);
        
        --btn-bg: #60a5fa; 
        --btn-text: #0f172a;
        --role-pill-bg: rgba(0, 0, 0, 0.4);

        --dropdown-bg: #0f172a; 
        
        --page-overlay: transparent; 
    }

    /* =========================================
       HIGH CONTRAST MODE FIXED
       ========================================= */
    html.high-contrast body { filter: none !important; }
    html.high-contrast[data-theme="light"] {
        --card-bg: #ffffff; 
        --card-border: #000000; 
        --text-heading: #000000;
        --text-main: #000000;
        --text-muted: #333333;
        --input-border: #000000;
        --btn-bg: #000000;
        --btn-text: #ffffff;
        --dropdown-bg: #ffffff;
        --page-overlay: rgba(255,255,255, 0.95); 
    }
    html.high-contrast[data-theme="dark"] {
        --card-bg: #000000; 
        --card-border: #ffffff;
        --text-heading: #ffffff;
        --text-main: #ffffff;
        --text-muted: #cccccc;
        --input-border: #ffffff;
        --btn-bg: #ffffff;
        --btn-text: #000000;
        --dropdown-bg: #000000;
        --page-overlay: rgba(0,0,0, 0.95);
    }
    html.high-contrast .login-card, html.high-contrast .info-card {
        backdrop-filter: none !important; 
        border-width: 3px;
        box-shadow: none;
    }
    html.high-contrast p, html.high-contrast h2, html.high-contrast h3, html.high-contrast span { font-weight: 700 !important; }

    *, *::before, *::after { box-sizing: border-box; transition: background-color 0.4s ease, color 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease; }

    body {
        margin: 0; padding: 0; min-height: 100vh;
        font-family: 'Poppins', sans-serif;
        color: var(--text-main);
        display: flex; flex-direction: column; align-items: center;
        position: relative; overflow-y: auto; overflow-x: hidden;
        background-color: #0f172a; 
    }

    /* =========================================
       PREMIUM CINEMATIC ANIMATIONS
       ========================================= */
    @keyframes slowBreathingZoom { 0% { transform: scale(1); } 100% { transform: scale(1.08); } }
    @keyframes reveal3D { 
        0% { opacity: 0; transform: translateY(60px) scale(0.9) rotateX(-5deg); filter: blur(10px); } 
        100% { opacity: 1; transform: translateY(0) scale(1) rotateX(0deg); filter: blur(0); } 
    }
    @keyframes cascadeUp { 0% { opacity: 0; transform: translateY(20px); filter: blur(5px); } 100% { opacity: 1; transform: translateY(0); filter: blur(0); } }
    @keyframes floatY { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-8px); } }
    @keyframes slideDownHeader { 0% { opacity: 0; transform: translateY(-30px); } 100% { opacity: 1; transform: translateY(0); } }
    @keyframes pulse-brand { 0% { box-shadow: 0 0 0 0 var(--brand-primary-glow); } 70% { box-shadow: 0 0 0 15px rgba(0,0,0,0); } 100% { box-shadow: 0 0 0 0 rgba(0,0,0,0); } }
    @keyframes shakeError { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-10px); } 50% { transform: translateX(10px); } 75% { transform: translateX(-10px); } }

    /* Initial hidden states */
    .status-bar, .main-header, .login-card, .info-card, .anim-stagger { opacity: 0; }

    /* Animation Triggers */
    body.ui-ready .status-bar { animation: slideDownHeader 0.8s cubic-bezier(0.25, 1, 0.5, 1) forwards; }
    body.ui-ready .main-header { animation: slideDownHeader 0.8s cubic-bezier(0.25, 1, 0.5, 1) 0.15s forwards; }
    
    body.ui-ready .login-card { animation: reveal3D 1.2s cubic-bezier(0.16, 1, 0.3, 1) 0.1s forwards; perspective: 1000px; }
    body.ui-ready .info-card { animation: reveal3D 1.2s cubic-bezier(0.16, 1, 0.3, 1) 0.25s forwards; perspective: 1000px; }
    
    body.ui-ready .anim-stagger { animation: cascadeUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    body.ui-ready .delay-1 { animation-delay: 0.4s; }
    body.ui-ready .delay-2 { animation-delay: 0.5s; }
    body.ui-ready .delay-3 { animation-delay: 0.6s; }
    body.ui-ready .delay-4 { animation-delay: 0.7s; }
    body.ui-ready .delay-5 { animation-delay: 0.8s; }
    body.ui-ready .delay-6 { animation-delay: 0.9s; } /* New delay for register prompt */

    /* =========================================
       NEW CINEMATIC LOADER
       ========================================= */
    #pageLoader {
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: #020617;
        z-index: 9999; display: flex; flex-direction: column; justify-content: center; align-items: center;
        transition: opacity 0.8s cubic-bezier(0.76, 0, 0.24, 1), transform 0.8s cubic-bezier(0.76, 0, 0.24, 1);
    }
    #pageLoader::after {
        content:''; position: absolute; inset: 0; pointer-events: none;
        background: radial-gradient(circle at center, rgba(37,99,235,0.15) 0%, rgba(2,6,23,1) 80%);
    }
    .loader-content {
        position: relative; z-index: 2; display: flex; flex-direction: column; align-items: center;
        transition: all 0.6s cubic-bezier(0.76, 0, 0.24, 1);
    }
    .shield-wrapper {
        position: relative; width: 80px; height: 80px; display: flex; justify-content: center; align-items: center;
        animation: floatY 3s ease-in-out infinite;
    }
    .shield-wrapper .loader-icon { font-size: 4.5rem; color: var(--brand-primary); text-shadow: 0 0 25px var(--brand-primary-glow); }
    .scan-line {
        position: absolute; top: 0; left: -15%; right: -15%; height: 2px;
        background: #ffffff; box-shadow: 0 0 15px 2px #ffffff, 0 0 25px 5px var(--brand-primary);
        animation: scan 1.5s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate;
    }
    @keyframes scan { 0% { top: -5%; opacity: 0;} 10% { opacity: 1;} 90% { opacity: 1;} 100% { top: 105%; opacity: 0;} }
    
    .loader-text {
        margin-top: 35px; font-family: 'Montserrat', sans-serif; font-weight: 700; font-size: 1.1rem;
        color: #ffffff; letter-spacing: 3px; text-transform: uppercase;
    }
    .loader-progress-bg {
        width: 150px; height: 3px; background: rgba(255,255,255,0.1); border-radius: 3px; margin-top: 20px; overflow: hidden; position: relative;
    }
    .loader-progress-fill {
        height: 100%; width: 0%; background: var(--brand-primary); box-shadow: 0 0 10px var(--brand-primary);
        animation: loadFill 1s cubic-bezier(0.76, 0, 0.24, 1) forwards;
    }
    @keyframes loadFill { 0% { width: 0%; } 100% { width: 100%; } }
    
    #pageLoader.fade-out { opacity: 0; transform: scale(1.05); pointer-events: none; }
    .loader-content.slide-up { transform: translateY(-40px) scale(0.9); opacity: 0; }

    /* =========================================
       LAYOUT & COMPONENTS
       ========================================= */
    .bg-wrapper {
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        z-index: -3;
        background: url('BC.jpg') no-repeat center center fixed; 
        background-size: cover;
        animation: slowBreathingZoom 30s ease-in-out infinite alternate;
    }
    
    .overlay {
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        z-index: -1; 
        background: var(--page-overlay); 
        transition: all 0.5s ease;
    }
    
    body.focus-mode .overlay {
        background: rgba(0, 0, 0, 0.2);
        backdrop-filter: blur(8px); 
        -webkit-backdrop-filter: blur(8px);
    }

    .status-bar {
        width: 100%; background: var(--card-bg); color: var(--text-heading); border-bottom: 1px solid var(--card-border);
        text-align: center; padding: 8px; font-size: 0.8rem; font-weight: 500;
        z-index: 100; position: relative; display: flex; justify-content: center; gap: 10px; align-items: center;
        backdrop-filter: blur(15px);
    }
    .status-bar i { color: var(--brand-primary); }

    .main-header {
        width: 100%; padding: 25px 50px; display: flex;
        justify-content: space-between; align-items: center;
        z-index: 10; position: absolute; top: 40px; left: 0;
    }

    .brand-logo {
        font-family: 'Montserrat', sans-serif; font-weight: 700; font-size: 1.8rem; 
        color: var(--brand-primary); 
        display: flex; align-items: center; gap: 10px; cursor: default;
        letter-spacing: -0.5px; 
    }

    .header-tools { display: flex; gap: 15px; align-items: center; }
    .tool-btn {
        background: var(--widget-bg); 
        border: 1px solid var(--input-border);
        color: var(--text-heading); 
        width: 42px; height: 42px; border-radius: 50%;
        display: flex; justify-content: center; align-items: center; cursor: pointer;
        backdrop-filter: blur(15px); transition: all 0.3s cubic-bezier(0.25, 1, 0.5, 1); 
        box-shadow: var(--widget-shadow);
        font-size: 1.1rem;
    }
    .tool-btn:hover { transform: scale(1.15) rotate(5deg); color: var(--brand-primary); border-color: var(--brand-primary); }

    .theme-switch { position: relative; display: inline-block; width: 60px; height: 32px; }
    .theme-switch input { opacity: 0; width: 0; height: 0; }
    .slider { 
        position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; 
        background-color: var(--widget-bg); 
        transition: .4s; border-radius: 30px; border: 1px solid var(--input-border); 
        display: flex; align-items: center; justify-content: space-between; padding: 0 8px; 
        box-shadow: var(--widget-shadow); backdrop-filter: blur(10px);
    }
    .slider:before { position: absolute; content: ""; height: 24px; width: 24px; left: 4px; bottom: 3px; background-color: var(--brand-primary); transition: transform 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55); border-radius: 50%; box-shadow: 0 2px 5px rgba(0,0,0,0.2); z-index: 2;}
    input:checked + .slider { background-color: var(--widget-bg); }
    input:checked + .slider:before { transform: translateX(26px); }
    .sun-icon { color: #f59e0b; font-size: 14px; z-index: 1; transition: .4s; opacity: 1; }
    .moon-icon { color: #f1f5f9; font-size: 14px; z-index: 1; transition: .4s; opacity: 0.5; }
    [data-theme="dark"] .sun-icon { opacity: 0.5; }
    [data-theme="dark"] .moon-icon { opacity: 1; }

    .container {
        position: relative; z-index: 2; display: flex; flex-wrap: wrap;
        justify-content: center; gap: 35px; max-width: 1050px; width: 95%;
        margin-top: 140px; margin-bottom: 60px;
    }

    .login-card, .info-card {
        background: var(--card-bg); 
        border: 1px solid var(--card-border);
        border-radius: 28px; padding: 45px 40px; flex: 1;
        min-width: 350px; max-width: 480px; box-shadow: var(--card-shadow);
        backdrop-filter: blur(35px); 
        -webkit-backdrop-filter: blur(35px);
        position: relative;
        overflow: hidden;
    }
    
    .login-card::before, .info-card::before {
        content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 100%;
        background: linear-gradient(to right, rgba(255,255,255,0) 0%, rgba(255,255,255,0.2) 50%, rgba(255,255,255,0) 100%);
        transform: skewX(-25deg); animation: subtleShine 8s infinite; pointer-events: none;
    }

    .login-card.shake { animation: shakeError 0.5s ease-in-out; border-color: var(--danger); }
    .info-card { display: flex; flex-direction: column; }

    .progress-container { display: flex; justify-content: space-between; position: relative; margin-bottom: 30px; padding: 0 25px;}
    .progress-container::before { content:''; position: absolute; top: 12px; left: 40px; right: 40px; height: 2px; background: var(--input-border); z-index: 0; transition: 0.4s;}
    .step { text-align: center; position: relative; z-index: 1; font-size: 0.7rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; transition: 0.4s;}
    .step-circle { width: 26px; height: 26px; background: var(--widget-bg); border: 2px solid var(--input-border); border-radius: 50%; margin: 0 auto 5px; display: flex; align-items: center; justify-content: center; transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55); font-weight: 600;}
    .step.active .step-circle { border-color: var(--brand-primary); background: var(--brand-primary); color: var(--btn-text); transform: scale(1.1);}
    .step.active { color: var(--text-heading); }

    .welcome-msg { text-align: center; color: var(--brand-primary); font-weight: 600; font-size: 1rem; display: none; margin-bottom: -15px;}
    
    .login-header {
        font-size: 2rem; font-weight: 600; color: var(--text-heading);
        margin-top: 15px; margin-bottom: 30px; text-align: center; letter-spacing: -0.5px;
    }

    .google-btn {
        width: 100%; display: flex; align-items: center; justify-content: center; gap: 12px;
        padding: 14px; background: var(--widget-bg); border: 1px solid var(--input-border);
        border-radius: 12px; font-weight: 500; font-size: 0.95rem; color: var(--text-heading);
        cursor: pointer; margin-bottom: 25px; transition: all 0.3s ease; box-shadow: var(--widget-shadow);
    }
    .google-btn:hover { background: var(--input-bg); transform: translateY(-3px); box-shadow: 0 10px 20px rgba(0,0,0,0.08); }

    .divider { display: flex; align-items: center; margin: 25px 0; color: var(--text-muted); font-size: 0.85rem; font-weight: 500;}
    .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: var(--input-border); margin: 0 15px; }

    /* =========================================
       OVERLAP FIXED - STACKING CONTEXT & HIDING
       ========================================= */
    .input-group { position: relative; margin-bottom: 24px; width: 100%; transition: transform 0.3s ease; }
    .input-group:focus-within { transform: translateY(-2px); }
    
    .ig-id { z-index: 100 !important; } 
    /* The password group will literally hide when the dropdown opens */
    .ig-pw { z-index: 1 !important; transition: opacity 0.3s ease, visibility 0.3s ease; } 
    
    .label-text {
        font-size: 0.85rem; font-weight: 500; margin-bottom: 8px;
        display: flex; justify-content: space-between; align-items: center; color: var(--text-heading);
    }
    
    .help-tooltip { position: relative; cursor: help; color: var(--text-muted); margin-left: 6px; font-size: 0.9rem;}
    .help-tooltip::after {
        content: attr(data-tip); position: absolute; bottom: 130%; left: 50%; transform: translateX(-50%) translateY(10px);
        background: var(--text-heading); color: var(--card-bg); padding: 8px 14px; border-radius: 8px;
        font-size: 0.75rem; white-space: nowrap; opacity: 0; visibility: hidden; transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55); z-index: 20;
        box-shadow: 0 8px 20px rgba(0,0,0,0.2); font-weight: 500;
    }
    .help-tooltip:hover::after { opacity: 1; visibility: visible; transform: translateX(-50%) translateY(0); }

    .input-wrapper { position: relative; display: flex; align-items: center; width: 100%;}
    
    input[type="text"], input[type="password"] {
        width: 100%; padding: 15px 45px 15px 20px; 
        background: var(--input-bg); border: 2px solid var(--input-border);
        border-radius: 12px; font-family: 'Poppins', sans-serif;
        font-size: 0.95rem; color: var(--text-heading); transition: all 0.3s ease;
        font-weight: 500; box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);
    }
    input:focus { border-color: var(--input-border-focus); box-shadow: 0 0 0 4px var(--brand-primary-glow), inset 0 2px 4px rgba(0,0,0,0.02); outline: none; }
    
    /* Solid Dropdown */
    .autofill-panel {
        position: absolute; 
        top: calc(100% + 5px); 
        left: 0; 
        width: 100%; 
        background-color: var(--dropdown-bg) !important; 
        border: 1px solid var(--brand-primary); 
        border-radius: 12px; 
        box-shadow: 0 20px 45px rgba(0,0,0,0.3) !important; 
        z-index: 9999 !important; 
        display: none; 
        padding: 6px; 
        list-style: none; 
        max-height: 150px; 
        overflow-y: auto;
        backdrop-filter: none !important; 
    }

    .autofill-panel li { 
        padding: 12px; 
        font-size: 0.95rem; 
        cursor: pointer; 
        border-radius: 8px; 
        display: flex; 
        align-items: center; 
        gap: 10px; 
        font-weight: 600; 
        color: var(--text-heading);
        transition: all 0.2s ease;
    }

    .autofill-panel li:hover { 
        background: var(--brand-primary-glow); 
        color: var(--brand-primary); 
    }

    .validation-icon { position: absolute; right: 15px; top: 50%; transform: translateY(-50%) scale(0.5); font-size: 1.1rem; opacity: 0; transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55); }
    .validation-icon.valid { color: var(--success); opacity: 1; transform: translateY(-50%) scale(1);}
    .validation-icon.invalid { color: var(--danger); opacity: 1; transform: translateY(-50%) scale(1);}

    .pw-toggle {
        position: absolute; right: 15px; top: 50%; transform: translateY(-50%);
        background: none; border: none; cursor: pointer; color: var(--text-muted); font-size: 1.1rem; z-index: 10; transition: 0.3s;
    }
    .pw-toggle:hover { color: var(--brand-primary); transform: translateY(-50%) scale(1.1);}

    .caps-warning { font-size: 0.75rem; color: var(--warning); margin-top: 5px; display: none; align-items: center; gap: 5px; font-weight: 500;}
    .pw-strength-meter { height: 4px; width: 100%; background: var(--input-border); border-radius: 2px; margin-top: 8px; overflow: hidden; }
    .pw-strength-bar { height: 100%; width: 0%; border-radius: 2px; transition: width 0.4s ease, background-color 0.4s ease; }
    .strength-text { font-size: 0.75rem; float: right; margin-top: 4px; color: var(--text-muted); font-weight: 500; }

    .utilities { display: flex; flex-direction: column; gap: 12px; margin-bottom: 25px; margin-top: 15px; }
    .utils-row { display: flex; justify-content: space-between; align-items: center; }
    
    .checkbox-container { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: var(--text-main); cursor: pointer; user-select: none; font-weight: 500; transition: 0.2s;}
    .checkbox-container:hover { color: var(--brand-primary); }
    .checkbox-container input { display: none; }
    .checkmark { width: 18px; height: 18px; border: 2px solid var(--input-border); border-radius: 5px; display: flex; align-items: center; justify-content: center; background: var(--widget-bg); transition: 0.3s;}
    .checkbox-container input:checked + .checkmark { background: var(--brand-primary); border-color: var(--brand-primary); }
    .checkmark i { color: var(--btn-text); font-size: 10px; opacity: 0; transform: scale(0.5); transition: 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);}
    .checkbox-container input:checked + .checkmark i { opacity: 1; transform: scale(1);}

    .utilities a { color: var(--text-heading); text-decoration: none; font-weight: 500; font-size: 0.85rem; transition: 0.3s;}
    .utilities a:hover { text-decoration: underline; color: var(--brand-primary); }

    .role-seg {
        display: flex; background: var(--role-pill-bg); padding: 5px; border-radius: 12px;
        margin-bottom: 20px; position: relative; border: 1px solid var(--input-border);
    }
    .role-pill {
        position: absolute; top: 5px; bottom: 5px; left: 5px; width: calc(50% - 5px);
        background: var(--brand-primary); border-radius: 8px; box-shadow: 0 4px 12px var(--brand-primary-glow);
        transition: transform 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55); z-index: 1;
    }
    .role-option {
        flex: 1; text-align: center; padding: 12px; border-radius: 8px;
        cursor: pointer; font-weight: 500; font-size: 0.95rem;
        color: var(--text-muted); transition: color 0.4s ease; position: relative; z-index: 2; 
    }
    .role-option.active { color: var(--btn-text); font-weight: 600; }

    .btn-primary {
        width: 100%; padding: 16px; border: none; border-radius: 12px;
        background: var(--btn-bg); color: var(--btn-text); font-size: 1.05rem; font-weight: 600;
        cursor: pointer; display: flex; justify-content: center; align-items: center; gap: 10px;
        box-shadow: 0 8px 25px var(--brand-primary-glow); transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1);
    }
    .btn-primary:active { transform: scale(0.97); } 
    .btn-primary:hover { transform: translateY(-4px); box-shadow: 0 15px 35px rgba(37, 99, 235, 0.3); filter: brightness(1.1);}

    .spinner { display: none; width: 20px; height: 20px; border: 3px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: var(--btn-text); animation: spin 1s infinite linear; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .btn-primary.loading .spinner { display: block; }
    .btn-primary.loading .btn-text { display: none; }

    .error-message {
        background: rgba(239, 68, 68, 0.1); color: var(--danger); padding: 14px; border-radius: 10px;
        font-size: 0.9rem; text-align: center; margin-bottom: 25px; font-weight: 500; border: 1px solid rgba(239, 68, 68, 0.2);
        display: flex; align-items: center; justify-content: center; gap: 8px;
    }

    /* =========================================
       NEW REGISTER PROMPT ANIMATIONS
       ========================================= */
    /* =========================================
       NEW REGISTER PROMPT ANIMATIONS (FIXED VISIBILITY)
       ========================================= */
    .register-prompt {
        text-align: center; 
        margin-top: 25px; 
        font-size: 0.95rem; 
        color: var(--text-heading); /* এখানে কালার চেঞ্জ করা হয়েছে যাতে ক্লিয়ার বোঝা যায় */
        font-weight: 600; /* একটু বোল্ড করা হয়েছে */
    }
    .register-link {
        color: var(--brand-primary); text-decoration: none; font-weight: 700; margin-left: 5px;
        position: relative; display: inline-flex; align-items: center; gap: 6px; transition: all 0.3s ease;
        animation: registerPulse 2.5s infinite alternate;
    }
    @keyframes registerPulse {
        0% { text-shadow: 0 0 5px rgba(37, 99, 235, 0.1); }
        100% { text-shadow: 0 0 18px rgba(37, 99, 235, 0.8); }
    }
    .register-link::after {
        content: ''; position: absolute; width: 100%; height: 2px; bottom: -2px; left: 0;
        background: var(--brand-primary); transform: scaleX(0); transform-origin: right; transition: transform 0.4s cubic-bezier(0.86, 0, 0.07, 1);
    }
    .register-link:hover { color: var(--brand-primary-hover); animation: none; text-shadow: 0 0 12px var(--brand-primary-glow); }
    .register-link:hover::after { transform: scaleX(1); transform-origin: left; }
    .register-link i { transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
    .register-link:hover i { transform: translateX(5px) scale(1.15); }
    
    /* INFO CARD STYLES */
    .info-header { 
        color: var(--text-heading); font-size: 1.3rem; font-weight: 600; 
        margin-top: 0; margin-bottom: 30px; display: flex; align-items: center; gap: 10px; 
    }
    .info-header i { color: var(--brand-primary); font-size: 1.5rem; animation: floatY 4s ease-in-out infinite;}

    .tips-slider-container { min-height: 90px; position: relative; margin-bottom: 30px; }
    .premium-list { padding-left: 0; list-style: none; margin: 0; width: 100%; position: absolute; }
    .premium-list li { 
        display: flex; align-items: flex-start; gap: 12px;
        color: var(--text-main); font-size: 0.9rem; line-height: 1.6; font-weight: 400;
        opacity: 0; position: absolute; top:0; transform: translateY(10px); transition: all 0.6s cubic-bezier(0.16, 1, 0.3, 1); pointer-events: none;
    }
    .premium-list li.active { opacity: 1; transform: translateY(0); position: relative; pointer-events: auto;}
    .premium-list li i {
        color: var(--brand-primary); font-size: 1.15rem; margin-top: 2px;
        background: var(--widget-bg); border-radius: 50%; 
        box-shadow: 0 0 0 2px var(--input-border), 0 0 0 4px var(--brand-primary-glow); 
    }
    .premium-list strong { color: var(--text-heading); font-weight: 600; display: block; margin-bottom: 3px;}

    .premium-widgets { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 40px; }
    
    .p-widget {
        background: var(--widget-bg); border: 1px solid var(--widget-border); border-radius: 16px; 
        padding: 20px; display: flex; flex-direction: column; gap: 10px;
        border-left: 4px solid var(--brand-primary);
        box-shadow: var(--widget-shadow); transition: all 0.3s cubic-bezier(0.25, 1, 0.5, 1);
    }
    .p-widget:hover { transform: translateY(-5px); background: var(--input-bg); box-shadow: 0 12px 30px rgba(0,0,0,0.1); }
    
    .p-w-header { display: flex; justify-content: space-between; align-items: center; width: 100%; }
    .p-w-title { font-size: 0.65rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
    .p-w-icon { color: var(--brand-primary); font-size: 1rem; opacity: 0.9; animation: floatY 3s ease-in-out infinite alternate;}
    
    .p-w-value { font-size: 1.6rem; font-weight: 600; color: var(--text-heading); margin-top: -5px;}
    
    .p-w-bar-bg { width: 100%; height: 5px; background: var(--input-border); border-radius: 3px; overflow: hidden; margin-top: 2px; }
    .p-w-bar-fill { width: 92%; height: 100%; background: var(--brand-primary); border-radius: 3px; animation: loadBar 1.5s ease forwards; }

    .premium-support { margin-top: auto; padding-top: 25px; border-top: 1px solid var(--input-border); }
    .premium-support h4 { color: var(--text-heading); font-size: 1rem; font-weight: 600; margin-top: 0; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
    .premium-support p { color: var(--text-main); font-size: 0.85rem; line-height: 1.6; margin: 0; font-weight: 400;}
    .premium-support a { color: var(--brand-primary); font-weight: 500; text-decoration: none; transition: color 0.3s; }
    .premium-support a:hover { text-decoration: underline; color: var(--brand-primary-hover);}

    .location-badge {
        display: inline-flex; align-items: center; gap: 8px; background: var(--widget-bg); 
        color: var(--text-main); padding: 8px 18px; border-radius: 20px; font-size: 0.75rem; 
        font-weight: 500; border: 1px solid var(--widget-border); margin-bottom: 25px; align-self: center;
        box-shadow: var(--widget-shadow); transition: transform 0.3s ease;
    }
    .location-badge:hover { transform: translateY(-2px); }
    .location-badge i { color: var(--brand-primary); }

    @media (max-width: 850px) {
        .main-header { padding: 15px 20px; flex-direction: column; gap: 15px; top: 40px;}
        .header-tools { justify-content: center; }
        .container { flex-direction: column; align-items: center; margin-top: 150px; gap: 30px; }
        .login-card, .info-card { width: 100%; max-width: 100%; padding: 35px 25px; }
        .info-card { order: 2; }
    }
</style>
</head>
<body>

    <div id="pageLoader">
        <div class="loader-content">
            <div class="shield-wrapper">
                <i class="fa-solid fa-shield-halved loader-icon"></i>
                <div class="scan-line"></div>
            </div>
            <p class="loader-text">Connecting Securely</p>
            <div class="loader-progress-bg">
                <div class="loader-progress-fill"></div>
            </div>
        </div>
    </div>

    <div class="status-bar">
        <i class="fa-solid fa-lock"></i> 256-bit SSL Encrypted | Connection Risk: <span style="color:var(--brand-primary);">Low</span>
    </div>

    <div class="bg-wrapper"></div>
    <div class="overlay"></div>

    <header class="main-header">
        <div class="brand-logo">
            <i class="fa-solid fa-shield-halved"></i>
            <span>PhishSafeguard</span>
        </div>
        
        <div class="header-tools">
            <button class="tool-btn" id="a11yBtn" title="High Contrast Mode">
                <i class="fa-solid fa-universal-access"></i>
            </button>
            
            <button class="tool-btn" id="voiceAssistBtn" title="Voice Guidance">
                <i class="fa-solid fa-volume-high"></i>
            </button>

            <div class="theme-switch-wrapper">
                <label class="theme-switch" for="checkbox" title="Toggle Theme">
                    <input type="checkbox" id="checkbox" />
                    <div class="slider">
                        <i class="fa-solid fa-sun sun-icon"></i>
                        <i class="fa-solid fa-moon moon-icon"></i>
                    </div>
                </label>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="login-card <?= !empty($error) ? 'shake' : '' ?>">
            
            <div class="progress-container anim-stagger delay-1">
                <div class="step active">
                    <div class="step-circle"><i class="fa-solid fa-user"></i></div>
                    Credentials
                </div>
                <div class="step">
                    <div class="step-circle">2</div>
                    2FA Auth
                </div>
                <div class="step">
                    <div class="step-circle">3</div>
                    Secure
                </div>
            </div>

            <div id="welcomeMsg" class="welcome-msg"></div>

            <h2 class="login-header anim-stagger delay-1">Sign In</h2>

            <?php if ($error): ?>
                <div class="error-message anim-stagger">
                    <i class="fa-solid fa-triangle-exclamation"></i> <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form action="auth_google.php" method="POST" class="anim-stagger delay-2">
                <button type="submit" class="google-btn">
                    <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" alt="Google" width="20">
                    Continue with Google
                </button>
            </form>

            <div class="divider anim-stagger delay-2">Or use email</div>

            <form method="POST" id="loginForm">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                
                <div class="input-group ig-id anim-stagger delay-3">
                    <label class="label-text">
                        <span>Email or Phone 
                            <i class="fa-solid fa-circle-info help-tooltip" data-tip="Enter your registered email ID or 10-digit phone."></i>
                        </span>
                        <span id="identifierType" style="color: var(--brand-primary); font-size: 0.75rem;"></span>
                    </label>
                    <div class="input-wrapper">
                        <input type="text" name="identifier" id="identifierField" placeholder="e.g. user@example.com" required autocomplete="off">
                        <i class="fa-solid fa-check validation-icon" id="idValidationIcon"></i>
                        <ul class="autofill-panel" id="autofillPanel"></ul>
                    </div>
                </div>

                <div class="input-group ig-pw anim-stagger delay-3">
                    <label class="label-text">
                        <span>Password
                            <i class="fa-solid fa-circle-info help-tooltip" data-tip="Password must contain at least 8 characters."></i>
                        </span>
                    </label>
                    <div class="input-wrapper">
                        <input type="password" name="password" id="passwordField" placeholder="Enter password" required autocomplete="current-password">
                        <button type="button" class="pw-toggle" id="togglePw" title="Show/Hide Password">
                            <i class="fa-regular fa-eye" id="toggleIcon"></i>
                        </button>
                    </div>
                    <div class="caps-warning" id="capsWarning">
                        <i class="fa-solid fa-arrow-up-from-bracket"></i> Caps Lock is ON
                    </div>
                    <div class="pw-strength-meter">
                        <div class="pw-strength-bar" id="pwBar"></div>
                    </div>
                    <span class="strength-text" id="pwText"></span>
                </div>

                <div class="utilities anim-stagger delay-4">
                    <div class="utils-row">
                        <label class="checkbox-container">
                            <input type="checkbox" name="remember" id="rememberMe" value="1">
                            <div class="checkmark"><i class="fa-solid fa-check"></i></div>
                            Remember me
                        </label>
                        <a href="forget_password.php">Forgot Password?</a>
                    </div>
                    <div class="utils-row" style="margin-top: 8px;">
                        <label class="checkbox-container" title="Skip OTP for 30 days">
                            <input type="checkbox" name="trusted_device" id="trustedDevice" value="1">
                            <div class="checkmark"><i class="fa-solid fa-shield-heart"></i></div>
                            Trust this device (30 days)
                        </label>
                    </div>
                </div>

                <div class="input-group anim-stagger delay-4">
                    <div class="role-seg">
                        <div class="role-pill" id="rolePill"></div>
                        <div class="role-option active" data-role="user" id="roleUser">User</div>
                        <div class="role-option" data-role="admin" id="roleAdmin">Admin</div>
                    </div>
                    <input type="hidden" name="role" id="roleInput" value="user">
                </div>

                <div class="input-group g-recaptcha anim-stagger delay-5" data-sitekey="<?= htmlspecialchars($RECAPTCHA_SITEKEY) ?>" style="display:flex; justify-content:center; transform:scale(0.95); transform-origin:center; margin-bottom:25px;"></div>

                <div class="anim-stagger delay-5">
                    <button type="submit" name="login" id="submitBtn" class="btn-primary" <?= $_SESSION['lockout_time'] > time() ? 'disabled style="opacity:0.6; cursor:not-allowed;"' : '' ?>>
                        <span class="spinner"></span>
                        <span class="btn-text">Sign In <i class="fa-solid fa-arrow-right-to-bracket" style="margin-left: 8px;"></i></span>
                    </button>
                </div>
                
                <div class="register-prompt anim-stagger delay-6">
                    New to PhishSafeguard? 
                    <a href="register.php" class="register-link">
                        Create Account <i class="fa-solid fa-user-plus"></i>
                    </a>
                </div>
            </form>
        </div>

        <div class="info-card">

            <div class="location-badge anim-stagger delay-1" id="locationBadge">
                <i class="fa-solid fa-location-dot"></i> Verifying network...
            </div>

            <h3 class="info-header"><i class="fa-solid fa-shield-halved"></i> Security Quick Tips</h3>
            
            <div class="tips-slider-container">
                <ul class="premium-list" id="tipsSlider">
                    <li class="active">
                        <i class="fa-solid fa-circle-check"></i>
                        <div><strong>Inspect URLs Carefully:</strong> Hover over links to see the actual destination.</div>
                    </li>
                    <li>
                        <i class="fa-solid fa-circle-check"></i>
                        <div><strong>Enable 2FA:</strong> Add an essential layer of security to your account.</div>
                    </li>
                    <li>
                        <i class="fa-solid fa-circle-check"></i>
                        <div><strong>Be Wary of Urgency:</strong> Phishing attacks often create false urgency.</div>
                    </li>
                    <li>
                        <i class="fa-solid fa-circle-check"></i>
                        <div><strong>Update Devices:</strong> Keep your browser and system software up to date.</div>
                    </li>
                </ul>
            </div>

            <div class="premium-widgets">
                <div class="p-widget">
                    <div class="p-w-header">
                        <span class="p-w-title">Phishing Blocked</span>
                        <i class="fa-solid fa-bug-slash p-w-icon"></i>
                    </div>
                    <div class="p-w-value">
                        <span id="threatCount">1,207</span>
                        <i class="fa-solid fa-circle" style="font-size: 0.5rem; color: var(--brand-primary); margin-left: auto; animation: pulse-brand 2s infinite; border-radius:50%;"></i>
                    </div>
                </div>
                
                <div class="p-widget">
                    <div class="p-w-header">
                        <span class="p-w-title">Account Security</span>
                        <i class="fa-solid fa-fingerprint p-w-icon"></i>
                    </div>
                    <div class="p-w-value">92%</div>
                    <div class="p-w-bar-bg"><div class="p-w-bar-fill"></div></div>
                </div>
            </div>

            <div class="premium-support">
                <h4><i class="fa-solid fa-headset"></i> Need Help?</h4>
                <p>Our support team is available 24/7.<br>
                Email: <a href="mailto:hazrarupam222@gmail.com">hazrarupam222@gmail.com</a></p>
            </div>
            
        </div>
    </div>

<script>
    // Cinematic Loader JavaScript Logic
    window.addEventListener('load', function() {
        setTimeout(() => {
            const loader = document.getElementById('pageLoader');
            const loaderContent = document.querySelector('.loader-content');
            
            if(loader) {
                // Step 1: Content flies up and disappears
                loaderContent.classList.add('slide-up');
                
                setTimeout(() => { 
                    // Step 2: Background zooms out and fades
                    loader.classList.add('fade-out'); 
                    
                    setTimeout(() => {
                        loader.style.display = 'none'; 
                        // Step 3: Trigger the 3D cinematic cascade for the cards
                        document.body.classList.add('ui-ready'); 
                    }, 800);
                    
                }, 400); 
            } else {
                document.body.classList.add('ui-ready');
            }
        }, 1500); // Loader stays for 1.5s to show the cool animation
    });

    document.addEventListener("DOMContentLoaded", function() {

        // Theme Toggle Implementation
        const themeCheckbox = document.getElementById('checkbox');
        const htmlEl = document.documentElement;
        
        const savedTheme = localStorage.getItem('ps_theme') || 'light';
        htmlEl.setAttribute('data-theme', savedTheme);
        themeCheckbox.checked = (savedTheme === 'dark');

        themeCheckbox.addEventListener('change', (e) => {
            const newTheme = e.target.checked ? 'dark' : 'light';
            htmlEl.setAttribute('data-theme', newTheme);
            localStorage.setItem('ps_theme', newTheme);
        });
        
        // High Contrast Mode Fix
        const a11yBtn = document.getElementById('a11yBtn');
        let isA11y = localStorage.getItem('ps_a11y') === 'true';
        if(isA11y) htmlEl.classList.add('high-contrast');
        
        a11yBtn.addEventListener('click', () => {
            isA11y = !isA11y;
            htmlEl.classList.toggle('high-contrast');
            localStorage.setItem('ps_a11y', isA11y);
        });

        // Voice Assist
        const voiceBtn = document.getElementById('voiceAssistBtn');
        voiceBtn.addEventListener('click', () => {
            if('speechSynthesis' in window) {
                const text = "Welcome to Phish Safeguard. Enter your registered email or phone number, and password to sign in securely.";
                const utterance = new SpeechSynthesisUtterance(text);
                window.speechSynthesis.speak(utterance);
            } else {
                alert("Voice assist not supported.");
            }
        });

        // ==========================================
        // SMART AUTOFILL - INSTANT GAYEB LOGIC
        // ==========================================
        const idField = document.getElementById('identifierField');
        const autofillPanel = document.getElementById('autofillPanel');
        const welcomeMsg = document.getElementById('welcomeMsg');
        const pwGroup = document.querySelector('.ig-pw'); 
        const savedUser = localStorage.getItem('ps_recent_user');

        if(savedUser) {
            welcomeMsg.innerText = `Welcome back, ${savedUser.split('@')[0]}!`;
            welcomeMsg.style.display = 'block';
        }

        idField.addEventListener('focus', () => {
            if(savedUser && idField.value === '') {
                autofillPanel.innerHTML = `<li><i class="fa-solid fa-clock-rotate-left" style="color:var(--brand-primary);"></i> ${savedUser}</li>`;
                autofillPanel.style.display = 'block';
                
                // Instant Gayeb - zero delay
                pwGroup.style.display = 'none'; 
            }
        });

        idField.addEventListener('input', () => {
            // User type korle dropdown chole jabe r password field instant fire asbe
            if(autofillPanel.style.display === 'block') {
                autofillPanel.style.display = 'none';
                pwGroup.style.display = 'block';
            }
        });

        idField.addEventListener('blur', () => { 
            // Halka delay dorkar dropdown click register korar jonno, kintu password field instant firbe
            setTimeout(() => { 
                autofillPanel.style.display = 'none'; 
                pwGroup.style.display = 'block';
            }, 150); 
        });

        autofillPanel.addEventListener('mousedown', (e) => {
            // 'mousedown' use kora holo jate select korar sathe sathe fill hoye jay
            const li = e.target.closest('li');
            if(li) {
                idField.value = savedUser;
                autofillPanel.style.display = 'none';
                pwGroup.style.display = 'block';
                idField.dispatchEvent(new Event('input')); 
            }
        });

        // Focus Mode Blur
        const inputs = document.querySelectorAll('input[type="text"], input[type="password"]');
        inputs.forEach(input => {
            input.addEventListener('focus', () => document.body.classList.add('focus-mode'));
            input.addEventListener('blur', () => document.body.classList.remove('focus-mode'));
        });

        // Auto-changing Tips Slider
        const tips = document.querySelectorAll('#tipsSlider li');
        let currentTip = 0;
        setInterval(() => {
            tips[currentTip].classList.remove('active');
            currentTip = (currentTip + 1) % tips.length;
            tips[currentTip].classList.add('active');
        }, 4000);

        // Smart Location Fallback
        // Smart & Accurate Location Tracking (Browser Geolocation + OpenStreetMap)
// ==========================================
        // Smart Location Fallback (Updated with Email & Fallback API)
        // ==========================================
        const locationBadge = document.getElementById('locationBadge');

        if ("geolocation" in navigator) {
            navigator.geolocation.getCurrentPosition(function(position) {
                const lat = position.coords.latitude;
                const lon = position.coords.longitude;

                // 1st Try: Nominatim API with Email Parameter
                fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&email=hazrarupam222@gmail.com`)
                    .then(response => {
                        if (!response.ok) throw new Error("Nominatim Blocked");
                        return response.json();
                    })
                    .then(data => {
                        const city = data.address.city || data.address.town || data.address.village || data.address.county;
                        const state = data.address.state;
                        
                        if(city && state) {
                            locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Connected: ${city}, ${state}`;
                        } else {
                            locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Connected Securely`;
                        }
                    }).catch(err => {
                        // 2nd Try: Fallback to BigDataCloud API if Nominatim fails on localhost
                        fetch(`https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=en`)
                            .then(res => res.json())
                            .then(fallbackData => {
                                const fallCity = fallbackData.city || fallbackData.locality;
                                const fallState = fallbackData.principalSubdivision;
                                
                                if(fallCity && fallState) {
                                    locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Connected: ${fallCity}, ${fallState}`;
                                } else {
                                    locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Location API Error`;
                                }
                            }).catch(() => {
                                locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Location API Error`;
                            });
                    });
            }, function(error) {
                locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Location Access Denied`;
            });
        } else {
            locationBadge.innerHTML = `<i class="fa-solid fa-location-dot"></i> Geolocation Not Supported`;
        }
        // Password Toggle
        const pwField = document.getElementById('passwordField');
        const toggleBtn = document.getElementById('togglePw');
        const toggleIcon = document.getElementById('toggleIcon');
        
        toggleBtn.addEventListener('click', function(e){
            e.preventDefault();
            const show = pwField.type === 'password';
            pwField.type = show ? 'text' : 'password';
            toggleIcon.className = show ? 'fa-regular fa-eye-slash' : 'fa-regular fa-eye';
        });

        // Caps Lock Warning
        const capsWarning = document.getElementById('capsWarning');
        pwField.addEventListener('keyup', function(e) {
            if (e.getModifierState && e.getModifierState('CapsLock')) {
                capsWarning.style.display = 'flex';
            } else {
                capsWarning.style.display = 'none';
            }
        });

        // Password Strength
        const pwBar = document.getElementById('pwBar');
        const pwText = document.getElementById('pwText');
        
        pwField.addEventListener('input', function() {
            const val = this.value;
            let strength = 0;
            if(val.length > 0) {
                if(val.length >= 8) strength++;
                if(/[A-Z]/.test(val)) strength++;
                if(/[0-9]/.test(val)) strength++;
                if(/[^A-Za-z0-9]/.test(val)) strength++;
            }
            
            switch(strength) {
                case 0: pwBar.style.width = '0%'; pwText.innerText = ''; break;
                case 1: pwBar.style.width = '25%'; pwBar.style.backgroundColor = 'var(--danger)'; pwText.innerText = 'Weak'; break;
                case 2: pwBar.style.width = '50%'; pwBar.style.backgroundColor = 'var(--warning)'; pwText.innerText = 'Fair'; break;
                case 3: pwBar.style.width = '75%'; pwBar.style.backgroundColor = '#a3e635'; pwText.innerText = 'Good'; break;
                case 4: pwBar.style.width = '100%'; pwBar.style.backgroundColor = 'var(--success)'; pwText.innerText = 'Strong'; break;
            }
        });

        // Inline Format Validation
        const idIcon = document.getElementById('idValidationIcon');
        const idTypeTxt = document.getElementById('identifierType');

        idField.addEventListener('input', function() {
            const val = this.value.trim();
            const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
            const isPhone = /^\d{7,15}$/.test(val.replace(/\D/g,'')); 

            if (val === '') {
                idIcon.className = 'fa-solid fa-check validation-icon';
                idTypeTxt.innerText = '';
            } else if (isEmail) {
                idIcon.className = 'fa-solid fa-envelope validation-icon valid';
                idTypeTxt.innerText = '(Email)';
            } else if (isPhone) {
                idIcon.className = 'fa-solid fa-phone validation-icon valid';
                idTypeTxt.innerText = '(Phone)';
            } else {
                idIcon.className = 'fa-solid fa-circle-xmark validation-icon invalid';
                idTypeTxt.innerText = '';
            }
        });

        // Animated Role Pill
        const rUser = document.getElementById('roleUser');
        const rAdmin = document.getElementById('roleAdmin');
        const rInput = document.getElementById('roleInput');
        const pill = document.getElementById('rolePill');
        
        function setRole(role){
            rUser.classList.remove('active');
            rAdmin.classList.remove('active');
            if(role === 'user') {
                rUser.classList.add('active');
                pill.style.transform = 'translateX(0)';
            } else {
                rAdmin.classList.add('active');
                pill.style.transform = 'translateX(100%)';
            }
            rInput.value = role;
        }
        rUser.onclick = () => setRole('user');
        rAdmin.onclick = () => setRole('admin');

        // Form Submit Spinner & Save Local User
        const loginForm = document.getElementById('loginForm');
        const submitBtn = document.getElementById('submitBtn');
        
        loginForm.addEventListener('submit', function(e) {
            submitBtn.classList.add('loading');
            if(document.getElementById('rememberMe').checked){
                localStorage.setItem('ps_recent_user', idField.value); 
                sessionStorage.setItem('ps_temp_un', idField.value);
            }
        });

        // Live Animated Counter for Widgets
        let threatNum = 1244;
        const threatEl = document.getElementById('threatCount');
        setInterval(() => {
            if(Math.random() > 0.6) { 
                threatNum += Math.floor(Math.random() * 3) + 1;
                threatEl.innerText = threatNum.toLocaleString();
            }
        }, 3500);

    });
</script>
</body>
</html>