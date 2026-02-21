<?php
// forget_password.php (final, improved premium UI with heavy animations & scrolling)
if (session_status() === PHP_SESSION_NONE) session_start();
if (!defined('ALLOW_PUBLIC')) define('ALLOW_PUBLIC', true);
require_once __DIR__ . '/helpers_db.php';   // must provide db()
require_once __DIR__ . '/mail_helper.php';  // optional: sendOtpMail/sendOtpSms

// DEV: disable display_errors in production
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
date_default_timezone_set('Asia/Kolkata');

$errors = [];
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && isset($_SESSION['pw_notice'])) {
    unset($_SESSION['pw_notice']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $identifier = trim($_POST['identifier'] ?? '');
    if ($identifier === '') {
        $errors[] = "Please enter your email or phone.";
    } else {
        $conn = db();
        $is_email = false;
        $stmt = null;

        if (filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            $is_email = true;
            $stmt = $conn->prepare("SELECT id, username, email, phone FROM users WHERE email = ? LIMIT 1");
            if ($stmt) $stmt->bind_param('s', $identifier);
        } else {
            $phone_norm = preg_replace('/\D+/', '', $identifier);
            $stmt = $conn->prepare("SELECT id, username, email, phone FROM users WHERE REPLACE(REPLACE(REPLACE(phone,' ',''),'-',''),'+','') = ? LIMIT 1");
            if ($stmt) $stmt->bind_param('s', $phone_norm);
        }

        if (!$stmt) {
            $errors[] = "Database error: " . $conn->error;
        } else {
            $stmt->execute();
            $res = $stmt->get_result();
            if (!$res || $res->num_rows === 0) {
                $errors[] = "No user found with that email or phone.";
            } else {
                $user = $res->fetch_assoc();
                $user_id = (int)$user['id'];
                $username = $user['username'] ?? '';
                $dbEmail = $user['email'] ?? '';
                $dbPhone = $user['phone'] ?? '';

                try { $otp = strval(random_int(100000, 999999)); }
                catch (Exception $e) { $otp = strval(mt_rand(100000, 999999)); }

                $expiry_dt = (new DateTimeImmutable('now', new DateTimeZone('Asia/Kolkata')))
                                ->add(new DateInterval('PT30M'));
                $expiry_str = $expiry_dt->format('Y-m-d H:i:s');
                $otp_hash = password_hash($otp, PASSWORD_DEFAULT);

                $chan = $is_email ? 'email' : 'sms';
                $sent_to = $is_email ? $dbEmail : ($dbPhone ? $dbPhone : $identifier);

                $ins = $conn->prepare("INSERT INTO password_resets (user_id, otp_hash, channel, sent_to, expires_at) VALUES (?,?,?,?,?)");
                if (!$ins) {
                    $errors[] = "Internal error (prepare insert).";
                } else {
                    $ins->bind_param('issss', $user_id, $otp_hash, $chan, $sent_to, $expiry_str);
                    if (!$ins->execute()) {
                        $errors[] = "Internal error (execute insert).";
                    } else {
                        $reset_id = $conn->insert_id;
                        $_SESSION['password_reset_id'] = $reset_id;
                        $_SESSION['password_reset_user'] = $user_id;
                    }
                    $ins->close();
                }

                $sent = false;
                if ($is_email || !empty($dbEmail)) {
                    $to = $dbEmail ?: $identifier;
                    if (function_exists('sendOtpMail')) {
                        $sent = sendOtpMail($to, $username, $otp);
                    } else {
                        $subject = "Your OTP for password reset";
                        $body = "Hello " . ($username ?: '') . ",\n\nYour OTP is: $otp\nIt is valid for 30 minutes.\n\nIf you didn't request this, ignore this message.";
                        $sent = @mail($to, $subject, $body, "From: no-reply@yourdomain.com\r\n");
                    }
                } else {
                    $toPhone = preg_replace('/\D+/', '', $dbPhone ?: $identifier);
                    if (!empty($toPhone) && function_exists('sendOtpSms')) {
                        $sent = sendOtpSms($toPhone, $otp);
                    } elseif (!empty($dbEmail)) {
                        if (function_exists('sendOtpMail')) {
                            $sent = sendOtpMail($dbEmail, $username, $otp);
                        } else {
                            $subject = "Your OTP for password reset";
                            $body = "Your OTP is: $otp (valid 30 minutes)";
                            $sent = @mail($dbEmail, $subject, $body, "From: no-reply@yourdomain.com\r\n");
                        }
                    } else {
                        $sent = false;
                    }
                }

                if ($sent) {
                    $_SESSION['pw_notice'] = "OTP has been sent to " . htmlspecialchars($sent_to);
                    header('Location: verify_password_reset.php');
                    exit;
                } else {
                    $errors[] = "Failed to send OTP. Check mail/SMS configuration.";
                }
            }
            $stmt->close();
        }
        $conn->close();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Password Recovery — PhishSafeguard</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    /* Modern Premium Font */
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
    
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        font-family: 'Poppins', sans-serif;
    }

    /* SCROLL ENABLED: overflow-y is set to auto, removed overflow: hidden */
    body {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background-image: linear-gradient(to right, rgba(9, 14, 23, 0.85), rgba(9, 14, 23, 0.7)), 
                        url('https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=2564&auto=format&fit=crop');
      background-size: cover;
      background-position: center;
      background-attachment: fixed;
      color: #e6edf3;
      padding: 100px 15px; /* Added more top/bottom padding for comfortable scrolling */
      overflow-x: hidden;
      overflow-y: auto; /* ENABLE SCROLLING */
      position: relative;
    }

    /* ========================================= */
    /* KEYFRAME ANIMATIONS */
    /* ========================================= */
    
    @keyframes fadeInDownBrand {
        0% { opacity: 0; transform: translateY(-30px); }
        100% { opacity: 1; transform: translateY(0); }
    }

    @keyframes floatBrand {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-8px); }
        100% { transform: translateY(0px); }
    }

    @keyframes rotateIcon {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    @keyframes floatShape1 {
        0% { transform: translateY(0) translateX(0) scale(1) rotate(0deg); }
        50% { transform: translateY(60px) translateX(80px) scale(1.1) rotate(45deg); }
        100% { transform: translateY(-30px) translateX(-50px) scale(0.9) rotate(90deg); }
    }
    
    @keyframes floatShape2 {
        0% { transform: translateY(0) translateX(0) scale(1); }
        50% { transform: translateY(-70px) translateX(-60px) scale(1.2); }
        100% { transform: translateY(40px) translateX(40px) scale(0.8); }
    }

    @keyframes cardEntrance {
      0% { opacity: 0; transform: translateY(60px) scale(0.9) perspective(1000px) rotateX(10deg); }
      100% { opacity: 1; transform: translateY(0) scale(1) perspective(1000px) rotateX(0deg); }
    }

    @keyframes popInElement {
        0% { opacity: 0; transform: translateY(20px); }
        100% { opacity: 1; transform: translateY(0); }
    }

    @keyframes pulseGlowButton {
        0% { box-shadow: 0 0 0 0 rgba(31, 111, 235, 0.7); }
        70% { box-shadow: 0 0 0 15px rgba(31, 111, 235, 0); }
        100% { box-shadow: 0 0 0 0 rgba(31, 111, 235, 0); }
    }
    
    @keyframes iconWobble {
        0%, 100% { transform: rotate(0deg); }
        25% { transform: rotate(-15deg); }
        75% { transform: rotate(15deg); }
    }

    /* ========================================= */
    /* STYLING & ANIMATION APPLICATION */
    /* ========================================= */

    /* Top Left Branding Logo */
    .top-left-brand {
        position: absolute;
        top: 30px;
        left: 40px;
        display: flex;
        align-items: center;
        gap: 12px;
        z-index: 10;
        animation: fadeInDownBrand 1s ease forwards, floatBrand 4s ease-in-out infinite 1s;
    }

    .top-left-brand i {
        font-size: 28px;
        color: #58a6ff;
        filter: drop-shadow(0 0 8px rgba(88, 166, 255, 0.5));
        transition: transform 0.4s ease;
    }
    
    .top-left-brand:hover i {
        animation: rotateIcon 1s ease-in-out;
    }

    .top-left-brand span {
        font-size: 22px;
        font-weight: 600;
        color: #ffffff;
        letter-spacing: 0.5px;
    }

    /* Floating Background Shapes */
    .background-shapes {
        position: fixed; 
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 0;
        pointer-events: none; /* Let clicks pass through */
    }
    .shape {
        position: absolute;
        border-radius: 50%;
        opacity: 0.3;
        filter: blur(100px);
    }
    .shape1 {
        width: 450px;
        height: 450px;
        background: #1f6feb;
        top: -10%;
        left: -10%;
        animation: floatShape1 20s infinite alternate ease-in-out;
    }
    .shape2 {
        width: 400px;
        height: 400px;
        background: #8957e5;
        bottom: -10%;
        right: -5%;
        animation: floatShape2 25s infinite alternate-reverse ease-in-out;
    }

    /* Premium Glassmorphism Card */
    .card {
      background: rgba(13, 17, 23, 0.4); 
      backdrop-filter: blur(25px);
      -webkit-backdrop-filter: blur(25px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-top: 1px solid rgba(255, 255, 255, 0.2);
      border-left: 1px solid rgba(255, 255, 255, 0.2);
      padding: 45px 40px;
      border-radius: 24px;
      box-shadow: 0 30px 60px rgba(0,0,0,0.6);
      width: 460px;
      max-width: 100%;
      text-align: center;
      animation: cardEntrance 1s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
      z-index: 1;
      position: relative;
    }

    /* Staggered Elements Inside Card */
    .card-element {
        opacity: 0;
        animation: popInElement 0.6s cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
    }
    .delay-1 { animation-delay: 0.3s; }
    .delay-2 { animation-delay: 0.5s; }
    .delay-3 { animation-delay: 0.7s; }
    .delay-4 { animation-delay: 0.9s; }
    .delay-5 { animation-delay: 1.1s; }
    
    .card .icon-wrapper {
        width: 65px;
        height: 65px;
        background: rgba(88, 166, 255, 0.1);
        border: 1px solid rgba(88, 166, 255, 0.3);
        border-radius: 50%;
        display: flex;
        justify-content: center;
        align-items: center;
        margin: 0 auto 20px;
        color: #58a6ff;
        font-size: 26px;
        box-shadow: 0 0 20px rgba(88, 166, 255, 0.2);
        transition: all 0.4s ease;
    }
    
    .card:hover .icon-wrapper {
        transform: scale(1.1);
        box-shadow: 0 0 30px rgba(88, 166, 255, 0.4);
        background: rgba(88, 166, 255, 0.2);
    }
    .card:hover .icon-wrapper i {
        animation: iconWobble 0.6s ease-in-out;
    }

    .card h2 {
        font-size: 28px;
        color: #ffffff;
        font-weight: 600;
        margin-bottom: 12px;
    }
    
    .helptext {
        color: #8b949e;
        font-size: 14.5px;
        margin-bottom: 35px;
        line-height: 1.6;
    }

    /* Modern Floating Label Inputs */
    .input-group {
        position: relative;
        margin-bottom: 25px;
        text-align: left;
    }
    .input-field {
        width: 100%;
        padding: 16px 18px;
        border: 1px solid rgba(255, 255, 255, 0.15);
        background: rgba(0, 0, 0, 0.2);
        border-radius: 12px;
        outline: none;
        transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1); /* Bouncier transition */
        font-size: 15px;
        color: #ffffff;
    }
    .input-label {
        position: absolute;
        top: 16px;
        left: 18px;
        color: #8b949e;
        pointer-events: none;
        transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        padding: 0 6px;
        font-size: 15px;
    }
    
    .input-field:focus + .input-label,
    .input-field:not(:placeholder-shown) + .input-label {
        top: -10px;
        left: 12px;
        font-size: 13px;
        color: #58a6ff;
        background: #0d1117;
        border-radius: 4px;
        font-weight: bold;
    }
    
    .input-field:focus {
        border-color: #58a6ff;
        background: rgba(0, 0, 0, 0.4);
        box-shadow: 0 0 15px rgba(88, 166, 255, 0.3);
        transform: translateY(-2px);
    }

    /* Premium Button with Heavy Animations */
    .btn-primary {
        display: inline-flex;
        align-items: center;
        gap: 12px;
        justify-content: center;
        width: 100%; 
        padding: 16px; 
        border: none; 
        border-radius: 12px;
        background: linear-gradient(135deg, #1f6feb, #3182ce);
        color: #ffffff; 
        font-size: 16px; 
        font-weight: 600; 
        cursor: pointer;
        transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
        margin-top: 5px;
        letter-spacing: 0.5px;
        position: relative;
        overflow: hidden;
        animation: pulseGlowButton 2s infinite;
    }
    
    /* Shimmer Effect on Button */
    .btn-primary::after {
        content: '';
        position: absolute;
        top: 0; left: -100%;
        width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
        transform: skewX(-25deg);
        transition: all 0.6s ease;
    }

    .btn-primary:hover::after {
        left: 120%;
        transition: all 0.6s ease;
    }

    .btn-primary:hover {
        transform: translateY(-4px) scale(1.02);
        box-shadow: 0 15px 30px rgba(31, 111, 235, 0.5);
        background: linear-gradient(135deg, #2e7df5, #3a93e5);
    }
    
    .btn-primary:active {
        transform: translateY(0) scale(0.98);
    }

    .btn-primary:disabled {
        opacity: 0.7; 
        cursor: not-allowed;
        animation: none;
    }

    /* Alerts */
    .msg {
        margin: 0 0 20px;
        padding: 14px;
        border-radius: 10px;
        font-size: 14px;
        line-height: 1.5;
        text-align: left;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .msg.error {
        background: rgba(248, 81, 73, 0.15);
        color: #ff7b72;
        border: 1px solid rgba(248, 81, 73, 0.4);
    }
    .msg.success {
        background: rgba(63, 185, 80, 0.15);
        color: #56d364;
        border: 1px solid rgba(63, 185, 80, 0.4);
    }

    /* Return Link */
    .small {
        font-size: 14px;
        color: #8b949e;
        text-align: center;
        margin-top: 30px;
    }
    .small a {
        color: #58a6ff;
        text-decoration: none;
        font-weight: 500;
        transition: all 0.3s ease;
        display: inline-block;
    }
    .small a:hover {
        color: #79c0ff;
        transform: translateX(-5px); /* Slide left animation on hover */
    }
    
    /* Responsive Adjustments */
    @media (max-width: 600px) {
        .top-left-brand {
            top: 20px;
            left: 20px;
            position: relative; /* Allows better scrolling on mobile */
            margin-bottom: 20px;
        }
        .top-left-brand span { font-size: 18px; }
        body { padding: 40px 15px; flex-direction: column; }
        .card { padding: 35px 25px; }
    }
  </style>
</head>
<body>

  <div class="top-left-brand">
      <i class="fa-solid fa-shield-halved"></i>
      <span>PhishSafeguard</span>
  </div>

  <div class="background-shapes">
      <div class="shape shape1"></div>
      <div class="shape shape2"></div>
  </div>

  <div class="card" role="region" aria-labelledby="reset-title">
    
    <div class="icon-wrapper card-element delay-1">
        <i class="fa-solid fa-unlock-keyhole"></i>
    </div>
    
    <h2 id="reset-title" class="card-element delay-2">Forgot Password?</h2>
    
    <p class="helptext card-element delay-3">Enter the email or phone number associated with your account. We'll send you a secure 6-digit code, valid for 30 minutes.</p>

    <?php if (!empty($errors)): foreach ($errors as $e): ?>
      <div class="msg error card-element delay-4" role="alert"><i class="fa-solid fa-circle-exclamation"></i> <?php echo htmlspecialchars($e); ?></div>
    <?php endforeach; endif; ?>

    <?php if (!empty($_SESSION['pw_notice'])): ?>
      <div class="msg success card-element delay-4" role="status"><i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($_SESSION['pw_notice']); unset($_SESSION['pw_notice']); ?></div>
    <?php endif; ?>

    <form method="post" autocomplete="off" onsubmit="this.querySelector('button').disabled=true;" class="card-element delay-4">
      <div class="input-group">
        <input type="text" name="identifier" id="identifier" class="input-field" required placeholder=" ">
        <label for="identifier" class="input-label">Registered Email or Phone</label>
      </div>
      <button class="btn-primary" type="submit">
        Send Recovery Code <i class="fa-solid fa-arrow-right"></i>
      </button>
    </form>

    <div class="small card-element delay-5">
      <a href="login.php"><i class="fa-solid fa-arrow-left"></i> Back to Sign In</a>
    </div>
  </div>
</body>
</html>