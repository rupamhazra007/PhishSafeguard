<?php
// verify_password_reset.php (Ultra-Animated Premium UI - No Scanline, Lock Icon added)
if (session_status() === PHP_SESSION_NONE) session_start();
require_once __DIR__ . '/helpers_db.php'; // must provide db()

// debug entry
file_put_contents(__DIR__.'/debug_forget.log', date('Y-m-d H:i:s')." - ENTER verify_password_reset.php SESSION_RESET_ID:".($_SESSION['password_reset_id'] ?? 'N/A')."\n", FILE_APPEND);

// require a reset id set by forget_password.php
if (empty($_SESSION['password_reset_id']) || empty($_SESSION['password_reset_user'])) {
    $_SESSION['pw_notice'] = "Please request a password reset first.";
    header('Location: forget_password.php');
    exit;
}

$reset_id = (int)$_SESSION['password_reset_id'];
$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = trim($_POST['otp'] ?? '');
    if ($otp === '') {
        $errors[] = "Enter the 6-digit OTP.";
    } else {
        $conn = db();
        $stmt = $conn->prepare("SELECT id, user_id, otp_hash, expires_at, used FROM password_resets WHERE id = ? LIMIT 1");
        if (!$stmt) {
            $errors[] = "Internal error (prepare).";
            file_put_contents(__DIR__.'/debug_forget.log', date('Y-m-d H:i:s')." - PREPARE FAILED verify_password_reset: ".$conn->error."\n", FILE_APPEND);
        } else {
            $stmt->bind_param('i', $reset_id);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res && $res->num_rows === 1) {
                $row = $res->fetch_assoc();
                // expiry check using Asia/Kolkata timezone
                try {
                    $now = new DateTime('now', new DateTimeZone('Asia/Kolkata'));
                    $expires = new DateTime($row['expires_at'], new DateTimeZone('Asia/Kolkata'));
                } catch (Exception $e) {
                    $errors[] = "Internal date error.";
                    file_put_contents(__DIR__.'/debug_forget.log', date('Y-m-d H:i:s')." - DATE PARSE ERROR: ".$e->getMessage()."\n", FILE_APPEND);
                    $expires = new DateTime('now', new DateTimeZone('Asia/Kolkata'));
                }

                if ((int)$row['used'] === 1) {
                    $errors[] = "This OTP has already been used. Request a new reset.";
                } elseif ($expires < $now) {
                    $errors[] = "OTP has expired. Please request a new one.";
                } else {
                    if (password_verify($otp, $row['otp_hash'])) {
                        // mark used and allow password reset
                        $upd = $conn->prepare("UPDATE password_resets SET used = 1 WHERE id = ?");
                        if ($upd) {
                            $upd->bind_param('i', $reset_id);
                            $upd->execute();
                            $upd->close();
                        } else {
                            file_put_contents(__DIR__.'/debug_forget.log', date('Y-m-d H:i:s')." - UPDATE PREPARE FAILED: ".$conn->error."\n", FILE_APPEND);
                        }

                        $_SESSION['can_reset_password_for_user'] = $row['user_id'];
                        // unset the temporary password_reset_id to prevent reuse
                        unset($_SESSION['password_reset_id']);
                        // redirect to reset form
                        header('Location: reset_password.php');
                        exit;
                    } else {
                        $errors[] = "Incorrect OTP.";
                    }
                }
            } else {
                $errors[] = "Reset request not found. Please request again.";
                file_put_contents(__DIR__.'/debug_forget.log', date('Y-m-d H:i:s')." - RESET ROW NOT FOUND id=".$reset_id."\n", FILE_APPEND);
            }
            $stmt->close();
            $conn->close();
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Verify Identity — PhishSafeguard</title>
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

    /* SCROLL ENABLED */
    body {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background-image: linear-gradient(to right, rgba(9, 14, 23, 0.88), rgba(9, 14, 23, 0.75)), 
                        url('https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?q=80&w=2564&auto=format&fit=crop');
      background-size: cover;
      background-position: center;
      background-attachment: fixed;
      color: #e6edf3;
      padding: 100px 15px; 
      overflow-x: hidden;
      overflow-y: auto; 
      position: relative;
    }

    /* ========================================= */
    /* HEAVY KEYFRAME ANIMATIONS */
    /* ========================================= */
    
    @keyframes fadeInDownBrand {
        0% { opacity: 0; transform: translateY(-40px) scale(0.9); }
        100% { opacity: 1; transform: translateY(0) scale(1); }
    }

    @keyframes floatBrand {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-8px) rotate(1deg); }
        100% { transform: translateY(0px); }
    }

    @keyframes rotateIcon {
        0% { transform: rotate(0deg) scale(1); }
        50% { transform: rotate(180deg) scale(1.2); }
        100% { transform: rotate(360deg) scale(1); }
    }

    @keyframes floatShape1 {
        0% { transform: translateY(0) translateX(0) scale(1) rotate(0deg); }
        50% { transform: translateY(60px) translateX(80px) scale(1.2) rotate(45deg); }
        100% { transform: translateY(-30px) translateX(-50px) scale(0.8) rotate(90deg); }
    }
    
    @keyframes floatShape2 {
        0% { transform: translateY(0) translateX(0) scale(1); }
        50% { transform: translateY(-70px) translateX(-60px) scale(1.3) skewX(5deg); }
        100% { transform: translateY(40px) translateX(40px) scale(0.8) skewX(-5deg); }
    }

    @keyframes cardEntrance {
      0% { opacity: 0; transform: translateY(80px) scale(0.85) perspective(1000px) rotateX(15deg); filter: blur(10px); }
      100% { opacity: 1; transform: translateY(0) scale(1) perspective(1000px) rotateX(0deg); filter: blur(0); }
    }

    @keyframes popInElement {
        0% { opacity: 0; transform: translateY(30px) scale(0.95); }
        100% { opacity: 1; transform: translateY(0) scale(1); }
    }

    @keyframes pulseGlowButton {
        0% { box-shadow: 0 0 0 0 rgba(31, 111, 235, 0.7); }
        70% { box-shadow: 0 0 0 20px rgba(31, 111, 235, 0); }
        100% { box-shadow: 0 0 0 0 rgba(31, 111, 235, 0); }
    }
    
    @keyframes iconWobble {
        0%, 100% { transform: rotate(0deg) scale(1.1); }
        25% { transform: rotate(-20deg) scale(1.2); }
        75% { transform: rotate(20deg) scale(1.2); }
    }

    @keyframes shakeError {
        0%, 100% { transform: translateX(0); }
        20%, 60% { transform: translateX(-8px); }
        40%, 80% { transform: translateX(8px); }
    }

    @keyframes continuousGlow {
        0% { box-shadow: 0 0 10px rgba(88, 166, 255, 0.2); border-color: #58a6ff; }
        50% { box-shadow: 0 0 25px rgba(88, 166, 255, 0.6); border-color: #79c0ff; }
        100% { box-shadow: 0 0 10px rgba(88, 166, 255, 0.2); border-color: #58a6ff; }
    }

    @keyframes gradientShift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    @keyframes floatTech {
        0% { transform: translateY(100vh) scale(0.5) rotate(0deg); opacity: 0; }
        20% { opacity: 0.4; }
        80% { opacity: 0.4; }
        100% { transform: translateY(-20vh) scale(1.5) rotate(360deg); opacity: 0; }
    }

    /* ========================================= */
    /* BACKGROUND & ATMOSPHERE */
    /* ========================================= */

    .particles {
        position: fixed;
        top: 0; left: 0; width: 100%; height: 100%;
        z-index: 0; pointer-events: none; overflow: hidden;
    }
    
    .particle {
        position: absolute;
        color: rgba(88, 166, 255, 0.15);
        font-size: 20px;
        animation: floatTech linear infinite;
    }

    .background-shapes {
        position: fixed; 
        top: 0; left: 0; width: 100%; height: 100%;
        z-index: 0; pointer-events: none;
    }
    .shape {
        position: absolute; border-radius: 50%; opacity: 0.3; filter: blur(100px);
    }
    .shape1 {
        width: 450px; height: 450px; background: #1f6feb; top: -10%; left: -10%;
        animation: floatShape1 15s infinite alternate ease-in-out;
    }
    .shape2 {
        width: 400px; height: 400px; background: #8957e5; bottom: -10%; right: -5%;
        animation: floatShape2 18s infinite alternate-reverse ease-in-out;
    }

    /* ========================================= */
    /* BRANDING & CARD */
    /* ========================================= */

    .top-left-brand {
        position: absolute;
        top: 30px; left: 40px;
        display: flex; align-items: center; gap: 12px; z-index: 10;
        animation: fadeInDownBrand 1.2s cubic-bezier(0.2, 0.8, 0.2, 1) forwards, floatBrand 4s ease-in-out infinite 1.2s;
    }

    .top-left-brand i {
        font-size: 28px; color: #58a6ff;
        filter: drop-shadow(0 0 10px rgba(88, 166, 255, 0.8));
        transition: transform 0.4s ease, filter 0.4s ease;
    }
    
    .top-left-brand:hover i {
        animation: rotateIcon 1s ease-in-out;
        filter: drop-shadow(0 0 20px rgba(88, 166, 255, 1));
    }

    .top-left-brand span {
        font-size: 22px; font-weight: 600; color: #ffffff; letter-spacing: 0.5px;
        text-shadow: 0 0 10px rgba(255, 255, 255, 0.2);
    }

    .card {
      background: rgba(13, 17, 23, 0.5); 
      backdrop-filter: blur(30px);
      -webkit-backdrop-filter: blur(30px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-top: 1px solid rgba(255, 255, 255, 0.25);
      border-left: 1px solid rgba(255, 255, 255, 0.25);
      padding: 45px 40px;
      border-radius: 24px;
      box-shadow: 0 30px 60px rgba(0,0,0,0.7), inset 0 0 20px rgba(88, 166, 255, 0.05);
      width: 460px; max-width: 100%; text-align: center;
      animation: cardEntrance 1.2s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
      z-index: 1; position: relative;
      transition: transform 0.5s ease, box-shadow 0.5s ease;
      transform-style: preserve-3d;
    }

    /* 3D Hover Effect on Card */
    .card:hover {
        transform: translateY(-5px) scale(1.01);
        box-shadow: 0 40px 70px rgba(0,0,0,0.8), inset 0 0 30px rgba(88, 166, 255, 0.1);
    }

    .card-element {
        opacity: 0; animation: popInElement 0.7s cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
    }
    .delay-1 { animation-delay: 0.2s; }
    .delay-2 { animation-delay: 0.4s; }
    .delay-3 { animation-delay: 0.6s; }
    .delay-4 { animation-delay: 0.8s; }
    .delay-5 { animation-delay: 1.0s; }
    
    .card .icon-wrapper {
        width: 70px; height: 70px;
        background: linear-gradient(135deg, rgba(88, 166, 255, 0.1), rgba(31, 111, 235, 0.2));
        border: 1px solid rgba(88, 166, 255, 0.4); border-radius: 50%;
        display: flex; justify-content: center; align-items: center; margin: 0 auto 20px;
        color: #58a6ff; font-size: 28px; box-shadow: 0 0 25px rgba(88, 166, 255, 0.25); 
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    
    .card:hover .icon-wrapper {
        transform: scale(1.15) translateY(-5px);
        box-shadow: 0 0 40px rgba(88, 166, 255, 0.6);
        background: linear-gradient(135deg, rgba(88, 166, 255, 0.2), rgba(31, 111, 235, 0.4));
        border-color: rgba(88, 166, 255, 0.8);
    }
    .card:hover .icon-wrapper i {
        animation: iconWobble 0.8s ease-in-out infinite;
    }

    .card h2 { font-size: 28px; color: #ffffff; font-weight: 600; margin-bottom: 12px; letter-spacing: 0.5px;}
    .helptext { color: #8b949e; font-size: 14.5px; margin-bottom: 30px; line-height: 1.6; }

    /* ========================================= */
    /* INPUTS & BUTTONS */
    /* ========================================= */

    form { display:flex; flex-direction:column; align-items:center; width: 100%; }
    .otp-input-wrapper { position: relative; margin-bottom: 30px; width: 100%; display: flex; justify-content: center;}
    
    input[type="text"] {
      padding: 18px;
      border: 2px solid rgba(255, 255, 255, 0.15);
      background: rgba(0, 0, 0, 0.4);
      border-radius: 12px; font-size: 28px; width: 280px;
      text-align: center; letter-spacing: 12px; outline: none;
      color: #ffffff; font-weight: 600;
      transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    
    /* Animated continuous glow when focused */
    input[type="text"]:focus { 
        background: rgba(0, 0, 0, 0.6);
        transform: translateY(-3px) scale(1.02);
        animation: continuousGlow 2s infinite;
    }
    
    input[type="text"]::placeholder { 
        color: #4d5560; letter-spacing: 12px; font-size: 24px; transform: translateY(-2px); display: inline-block;
        transition: color 0.3s ease;
    }
    input[type="text"]:focus::placeholder { color: rgba(88, 166, 255, 0.3); }

    .controls { width: 100%; display: flex; gap: 12px; margin-bottom: 15px;}

    button {
      flex: 1; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600;
      cursor: pointer; transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
      display: flex; align-items: center; justify-content: center; gap: 8px;
    }
    button:active { transform: translateY(0) scale(0.95); }
    
    .btn-primary {
        background: linear-gradient(270deg, #1f6feb, #3182ce, #1f6feb, #8957e5);
        background-size: 300% 300%;
        color: #ffffff; position: relative; overflow: hidden;
        animation: pulseGlowButton 2s infinite, gradientShift 6s ease infinite;
        letter-spacing: 0.5px; border: 1px solid rgba(255,255,255,0.1);
    }
    
    .btn-primary::after {
        content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.5), transparent);
        transform: skewX(-25deg); transition: all 0.6s ease;
    }
    
    .btn-primary:hover::after { left: 120%; }
    .btn-primary:hover {
        transform: translateY(-4px) scale(1.03);
        box-shadow: 0 15px 35px rgba(31, 111, 235, 0.6);
    }
    .btn-primary:disabled { opacity: 0.7; cursor: not-allowed; animation: none; transform: none; box-shadow: none;}

    .btn-secondary {
        background: rgba(13, 17, 23, 0.6); color: #8b949e; border: 1px solid rgba(255, 255, 255, 0.15);
        position: relative; overflow: hidden;
    }
    .btn-secondary:hover {
        color: #ffffff; background: rgba(255, 255, 255, 0.1); border-color: rgba(255, 255, 255, 0.3);
        transform: translateY(-3px); box-shadow: 0 10px 20px rgba(0,0,0,0.3);
    }
    .btn-secondary:hover i { animation: rotateIcon 1s linear infinite; }

    /* ========================================= */
    /* ALERTS & LINKS */
    /* ========================================= */

    .msg {
        margin: 0 0 20px; padding: 14px 18px; border-radius: 12px; font-size: 14px; line-height: 1.5; text-align: left; 
        display: flex; align-items: center; gap: 12px; width: 100%; font-weight: 500;
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    .msg.error {
        background: linear-gradient(to right, rgba(248, 81, 73, 0.15), rgba(248, 81, 73, 0.05));
        color: #ff7b72; border-left: 4px solid #ff7b72;
        animation: popInElement 0.5s forwards, shakeError 0.5s ease-in-out;
    }
    .msg.success {
        background: linear-gradient(to right, rgba(63, 185, 80, 0.15), rgba(63, 185, 80, 0.05));
        color: #56d364; border-left: 4px solid #56d364;
    }

    .note { color:#8b949e; font-size:13.5px; text-align:center; margin-top:20px; line-height: 1.6; opacity: 0.8;}
    
    .small { font-size: 14.5px; color: #8b949e; text-align: center; margin-top: 30px; }
    .small a {
        color: #58a6ff; text-decoration: none; font-weight: 500; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 6px;
    }
    .small a i { transition: transform 0.3s ease; }
    .small a:hover { color: #79c0ff; text-shadow: 0 0 8px rgba(121, 192, 255, 0.5);}
    .small a:hover i { transform: translateX(-5px); }

    /* Responsive */
    @media (max-width: 600px) {
        .top-left-brand { top: 20px; left: 20px; position: relative; margin-bottom: 25px; }
        .top-left-brand span { font-size: 18px; }
        body { padding: 40px 15px; flex-direction: column; }
        .card { padding: 35px 25px; width: 100%;}
        .controls { flex-direction: column; }
        input[type="text"] { width: 100%; font-size: 24px; letter-spacing: 8px;}
    }
  </style>
</head>
<body>

  <div class="particles" aria-hidden="true">
      <i class="fa-solid fa-lock particle" style="left: 10%; animation-duration: 15s; animation-delay: 0s;"></i>
      <i class="fa-solid fa-shield-halved particle" style="left: 30%; animation-duration: 20s; animation-delay: 2s;"></i>
      <i class="fa-solid fa-key particle" style="left: 60%; animation-duration: 18s; animation-delay: 5s;"></i>
      <i class="fa-solid fa-user-shield particle" style="left: 85%; animation-duration: 22s; animation-delay: 1s;"></i>
      <i class="fa-solid fa-fingerprint particle" style="left: 50%; animation-duration: 16s; animation-delay: 7s;"></i>
  </div>

  <div class="top-left-brand">
      <i class="fa-solid fa-shield-halved"></i>
      <span>PhishSafeguard</span>
  </div>

  <div class="background-shapes">
      <div class="shape shape1"></div>
      <div class="shape shape2"></div>
  </div>

  <div class="card" role="main" aria-labelledby="verify-heading">
    
    <div class="icon-wrapper card-element delay-1">
        <i class="fa-solid fa-lock"></i>
    </div>

    <h2 id="verify-heading" class="card-element delay-2">Verify Identity</h2>
    
    <p class="helptext card-element delay-3">Please enter the 6-digit verification code we sent to your registered email or phone.</p>

    <?php if (!empty($errors)): ?>
      <?php foreach ($errors as $e): ?>
        <div class="msg error card-element delay-4"><i class="fa-solid fa-circle-exclamation"></i> <?php echo htmlspecialchars($e); ?></div>
      <?php endforeach; ?>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="msg success card-element delay-4"><i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <?php if (!empty($_SESSION['pw_notice'])): ?>
      <div class="msg success card-element delay-4" role="status"><i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($_SESSION['pw_notice']); unset($_SESSION['pw_notice']); ?></div>
    <?php endif; ?>

    <form method="post" autocomplete="off" id="otpForm" class="card-element delay-4">
        
      <div class="otp-input-wrapper">
        <input id="otp" name="otp" type="text" inputmode="numeric" pattern="\d{6}" maxlength="6" required placeholder="------" aria-label="6 digit OTP">
      </div>
      
      <div class="controls">
        <button type="button" id="resendBtn" class="btn-secondary"><i class="fa-solid fa-rotate-right"></i> Resend</button>
        <button type="submit" class="btn-primary">Verify Code <i class="fa-solid fa-bolt"></i></button>
      </div>
    </form>

    <div class="note card-element delay-5">Didn't receive the code? Check your spam folder.</div>

    <div class="small card-element delay-5">
      <a href="login.php"><i class="fa-solid fa-arrow-left"></i> Back to Sign In</a>
    </div>
  </div>

  <script>
    (function(){
      const otpInput = document.getElementById('otp');
      const form = document.getElementById('otpForm');
      const resendBtn = document.getElementById('resendBtn');
      const submitBtn = form.querySelector('.btn-primary');
      const errorMsgs = document.querySelectorAll('.msg.error');

      // Re-trigger shake animation on click for fun (if errors exist)
      errorMsgs.forEach(msg => {
          msg.addEventListener('click', () => {
              msg.style.animation = 'none';
              msg.offsetHeight; /* trigger reflow */
              msg.style.animation = 'shakeError 0.5s ease-in-out';
          });
      });

      // Allow only digits; remove non-digits on input
      otpInput.addEventListener('input', function(e){
        this.value = this.value.replace(/\D/g,'').slice(0,6);
      });

      // handle resend button: navigate back to forget_password.php
      resendBtn.addEventListener('click', function(){
        // Add a quick zoom-out effect before leaving
        document.querySelector('.card').style.transform = 'scale(0.8) translateY(100px)';
        document.querySelector('.card').style.opacity = '0';
        setTimeout(() => {
            window.location.href = 'forget_password.php';
        }, 300);
      });

      // client-side validation on submit & loading state
      form.addEventListener('submit', function(e){
        if (otpInput.value.length !== 6) {
          e.preventDefault();
          
          // Trigger error styling dynamically
          otpInput.style.borderColor = '#ff7b72';
          otpInput.style.boxShadow = '0 0 15px rgba(248, 81, 73, 0.4)';
          otpInput.style.animation = 'shakeError 0.5s ease-in-out';
          setTimeout(() => { otpInput.style.animation = 'continuousGlow 2s infinite'; }, 500);
          
          otpInput.focus();
        } else {
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Verifying...';
          submitBtn.style.background = 'linear-gradient(135deg, #2ea043, #3fb950)';
          submitBtn.style.boxShadow = '0 0 30px rgba(63, 185, 80, 0.5)';
        }
      });

      // autofocus with a slight delay for animation smoothness
      setTimeout(() => otpInput.focus(), 1200);
    })();
  </script>
</body>
</html>