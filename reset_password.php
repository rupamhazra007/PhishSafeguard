<?php
// reset_password.php
// Put this file in your project (replace existing). Requires helpers_db.php with db() function.

if (session_status() === PHP_SESSION_NONE) session_start();
require_once __DIR__ . '/helpers_db.php';

// Check if user is authorized to reset password
if (empty($_SESSION['can_reset_password_for_user'])) {
    $_SESSION['pw_notice'] = "Unauthorized or session expired. Please request a password reset again.";
    header('Location: forget_password.php');
    exit;
}

$user_id = (int)$_SESSION['can_reset_password_for_user'];
$errors = [];
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pw = $_POST['password'] ?? '';
    $pw2 = $_POST['password_confirm'] ?? '';

    // Server-side validation
    if (strlen($pw) < 8) { // Increased minimum length
        $errors[] = "Password must be at least 8 characters.";
    } elseif ($pw !== $pw2) {
        $errors[] = "Passwords do not match.";
    } else {
        // Hash the new password and update the database
        $pw_hash = password_hash($pw, PASSWORD_DEFAULT);
        $conn = db();
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param('si', $pw_hash, $user_id);
            if ($stmt->execute()) {
                $success = "Password updated successfully. You may now login.";
                unset($_SESSION['can_reset_password_for_user']); // Invalidate the reset session
            } else {
                $errors[] = "Failed to update password.";
            }
            $stmt->close();
        } else {
            $errors[] = "Internal error (prepare failed).";
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
  <title>Reset Password — PhishSafeguard</title>
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
        50% { box-shadow: 0 0 20px rgba(88, 166, 255, 0.5); border-color: #79c0ff; }
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
      width: 480px; max-width: 100%; text-align: center;
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

    .card h2 { font-size: 28px; color: #ffffff; font-weight: 600; margin-bottom: 30px; letter-spacing: 0.5px;}

    /* ========================================= */
    /* INPUTS & FORM */
    /* ========================================= */

    form { text-align: left; width: 100%; }
    
    .input-group { margin-bottom: 25px; position: relative; }
    label { display: block; margin-bottom: 10px; color: #8b949e; font-size: 14.5px; font-weight: 500; }
    
    .input-wrapper { position: relative; }
    
    input[type="password"], input[type="text"] {
      width: 100%; padding: 16px 50px 16px 18px; 
      border: 2px solid rgba(255, 255, 255, 0.15);
      background: rgba(0, 0, 0, 0.4);
      border-radius: 12px; font-size: 15px; outline: none;
      color: #ffffff; font-weight: 500;
      transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    
    input:focus { 
        background: rgba(0, 0, 0, 0.6);
        transform: translateY(-2px);
        animation: continuousGlow 2s infinite;
    }
    input::placeholder { color: #4d5560; transition: color 0.3s ease; }
    input:focus::placeholder { color: rgba(88, 166, 255, 0.3); }

    .toggle-eye-button {
      position: absolute; right: 15px; top: 50%; transform: translateY(-50%);
      display: inline-flex; align-items: center; justify-content: center;
      background: transparent; border: none; color: #8b949e; font-size: 18px;
      cursor: pointer; transition: all 0.3s ease; width: 30px; height: 30px;
    }
    .toggle-eye-button:hover { color: #58a6ff; transform: translateY(-50%) scale(1.1); filter: drop-shadow(0 0 5px rgba(88,166,255,0.5));}

    /* Password Strength Meter */
    .strength-meter {
        height: 6px; background-color: rgba(255,255,255,0.08); border-radius: 6px;
        margin: 12px 0 6px 0; overflow: hidden; display: none;
    }
    .strength-meter-bar {
        height: 100%; width: 0; border-radius: 6px;
        transition: width 0.4s ease-in-out, background-color 0.4s ease-in-out, box-shadow 0.4s ease-in-out;
    }
    #strength-meter-text { font-size: 13.5px; text-align: right; min-height: 20px; font-weight: 600; margin-top: 5px; transition: color 0.3s;}
    
    .weak { color: #ff7b72 !important; }
    .medium { color: #f0ad4e !important; }
    .strong { color: #58a6ff !important; }
    .very-strong { color: #3fb950 !important; }
    
    .strength-meter-bar.weak { background-color: #ff7b72; box-shadow: 0 0 10px rgba(255, 123, 114, 0.6); }
    .strength-meter-bar.medium { background-color: #f0ad4e; box-shadow: 0 0 10px rgba(240, 173, 78, 0.6); }
    .strength-meter-bar.strong { background-color: #58a6ff; box-shadow: 0 0 10px rgba(88, 166, 255, 0.6); }
    .strength-meter-bar.very-strong { background-color: #3fb950; box-shadow: 0 0 10px rgba(63, 185, 80, 0.6); }

    /* Buttons */
    button[type="submit"] {
        width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600;
        cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px;
        background: linear-gradient(270deg, #1f6feb, #3182ce, #1f6feb, #8957e5);
        background-size: 300% 300%; color: #ffffff; position: relative; overflow: hidden;
        animation: pulseGlowButton 2s infinite, gradientShift 6s ease infinite;
        letter-spacing: 0.5px; border: 1px solid rgba(255,255,255,0.1);
        transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
        margin-top: 10px;
    }
    button[type="submit"]::after {
        content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.5), transparent);
        transform: skewX(-25deg); transition: all 0.6s ease;
    }
    button[type="submit"]:hover::after { left: 120%; }
    button[type="submit"]:hover { transform: translateY(-4px) scale(1.02); box-shadow: 0 15px 35px rgba(31, 111, 235, 0.6); }
    button[type="submit"]:active { transform: translateY(0) scale(0.98); }

    /* ========================================= */
    /* ALERTS & LINKS */
    /* ========================================= */

    .msg {
        margin: 0 0 25px; padding: 14px 18px; border-radius: 12px; font-size: 14px; line-height: 1.5; text-align: left; 
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

    .link-small { text-align: center; margin-top: 30px; font-size: 14.5px; color: #8b949e; }
    .link-small a { color: #58a6ff; text-decoration: none; font-weight: 500; transition: all 0.3s ease; display: inline-flex; align-items: center; gap: 6px; }
    .link-small a:hover { color: #79c0ff; text-shadow: 0 0 8px rgba(121, 192, 255, 0.5); }
    .link-small span { margin: 0 10px; color: #4d5560; }

    /* Responsive */
    @media (max-width: 600px) {
        .top-left-brand { top: 20px; left: 20px; position: relative; margin-bottom: 25px; }
        .top-left-brand span { font-size: 18px; }
        body { padding: 40px 15px; flex-direction: column; }
        .card { padding: 35px 25px; width: 100%;}
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

  <div class="card" role="main" aria-labelledby="reset-heading">
    
    <div class="icon-wrapper card-element delay-1">
        <i class="fa-solid fa-key"></i>
    </div>

    <h2 id="reset-heading" class="card-element delay-2">Create New Password</h2>

    <?php if (!empty($errors)): ?>
      <?php foreach ($errors as $e): ?>
        <div class="msg error card-element delay-3"><i class="fa-solid fa-circle-exclamation"></i> <?php echo htmlspecialchars($e); ?></div>
      <?php endforeach; ?>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="msg success card-element delay-3"><i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($success); ?></div>
      <div class="link-small card-element delay-4"><a href="login.php">Proceed to Sign In <i class="fa-solid fa-arrow-right"></i></a></div>
    <?php else: ?>
      <form method="post" autocomplete="off" id="resetForm" class="card-element delay-3" novalidate>
        
        <div class="input-group">
          <label for="password">New Password</label>
          <div class="input-wrapper">
            <input id="password" type="password" name="password" required minlength="8" placeholder="Enter at least 8 characters" autocomplete="new-password">
            <button type="button" class="toggle-eye-button" data-target="password" aria-pressed="false" aria-label="Show password">
              <i class="fa-solid fa-eye" aria-hidden="true"></i>
            </button>
          </div>
          <div id="strength-meter" class="strength-meter">
              <div class="strength-meter-bar"></div>
          </div>
          <p id="strength-meter-text"></p>
        </div>

        <div class="input-group">
          <label for="password_confirm">Confirm New Password</label>
          <div class="input-wrapper">
            <input id="password_confirm" type="password" name="password_confirm" required placeholder="Repeat the new password" autocomplete="new-password">
            <button type="button" class="toggle-eye-button" data-target="password_confirm" aria-pressed="false" aria-label="Show confirm password">
              <i class="fa-solid fa-eye" aria-hidden="true"></i>
            </button>
          </div>
        </div>

        <button type="submit">Set New Password <i class="fa-solid fa-bolt"></i></button>
      </form>
      
      <div class="link-small card-element delay-4">
          <a href="forget_password.php">Request Another Reset</a> <span>•</span> <a href="login.php">Back to Sign In</a>
      </div>
    <?php endif; ?>
  </div>

  <script>
    (function(){
      const form = document.getElementById('resetForm');
      if (form) {
        const pw = document.getElementById('password');
        const pw2 = document.getElementById('password_confirm');

        // Form Validation Shake Animation Helper
        function triggerErrorShake(element) {
            element.style.borderColor = '#ff7b72';
            element.style.boxShadow = '0 0 15px rgba(248, 81, 73, 0.4)';
            element.style.animation = 'shakeError 0.5s ease-in-out';
            setTimeout(() => { 
                element.style.animation = ''; 
                element.style.borderColor = '';
                element.style.boxShadow = '';
            }, 600);
        }

        // Client-side validation on submit
        form.addEventListener('submit', function(e){
          if (pw.value.length < 8) { 
            e.preventDefault();
            triggerErrorShake(pw);
            pw.focus();
            return false;
          }
          if (pw.value !== pw2.value) {
            e.preventDefault();
            triggerErrorShake(pw2);
            pw2.focus();
            return false;
          }
          
          // Show loading state on button
          const submitBtn = form.querySelector('button[type="submit"]');
          submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Updating...';
          submitBtn.style.background = 'linear-gradient(135deg, #2ea043, #3fb950)';
          submitBtn.style.boxShadow = '0 0 30px rgba(63, 185, 80, 0.5)';
        });

        // --- Password Strength Meter Logic ---
        const strengthMeter = document.getElementById('strength-meter');
        const strengthBar = document.querySelector('.strength-meter-bar');
        const strengthText = document.getElementById('strength-meter-text');

        pw.addEventListener('input', function() {
            const password = pw.value;
            const score = calculatePasswordStrength(password);
            
            if (password.length === 0) {
                strengthMeter.style.display = 'none';
                strengthText.textContent = '';
                return;
            }
            
            strengthMeter.style.display = 'block';

            let strength = { width: '0%', className: '', text: '' };

            if (score < 2) {
                strength = { width: '25%', className: 'weak', text: 'Weak' };
            } else if (score === 2) {
                strength = { width: '50%', className: 'medium', text: 'Medium' };
            } else if (score === 3) {
                strength = { width: '75%', className: 'strong', text: 'Strong' };
            } else if (score >= 4) {
                strength = { width: '100%', className: 'very-strong', text: 'Very Strong' };
            }
            
            strengthBar.style.width = strength.width;
            strengthBar.className = 'strength-meter-bar ' + strength.className;
            strengthText.textContent = strength.text;
            strengthText.className = strength.className;
        });

        function calculatePasswordStrength(password) {
            let score = 0;
            if (password.length >= 8) score++;      // 1. Length
            if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++; // 2. Mixed Case
            if (/[0-9]/.test(password)) score++;     // 3. Numbers
            if (/[^a-zA-Z0-9]/.test(password)) score++; // 4. Special Characters
            
            if (password.length > 12) score++;      // Bonus for long passwords
            return score;
        }
      }

      // Accessible show/hide password toggle
      document.querySelectorAll('.toggle-eye-button').forEach(btn=>{
        btn.addEventListener('click', function(e){
          const targetId = this.getAttribute('data-target');
          const input = document.getElementById(targetId);
          if (!input) return;
          const icon = this.querySelector('i');

          if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
            this.setAttribute('aria-pressed','true');
            this.setAttribute('aria-label','Hide password');
          } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
            this.setAttribute('aria-pressed','false');
            this.setAttribute('aria-label','Show password');
          }
        });
      });
    })();
  </script>
</body>
</html>