<?php
session_start();
date_default_timezone_set('Asia/Kolkata');

// Database Connection Configuration
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "phishing_db";

// Create Connection
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize message variables for SweetAlert
$msg = "";
$msg_type = ""; // "success" or "error"

// Process Form Submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username_raw = trim($_POST['username'] ?? '');
    $email_raw    = trim($_POST['email'] ?? '');
    $phone_raw    = trim($_POST['phone'] ?? '');
    $password_raw = $_POST['password'] ?? '';

    // Basic required fields check
    if (empty($username_raw) || empty($password_raw)) {
        $msg_type = "error";
        $msg = "Username and Password are required.";
    } 
    elseif (strlen($password_raw) < 8) {
        $msg_type = "error";
        $msg = "Password must be at least 8 characters long.";
    }
    else {
        // Normalize contact info
        $email_final = null;
        if ($email_raw !== '') {
            if (filter_var($email_raw, FILTER_VALIDATE_EMAIL)) {
                $email_final = strtolower($email_raw);
            } else {
                $msg_type = "error";
                $msg = "Invalid email format.";
            }
        }

        $phone_final = null;
        if ($phone_raw !== '' && empty($msg)) {
            $digits = preg_replace('/\D+/', '', $phone_raw);
            if (strlen($digits) >= 7 && strlen($digits) <= 15) {
                $phone_final = $digits;
            } else {
                $msg_type = "error";
                $msg = "Phone must contain 7-15 digits.";
            }
        }

        if (empty($msg) && $email_final === null && $phone_final === null) {
            $msg_type = "error";
            $msg = "Provide either a valid Email OR Phone number.";
        }

        if (empty($msg)) {
            $conflict = false;

            // Check Username
            $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->bind_param("s", $username_raw);
            $stmt->execute();
            if ($stmt->get_result()->num_rows > 0) {
                $msg_type = "error";
                $msg = "Username already taken. Please choose another.";
                $conflict = true;
            }
            $stmt->close();

            // Check Email
            if (!$conflict && $email_final !== null) {
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->bind_param("s", $email_final);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    $msg_type = "error";
                    $msg = "Email already registered. Please go to the Login page.";
                    $conflict = true;
                }
                $stmt->close();
            }

            // Check Phone
            if (!$conflict && $phone_final !== null) {
                $stmt = $conn->prepare("SELECT id FROM users WHERE phone = ?");
                $stmt->bind_param("s", $phone_final);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    $msg_type = "error";
                    $msg = "Phone number already registered. Please go to the Login page.";
                    $conflict = true;
                }
                $stmt->close();
            }

            // Insert new user
            if (!$conflict) {
                $hashed_password = password_hash($password_raw, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO users (username, email, phone, password, created_at) VALUES (?, ?, ?, ?, NOW())");
                $stmt->bind_param("ssss", $username_raw, $email_final, $phone_final, $hashed_password);

                if ($stmt->execute()) {
                    $msg_type = "success";
                    $msg = "Registration successful! Redirecting to login...";
                    $_POST = [];
                } else {
                    $msg_type = "error";
                    $msg = "A system error occurred. Please try again later.";
                }
                $stmt->close();
            }
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
<title>Join PhishSafeguard - Elite Cybersecurity</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700;800&family=Poppins:wght@300;400;500;600&family=Space+Grotesk:wght@700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

<style>
    :root {
        --primary-cyan: #00f2fe;
        --primary-blue: #4facfe;
        --dark-bg: #030712;
        --panel-bg: rgba(15, 23, 42, 0.7); /* Deep frosted glass */
        --panel-border: rgba(255, 255, 255, 0.08);
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
        --input-bg: rgba(255, 255, 255, 0.03);
        --input-border: rgba(255, 255, 255, 0.1);
        
        --danger: #ff4d4f;
        --warning: #fbbf24;
        --success: #10b981;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    /* --- FULL PAGE SCROLL ENABLED --- */
    body {
        font-family: 'Poppins', sans-serif;
        min-height: 100vh;
        margin: 0;
        overflow-x: hidden;
        overflow-y: auto; /* Full page scroll */
        background-color: var(--dark-bg);
        display: flex;
        flex-direction: row;
        color: var(--text-main);
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: var(--dark-bg); }
    ::-webkit-scrollbar-thumb { background: var(--primary-blue); border-radius: 10px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--primary-cyan); }

    /* --- 4K CINEMATIC BACKGROUND WITH CYBER GRID --- */
    .hero-section {
        flex: 1.2;
        position: relative;
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
        padding: 100px 5% 60px;
        z-index: 1;
        overflow: hidden;
    }

    .hero-bg {
        position: absolute;
        inset: -5%;
        z-index: -3;
        background: url('https://images.unsplash.com/photo-1550745165-9bc0b252726f?q=80&w=3840&auto=format&fit=crop') no-repeat center center;
        background-size: cover;
        animation: cinematicPan 30s ease-in-out infinite alternate, bgPulse 10s infinite alternate;
        filter: brightness(0.3) contrast(1.2);
    }

    /* Animated Cyber Grid Overlay */
    .cyber-grid {
        position: absolute;
        inset: 0;
        z-index: -2;
        background-image: 
            linear-gradient(rgba(0, 242, 254, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 242, 254, 0.05) 1px, transparent 1px);
        background-size: 30px 30px;
        animation: gridMove 20s linear infinite;
        opacity: 0.6;
    }

    @keyframes gridMove {
        0% { transform: translateY(0); }
        100% { transform: translateY(30px); }
    }

    @keyframes bgPulse {
        0% { filter: brightness(0.25) contrast(1.1) hue-rotate(0deg); }
        100% { filter: brightness(0.4) contrast(1.2) hue-rotate(15deg); }
    }

    /* Dynamic Glowing Orbs for 3D Depth */
    .glow-orb {
        position: absolute;
        border-radius: 50%;
        filter: blur(90px);
        z-index: -2;
        opacity: 0;
        animation: orbEntrance 2s ease forwards, orbFloat 20s infinite ease-in-out alternate;
    }
    .orb-1 { width: 500px; height: 500px; background: #00f2fe; top: -100px; left: -100px; animation-delay: 0.5s, 0s; }
    .orb-2 { width: 600px; height: 600px; background: #4facfe; bottom: -200px; right: 20%; animation-delay: 1s, -5s; }
    .orb-3 { width: 400px; height: 400px; background: #9333ea; top: 40%; left: 30%; animation-delay: 1.5s, -10s; }

    @keyframes orbEntrance { to { opacity: 0.6; } }

    .hero-overlay {
        position: absolute; inset: 0; z-index: -1;
        background: linear-gradient(90deg, rgba(3,7,18,0.95) 0%, rgba(3,7,18,0.2) 100%);
    }

    @keyframes cinematicPan {
        0% { transform: scale(1) translate(0, 0); }
        100% { transform: scale(1.15) translate(-2%, -2%); }
    }
    @keyframes orbFloat {
        0% { transform: translate(0, 0) scale(1); }
        100% { transform: translate(150px, -80px) scale(1.3); }
    }

    /* --- BRAND LOGO --- */
    .brand-logo {
        position: absolute;
        top: 30px; 
        left: 40px; 
        z-index: 100;
        font-family: 'Space Grotesk', sans-serif; 
        font-size: 1.8rem; 
        font-weight: 700;
        display: inline-flex; 
        align-items: center; 
        gap: 12px;
        text-decoration: none;
        background: linear-gradient(to right, #ffffff, var(--primary-cyan), #ffffff);
        background-size: 200% auto;
        -webkit-background-clip: text; 
        -webkit-text-fill-color: transparent;
        animation: shine 3s linear infinite, dropDownFade 0.8s ease-out forwards;
    }
    .brand-logo i { 
        color: var(--primary-cyan); -webkit-text-fill-color: initial; 
        animation: pulseShield 2s infinite ease-in-out; filter: drop-shadow(0 0 15px rgba(0, 242, 254, 0.8));
    }

    @keyframes dropDownFade { to { opacity: 1; transform: translateY(0); } }
    @keyframes pulseShield { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.15); filter: drop-shadow(0 0 25px rgba(0, 242, 254, 1)); } }

    /* --- HERO CONTENT WITH CYBER ANIMATIONS --- */
    .hero-content {
        position: relative; z-index: 3;
        max-width: 650px;
        width: 100%;
        perspective: 1000px;
    }

    .hero-content h1 { 
        font-family: 'Playfair Display', serif;
        font-size: clamp(2.5rem, 4.5vw, 4.5rem); 
        line-height: 1.1; margin-bottom: 25px; 
        color: #fff; font-weight: 800; letter-spacing: -1px;
        opacity: 0; transform: rotateX(-20deg) translateY(40px);
        animation: 3DFlipIn 1.2s cubic-bezier(0.16, 1, 0.3, 1) 0.4s forwards, glitchText 5s infinite;
        position: relative;
    }
    
    @keyframes glitchText {
        0%, 96%, 100% { text-shadow: none; transform: none; }
        97% { text-shadow: 2px 0 var(--primary-cyan), -2px 0 var(--danger); transform: skewX(2deg); }
        98% { text-shadow: -2px 0 var(--primary-cyan), 2px 0 var(--danger); transform: skewX(-2deg); }
        99% { text-shadow: none; transform: none; }
    }
    
    .hero-content p { 
        font-size: clamp(1rem, 1.5vw, 1.15rem); 
        color: #cbd5e1; 
        line-height: 1.8; 
        font-weight: 300;
        opacity: 0; 
        transform: translateX(-30px);
        animation: slideRightFade 1s cubic-bezier(0.16, 1, 0.3, 1) 0.8s forwards;
        text-align: justify;
        text-justify: inter-word;
        max-width: 95%;
    }

    @keyframes 3DFlipIn { to { opacity: 1; transform: rotateX(0) translateY(0); } }
    @keyframes slideRightFade { to { opacity: 1; transform: translateX(0); } }
    @keyframes shine { to { background-position: 200% center; } }

    /* --- ELITE FROSTED GLASS DRAWER (Right Side) --- */
    .form-section {
        width: 550px; 
        flex-shrink: 0; 
        min-height: 100vh;
        background: var(--panel-bg);
        backdrop-filter: blur(40px) saturate(150%);
        -webkit-backdrop-filter: blur(40px) saturate(150%);
        border-left: 1px solid var(--panel-border);
        box-shadow: -30px 0 60px rgba(0,0,0,0.6);
        display: flex; flex-direction: column; justify-content: center;
        padding: 60px 50px; position: relative; z-index: 10;
        overflow: hidden;
        
        transform: translateX(100%);
        animation: slideInDrawer 1.2s cubic-bezier(0.16, 1, 0.3, 1) 0.3s forwards;
    }

    /* Cyber Scanner Line over form */
    .form-section::before {
        content: '';
        position: absolute;
        top: -100%;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(to bottom, transparent, rgba(0, 242, 254, 0.1), transparent);
        animation: scanline 8s linear infinite;
        pointer-events: none;
        z-index: 20;
    }

    @keyframes scanline {
        0% { top: -100%; }
        100% { top: 200%; }
    }

    @keyframes slideInDrawer { to { transform: translateX(0); } }

    .form-header { margin-bottom: 45px; text-align: left; position: relative; z-index: 21;}
    .form-header h2 { 
        font-family: 'Playfair Display', serif; font-size: 2.4rem; color: #fff; 
        font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px;
    }
    .form-header p { color: var(--primary-cyan); font-size: 1rem; font-weight: 500; letter-spacing: 1px; text-transform: uppercase;}

    /* --- FORM ELEMENTS (Staggered Load & Hover effects) --- */
    form { position: relative; z-index: 21; }
    .anim-item { opacity: 0; transform: translateY(30px) scale(0.95); animation: popUpItem 0.8s cubic-bezier(0.34, 1.56, 0.64, 1) forwards; }
    .d-1 { animation-delay: 0.9s; }
    .d-2 { animation-delay: 1.1s; }
    .d-3 { animation-delay: 1.3s; }
    .d-4 { animation-delay: 1.5s; }
    .d-5 { animation-delay: 1.7s; }
    .d-6 { animation-delay: 1.9s; }
    .d-7 { animation-delay: 2.1s; }

    @keyframes popUpItem { to { opacity: 1; transform: translateY(0) scale(1); } }

    .input-group { margin-bottom: 25px; position: relative; transition: transform 0.3s; }
    .input-group:hover { transform: translateX(5px); }

    .input-group label { 
        display: block; font-size: 0.85rem; font-weight: 600; color: #94a3b8; 
        margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px;
    }
    
    .input-wrapper { position: relative; overflow: hidden; border-radius: 12px; }
    
    /* Input border animated gradient on hover */
    .input-wrapper::after {
        content: ''; position: absolute; bottom: 0; left: 0; width: 0%; height: 2px;
        background: var(--primary-cyan); transition: width 0.4s ease;
    }
    .input-wrapper:focus-within::after { width: 100%; }

    .input-wrapper i { 
        position: absolute; left: 18px; top: 50%; transform: translateY(-50%); 
        color: #64748b; font-size: 1.1rem; transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); 
        z-index: 2;
    }
    
    input[type="text"], input[type="email"], input[type="password"] {
        width: 100%; padding: 18px 18px 18px 55px;
        background: var(--input-bg); border: 1px solid var(--input-border); 
        border-radius: 12px; font-family: 'Poppins', sans-serif; font-size: 1rem; color: #fff;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        position: relative; z-index: 1;
    }

    input:focus {
        background: rgba(255,255,255,0.06); border-color: var(--primary-cyan); outline: none;
        box-shadow: 0 0 20px rgba(0, 242, 254, 0.2), inset 0 0 10px rgba(0, 242, 254, 0.1);
        transform: translateY(-3px);
    }
    input:focus + i { color: var(--primary-cyan); transform: translateY(-50%) scale(1.2) rotate(10deg); filter: drop-shadow(0 0 8px var(--primary-cyan)); }
    input::placeholder { color: #475569; font-weight: 300; }

    .hint { font-size: 0.8rem; color: #64748b; margin-top: 8px; transition: color 0.3s; }
    .input-group:hover .hint { color: #94a3b8; }

    /* Password Eye Toggle */
    .pw-toggle-btn {
        position: absolute;
        right: 15px;
        top: 50%;
        transform: translateY(-50%);
        background: none;
        border: none;
        cursor: pointer;
        color: #64748b;
        font-size: 1.2rem;
        transition: 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        z-index: 10;
    }
    .pw-toggle-btn:hover { color: var(--primary-cyan); transform: translateY(-50%) scale(1.2); }

    /* --- LED PASSWORD STRENGTH METER --- */
    .strength-container { 
        margin-top: 15px; opacity: 0; height: 0; overflow: hidden; 
        transition: all 0.4s ease; display: flex; align-items: center; gap: 15px;
    }
    .strength-container.visible { opacity: 1; height: 12px; margin-top: 20px;}
    .strength-segments { display: flex; gap: 6px; flex: 1; height: 4px; }
    .segment { flex: 1; background: #334155; border-radius: 10px; transition: all 0.4s ease; }
    
    .strength-container[data-score="1"] .segment:nth-child(1) { background: var(--danger); box-shadow: 0 0 15px var(--danger); }
    .strength-container[data-score="2"] .segment:nth-child(1), .strength-container[data-score="2"] .segment:nth-child(2) { background: var(--warning); box-shadow: 0 0 15px var(--warning); }
    .strength-container[data-score="3"] .segment:nth-child(1), .strength-container[data-score="3"] .segment:nth-child(2), .strength-container[data-score="3"] .segment:nth-child(3) { background: var(--success); box-shadow: 0 0 15px var(--success); }
    .strength-container[data-score="4"] .segment { background: var(--primary-cyan); box-shadow: 0 0 18px var(--primary-cyan); }
    .strength-text { font-size: 0.75rem; font-weight: 700; width: 60px; text-transform: uppercase; letter-spacing: 1.5px; color: #fff;}

    /* --- LIQUID GRADIENT BUTTON WITH GLITCH HOVER --- */
    button[type="submit"] {
        width: 100%; padding: 20px; border: none; border-radius: 12px;
        background: linear-gradient(45deg, #00f2fe, #4facfe, #00f2fe, #4facfe);
        background-size: 300% 300%;
        color: #030712; font-size: 1.15rem; font-weight: 700; font-family: 'Poppins', sans-serif;
        text-transform: uppercase; letter-spacing: 1px;
        cursor: pointer; margin-top: 20px; position: relative; overflow: hidden;
        box-shadow: 0 10px 30px rgba(0, 242, 254, 0.4); 
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); 
        animation: liquidGradient 4s ease infinite;
    }
    
    @keyframes liquidGradient { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
    
    button[type="submit"]:hover { 
        transform: translateY(-5px) scale(1.02); 
        box-shadow: 0 15px 40px rgba(0, 242, 254, 0.6); 
        letter-spacing: 2px;
    }
    button[type="submit"]:active { transform: translateY(2px) scale(0.98); }
    button[type="submit"] i { transition: transform 0.3s; }
    button[type="submit"]:hover i { transform: translateX(8px); }

    .auth-footer { margin-top: 40px; text-align: center; color: var(--text-muted); font-size: 0.95rem; position: relative; z-index: 21;}
    .auth-footer a { color: #fff; font-weight: 600; text-decoration: none; border-bottom: 2px solid var(--primary-cyan); padding-bottom: 3px; transition: 0.3s; }
    .auth-footer a:hover { color: var(--primary-cyan); text-shadow: 0 0 15px rgba(0,242,254,0.7); border-color: transparent;}

    /* Responsive adjustments */
    @media (max-width: 1024px) {
        body { flex-direction: column; }
        .brand-logo { top: 20px; left: 20px; }
        .hero-section { min-height: 60vh; padding: 120px 5% 60px; text-align: center; }
        .hero-content { margin: 0 auto; }
        .hero-content h1 { transform: translateY(40px); animation: slideUpFade 1s cubic-bezier(0.16, 1, 0.3, 1) 0.4s forwards; }
        .form-section { width: 100%; min-height: auto; border-left: none; border-top: 1px solid var(--panel-border); padding: 50px 30px; animation: slideUpDrawer 1.2s cubic-bezier(0.16, 1, 0.3, 1) forwards; transform: translateY(100px); opacity: 0; }
        @keyframes slideUpDrawer { to { transform: translateY(0); opacity: 1; } }
        @keyframes slideUpFade { to { opacity: 1; transform: translateY(0); } }
    }
</style>
</head>
<body>

    <div class="hero-section">
        <div class="hero-bg"></div>
        <div class="cyber-grid"></div>
        <div class="glow-orb orb-1"></div>
        <div class="glow-orb orb-2"></div>
        <div class="glow-orb orb-3"></div>
        <div class="hero-overlay"></div>
        
        <a href="welcome.php" class="brand-logo">
            <i class="fa-solid fa-shield-halved"></i>
            PhishSafeguard
        </a>

        <div class="hero-content">
            <h1>Secure your digital perimeter.</h1>
             <p>PhishSafeguard deploys an elite AI-driven intelligence network designed to neutralize zero-day phishing attacks in milliseconds. By leveraging advanced machine learning and real-time global data, the system identifies and blocks sophisticated threats before they can breach your digital perimeter. This proactive defense grid ensures constant security by evolving alongside the world's most complex cyber-attacks. Joining this network provides you with a personalized, high-performance dashboard for an impenetrable security experience.</p>
        </div>
    </div>

    <div class="form-section">
        <div class="form-header anim-item d-1">
            <h2>Initialize Access</h2>
            <p>Deploy your security dashboard</p>
        </div>
        
        <form method="POST" action="" id="registerForm" novalidate>
            
            <div class="input-group anim-item d-2">
                <label for="username">User ID</label>
                <div class="input-wrapper">
                    <input type="text" name="username" id="username" required placeholder="Choose a unique username"
                           value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username']) : '' ?>">
                    <i class="fa-solid fa-user-astronaut"></i>
                </div>
            </div>

            <div class="input-group anim-item d-3">
                <label for="email">Encrypted Email (Optional With Number)</label>
                <div class="input-wrapper">
                    <input type="email" name="email" id="email" placeholder="name@domain.com"
                           value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '' ?>">
                    <i class="fa-solid fa-envelope"></i>
                </div>
                <div class="hint">System requires either Email or Phone verification.</div>
            </div>

            <div class="input-group anim-item d-4">
                <label for="phone">Secure Comm Line (Optional With Mail)</label>
                <div class="input-wrapper">
                    <input type="text" name="phone" id="phone" placeholder="+91 XXXXX XXXXX"
                           value="<?= isset($_POST['phone']) ? htmlspecialchars($_POST['phone']) : '' ?>">
                    <i class="fa-solid fa-phone"></i>
                </div>
            </div>

            <div class="input-group anim-item d-5">
                <label for="password">Encryption Key</label>
                <div class="input-wrapper password-wrapper">
                    <input type="password" name="password" id="password" required placeholder="Minimum 8 characters">
                    <i class="fa-solid fa-key"></i>
                    <button type="button" id="pwToggle" class="pw-toggle-btn" title="Toggle Visibility">
                        <i class="fa-solid fa-eye" id="pwIcon"></i>
                    </button>
                </div>

                <div class="strength-container" id="strengthContainer">
                    <div class="strength-segments">
                        <div class="segment"></div><div class="segment"></div>
                        <div class="segment"></div><div class="segment"></div>
                    </div>
                    <div class="strength-text" id="strengthText"></div>
                </div>
            </div>

            <div class="anim-item d-6">
                <button type="submit">Establish Uplink <i class="fa-solid fa-arrow-right" style="margin-left:8px;"></i></button>
            </div>
        </form>

        <div class="auth-footer anim-item d-7">
            Clearance already established? <a href="login.php">Authenticate Here</a>
        </div>
    </div>

<script>
    // Eye Toggle with Rotation Pop Animation
    const pwInput = document.getElementById('password');
    const pwToggle = document.getElementById('pwToggle');
    const pwIcon = document.getElementById('pwIcon');

    pwToggle.addEventListener('click', () => {
        const isPass = pwInput.getAttribute('type') === 'password';
        pwInput.setAttribute('type', isPass ? 'text' : 'password');
        
        pwIcon.style.transform = "scale(0) rotate(-180deg)";
        setTimeout(() => {
            pwIcon.className = isPass ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
            pwIcon.style.transform = "scale(1) rotate(0deg)";
        }, 150);
        pwInput.focus();
    });

    // Pro LED Strength Meter Logic
    const strengthContainer = document.getElementById('strengthContainer');
    const strengthText = document.getElementById('strengthText');

    pwInput.addEventListener('input', function() {
        const val = pwInput.value;
        if(val.length > 0) { strengthContainer.classList.add('visible'); } 
        else { strengthContainer.classList.remove('visible'); strengthContainer.setAttribute('data-score', '0'); return; }

        let score = 0;
        if (val.length >= 8) score++;
        if (/[a-z]/.test(val) && /[A-Z]/.test(val)) score++; 
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        if (val.length < 8 && score > 2) score = 2; // Penalty for short passwords

        strengthContainer.setAttribute('data-score', score);

        if (score <= 1) { strengthText.textContent = 'WEAK'; strengthText.style.color = 'var(--danger)'; } 
        else if (score === 2) { strengthText.textContent = 'FAIR'; strengthText.style.color = 'var(--warning)'; } 
        else if (score === 3) { strengthText.textContent = 'GOOD'; strengthText.style.color = 'var(--success)'; } 
        else { strengthText.textContent = 'ELITE'; strengthText.style.color = '#00f2fe'; }
    });

    // Client-side instant form validation using SweetAlert2
    document.getElementById('registerForm').addEventListener('submit', function(e) {
        const email = document.getElementById('email').value.trim();
        const phone = document.getElementById('phone').value.trim();
        const pass = document.getElementById('password').value;
        
        let err = '';
        if (email === '' && phone === '') {
            err = "Identity verification required (Email or Phone).";
        } else if (pass.length < 8) {
            err = "Encryption key must be at least 8 characters.";
        }

        if(err) {
            e.preventDefault();
            Swal.fire({
                icon: 'warning',
                title: 'Security Alert',
                text: err,
                background: 'rgba(15, 23, 42, 0.95)',
                color: '#fff',
                confirmButtonColor: '#00f2fe',
                backdrop: `rgba(3, 7, 18, 0.8)`
            });
        }
    });
</script>

<?php 
// Server-side SweetAlert2 Popups
if (!empty($msg)) {
    if ($msg_type === 'success') {
        echo "<script>
            Swal.fire({
                title: 'Uplink Established!',
                text: '" . addslashes($msg) . "',
                icon: 'success',
                background: 'rgba(15, 23, 42, 0.95)',
                color: '#00f2fe',
                showConfirmButton: false,
                timer: 2000,
                timerProgressBar: true,
                backdrop: `rgba(3, 7, 18, 0.8)`
            }).then(() => {
                window.location.href = 'login.php';
            });
        </script>";
    } else {
        echo "<script>
            Swal.fire({
                title: 'Access Denied',
                text: '" . addslashes($msg) . "',
                icon: 'error',
                background: 'rgba(15, 23, 42, 0.95)',
                color: '#fff',
                confirmButtonColor: '#ff4d4f',
                backdrop: `rgba(3, 7, 18, 0.8)`
            });
        </script>";
    }
}
?>

</body>
</html>