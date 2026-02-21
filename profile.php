<?php
session_start();

// 1. Check Login
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// 2. Database Connection
$conn = new mysqli("localhost", "root", "", "phishing_db");
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$uid = $_SESSION['user_id'];
$message = "";
$msg_type = "";

// --- Handle Form Submissions ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // A. Remove Profile Photo (Permanent Delete)
    if (isset($_POST['remove_profile_photo'])) {
        $stmt = $conn->prepare("SELECT avatar FROM users WHERE id = ?");
        $stmt->bind_param("i", $uid);
        $stmt->execute();
        $stmt->bind_result($old_avatar);
        $stmt->fetch();
        $stmt->close();

        if ($old_avatar && file_exists("uploads/".$old_avatar)) {
            unlink("uploads/".$old_avatar); // সার্ভার থেকে ডিলিট
        }

        $conn->query("UPDATE users SET avatar = NULL WHERE id = $uid"); // ডাটাবেস আপডেট
        $message = "Profile photo removed permanently."; $msg_type = "success";
    }

    // B. Update Profile Info (Permanent Update)
    if (isset($_POST['update_profile'])) {
        $new_name = trim($_POST['full_name']); 
        $new_phone = trim($_POST['phone']);
        $new_email = trim($_POST['email']);
        $new_website = trim($_POST['website']);
        
        // Image Upload Logic
        if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] == 0) {
            $allowed = ['jpg', 'jpeg', 'png', 'gif'];
            $filename = $_FILES['profile_image']['name'];
            $filesize = $_FILES['profile_image']['size'];
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            
            if (in_array($ext, $allowed) && $filesize < 5000000) {
                $new_filename = "user_" . $uid . "_" . time() . "." . $ext;
                $upload_path = "uploads/" . $new_filename;
                
                if (!is_dir('uploads')) mkdir('uploads', 0777, true);
                
                if (move_uploaded_file($_FILES['profile_image']['tmp_name'], $upload_path)) {
                    // Delete old image
                    $stmt = $conn->prepare("SELECT avatar FROM users WHERE id = ?");
                    $stmt->bind_param("i", $uid);
                    $stmt->execute();
                    $stmt->bind_result($old_avatar);
                    $stmt->fetch();
                    $stmt->close();
                    if ($old_avatar && file_exists("uploads/".$old_avatar)) unlink("uploads/".$old_avatar);
                    
                    // Save new image path permanently
                    $upd = $conn->prepare("UPDATE users SET avatar = ? WHERE id = ?");
                    $upd->bind_param("si", $new_filename, $uid);
                    $upd->execute(); $upd->close();
                }
            }
        }

        // Text Update Logic
        $stmt = $conn->prepare("UPDATE users SET full_name = ?, phone = NULLIF(?, ''), email = ?, website = ? WHERE id = ?");
        
        if ($stmt) {
            $stmt->bind_param("ssssi", $new_name, $new_phone, $new_email, $new_website, $uid);
            
            try {
                if ($stmt->execute()) { 
                    $message = "Profile updated permanently!"; 
                    $msg_type = "success"; 
                    
                    // Session Update: সাথে সাথে সব জায়গায় নাম চেঞ্জ দেখাবে
                    if (!empty($new_name)) {
                        $_SESSION['username'] = $new_name; 
                    }
                } else { 
                    $message = "Error updating profile."; 
                    $msg_type = "error"; 
                }
            } catch (mysqli_sql_exception $e) {
                // Duplicate handling (Phone/Email)
                if ($e->getCode() == 1062) { 
                    if (strpos($e->getMessage(), 'phone') !== false) $message = "Error: This phone number is already taken.";
                    elseif (strpos($e->getMessage(), 'email') !== false) $message = "Error: This email is already taken.";
                    else $message = "Error: Duplicate entry found.";
                } else {
                    $message = "Database error: " . $e->getMessage();
                }
                $msg_type = "error";
            }
            $stmt->close();
        }
    }

    // C. Change Password (Secure & Permanent)
    if (isset($_POST['update_password'])) {
        $current_pass = $_POST['current_password'];
        $new_pass = $_POST['new_password'];
        $confirm_pass = $_POST['confirm_password'];
        
        if ($new_pass === $confirm_pass) {
            // ১. বর্তমান পাসওয়ার্ডটি ডাটাবেস থেকে আনি
            $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->bind_param("i", $uid);
            $stmt->execute();
            $stmt->bind_result($db_hash);
            $stmt->fetch();
            $stmt->close();

            // ২. বর্তমান পাসওয়ার্ড চেক করি
            if (password_verify($current_pass, $db_hash)) {
                // ৩. নতুন পাসওয়ার্ড শক্তিশালী এনক্রিপশন (Hash) করি
                $new_password_hash = password_hash($new_pass, PASSWORD_DEFAULT);
                
                // ৪. ডাটাবেসে আপডেট করি
                $upd = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                $upd->bind_param("si", $new_password_hash, $uid);
                
                if($upd->execute()) {
                    $message = "Password updated securely!"; $msg_type = "success";
                } else {
                    $message = "Database Error."; $msg_type = "error";
                }
                $upd->close();
            } else { 
                $message = "Wrong current password."; $msg_type = "error"; 
            }
        } else { $message = "New passwords do not match."; $msg_type = "error"; }
    }

    // D. Delete Account (Permanent Delete)
    if (isset($_POST['delete_account'])) {
        $del_pass = $_POST['delete_password'];
        $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
        $stmt->bind_param("i", $uid);
        $stmt->execute();
        $stmt->bind_result($db_hash);
        $stmt->fetch();
        $stmt->close();
        
        if (password_verify($del_pass, $db_hash)) {
            // সব ডিলিট করে দিচ্ছি
            $conn->query("DELETE FROM users WHERE id = $uid");
            $conn->query("DELETE FROM login_logs WHERE user_id = $uid");
            
            // সেশন ধ্বংস করে লগিন পেজে পাঠানো
            session_destroy();
            header("Location: login.php?msg=deleted");
            exit();
        } else { $message = "Wrong password."; $msg_type = "error"; }
    }
}

// --- Fetch User Data ---
$sql = "SELECT * FROM users WHERE id = $uid";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    
    $username_db = $row['username'];  
    $fullname_db = isset($row['full_name']) ? $row['full_name'] : ''; 
    
    $email = $row['email'];
    $phone = isset($row['phone']) ? $row['phone'] : '';
    $website = isset($row['website']) ? $row['website'] : '';
    $status = isset($row['status']) ? $row['status'] : 'active';
    $is_premium = isset($row['is_premium']) ? $row['is_premium'] : 0;
    $avatar = isset($row['avatar']) ? $row['avatar'] : '';
    $api_key = isset($row['api_key']) ? $row['api_key'] : '';
    $scan_usage = isset($row['scan_usage']) ? $row['scan_usage'] : 0;
    $scan_limit = isset($row['scan_limit']) ? $row['scan_limit'] : 10;
} else {
    session_destroy();
    header("Location: login.php");
    exit();
}

// --- NAME DISPLAY LOGIC (Consistent with Index) ---
$real_name = "";
if (!empty($fullname_db) && $fullname_db !== "User Name") {
    $real_name = htmlspecialchars($fullname_db);
} elseif (isset($_SESSION['username']) && !empty($_SESSION['username'])) {
    $real_name = htmlspecialchars($_SESSION['username']);
} else {
    $real_name = htmlspecialchars($username_db);
}

$display_header_name = $real_name;
$input_value_name    = $real_name;

// --- API Key Generation ---
if (empty($api_key)) {
    $api_key = "sk_" . bin2hex(random_bytes(16));
    $conn->query("UPDATE users SET api_key = '$api_key' WHERE id = $uid");
}

$usage_percent = ($scan_limit > 0) ? round(($scan_usage / $scan_limit) * 100) : 0;

$logs = [];
$res = $conn->query("SELECT ip_address, browser, login_time FROM login_logs WHERE user_id = $uid ORDER BY login_time DESC LIMIT 5");
if ($res) while ($r = $res->fetch_assoc()) $logs[] = $r;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo $display_header_name; ?> - Profile</title>
    
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,400;0,500;0,600;1,400&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400&display=swap" rel="stylesheet">
    
    <style>
        /* --- STYLES --- */
        :root { --primary-color: #2575fc; --secondary-color: #6a11cb; --accent-gold: #D4AF37; --glass-bg: rgba(255, 255, 255, 0.05); --glass-border: rgba(255, 255, 255, 0.1); --text-main: #f0f0f0; --text-muted: rgba(255, 255, 255, 0.6); }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Lora', serif; display: flex; min-height: 100vh; background: linear-gradient(125deg, #0f2027, #203a43, #2c5364); background-size: 400% 400%; animation: gradientBG 15s ease infinite; color: var(--text-main); overflow-x: hidden; }
        @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        h1, h2, h3, h4 { font-family: 'Playfair Display', serif; }
        
        .sidebar { width: 280px; margin: 20px; background: rgba(0, 0, 0, 0.2); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: 25px; padding: 40px 25px; height: calc(100vh - 40px); position: fixed; z-index: 10; display: flex; flex-direction: column; box-shadow: 0 15px 35px rgba(0,0,0,0.3); }
        .logo-text { text-align: center; margin-bottom: 60px; font-weight: 700; font-size: 28px; background: linear-gradient(to right, #fff, var(--primary-color)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 1px; }
        .sidebar a { color: var(--text-muted); text-decoration: none; padding: 18px 25px; display: flex; align-items: center; border-radius: 15px; margin-bottom: 12px; font-size: 17px; letter-spacing: 0.5px; transition: all 0.4s cubic-bezier(0.25, 0.8, 0.25, 1); border-left: 3px solid transparent; }
        .sidebar a:hover, .sidebar a.active { background: linear-gradient(90deg, rgba(255,255,255,0.05), transparent); color: #fff; border-left-color: var(--primary-color); transform: translateX(5px); padding-left: 30px; text-shadow: 0 0 10px rgba(37, 117, 252, 0.5); }
        .sidebar i { margin-right: 20px; width: 20px; text-align: center; font-size: 18px; }
        .sidebar .logout { margin-top: auto; color: #ff453a; }
        .sidebar .logout:hover { background: rgba(255, 69, 58, 0.1); border-left-color: #ff453a; color: #ff6b6b; }
        
        .main { flex: 1; margin-left: 320px; padding: 40px; z-index: 2; position: relative; }
        .glass-card { background: var(--glass-bg); backdrop-filter: blur(30px); -webkit-backdrop-filter: blur(30px); border: 1px solid var(--glass-border); border-radius: 24px; padding: 40px; box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2); margin-bottom: 40px; position: relative; overflow: hidden; transition: transform 0.6s cubic-bezier(0.165, 0.84, 0.44, 1), box-shadow 0.6s ease; }
        .glass-card::before { content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 100%; background: linear-gradient(to right, transparent, rgba(255,255,255,0.05), transparent); transform: skewX(-25deg); transition: 0.5s; pointer-events: none; }
        .glass-card:hover::before { left: 150%; transition: 0.8s ease-in-out; }
        .glass-card:hover { transform: translateY(-5px); box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3); border-color: rgba(255, 255, 255, 0.2); }
        
        .hero-section { display: flex; align-items: center; gap: 50px; }
        .avatar-container { position: relative; width: 150px; height: 150px; flex-shrink: 0; }
        .avatar-img { width: 100%; height: 100%; object-fit: cover; border-radius: 50%; border: 4px solid rgba(255,255,255,0.1); box-shadow: 0 0 30px rgba(37, 117, 252, 0.3); transition: transform 0.6s ease; }
        .glass-card:hover .avatar-img { transform: scale(1.05); border-color: var(--primary-color); }
        .avatar-upload-label { position: absolute; bottom: 8px; right: 8px; background: var(--primary-color); width: 42px; height: 42px; border-radius: 50%; display: flex; align-items: center; justify-content: center; cursor: pointer; border: 3px solid #1a1a2e; transition: 0.4s; box-shadow: 0 5px 15px rgba(0,0,0,0.5); }
        .avatar-upload-label:hover { transform: rotate(15deg) scale(1.1); background: #fff; color: var(--primary-color); }
        .avatar-upload-label i { color: #fff; transition: 0.3s; }
        .avatar-upload-label:hover i { color: var(--primary-color); }
        .remove-avatar-btn { position: absolute; top: 0; right: 0; background: #ff453a; width: 32px; height: 32px; border-radius: 50%; border: 3px solid #1a1a2e; color: white; cursor: pointer; transition: 0.3s; display: flex; align-items: center; justify-content: center; }
        .remove-avatar-btn:hover { background: #ff0000; transform: scale(1.1); }
        
        .profile-name { font-size: 48px; font-weight: 600; margin-bottom: 10px; background: linear-gradient(to right, #fff, #e0e0e0, var(--accent-gold)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: -1px; }
        .input-group { margin-bottom: 30px; position: relative; }
        label { font-size: 14px; color: var(--accent-gold); margin-bottom: 10px; display: block; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }
        input { width: 100%; padding: 18px 18px 18px 55px; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; color: #fff; font-size: 16px; outline: none; font-family: 'Lora', serif; transition: all 0.4s ease; }
        input:focus { border-color: var(--primary-color); background: rgba(0, 0, 0, 0.5); box-shadow: 0 0 25px rgba(37, 117, 252, 0.15); }
        .field-icon { position: absolute; left: 20px; top: 52px; color: rgba(255,255,255,0.3); font-size: 18px; transition: 0.4s; }
        input:focus ~ .field-icon { color: var(--primary-color); transform: scale(1.1); }
        .eye-btn { position: absolute; right: 20px; top: 52px; color: rgba(255,255,255,0.3); cursor: pointer; transition: 0.3s; }
        .eye-btn:hover { color: #fff; }
        
        /* Strength Bar CSS */
        .strength-line-bg { width: 100%; height: 4px; background: rgba(255, 255, 255, 0.1); border-radius: 2px; overflow: hidden; display: none; margin-top: 8px; }
        .strength-line-fill { height: 100%; width: 0%; transition: width 0.4s ease, background-color 0.4s ease; box-shadow: 0 0 8px currentColor; }
        .strength-text { font-size: 12px; font-family: 'Playfair Display', serif; letter-spacing: 0.5px; margin-top: 5px; text-align: right; font-weight: 600; transition: color 0.3s ease; min-height: 18px; }
        .bg-weak { background-color: #ff453a; box-shadow: 0 0 10px #ff453a; }
        .bg-medium { background-color: #ff9f0a; box-shadow: 0 0 10px #ff9f0a; }
        .bg-good { background-color: #32d74b; box-shadow: 0 0 10px #32d74b; }
        .bg-strong { background-color: #30d158; box-shadow: 0 0 15px #30d158; }
        .text-weak { color: #ff453a; }
        .text-medium { color: #ff9f0a; }
        .text-good { color: #32d74b; }
        .text-strong { color: #30d158; }

        .btn-primary { width: 100%; padding: 18px; background: linear-gradient(135deg, var(--primary-color), var(--secondary-color)); color: white; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; letter-spacing: 1px; cursor: pointer; position: relative; overflow: hidden; font-family: 'Playfair Display', serif; box-shadow: 0 10px 25px rgba(37, 117, 252, 0.3); transition: all 0.4s ease; }
        .btn-primary:hover { transform: translateY(-3px); box-shadow: 0 15px 35px rgba(37, 117, 252, 0.5); }
        .btn-danger { width: 100%; padding: 16px; background: transparent; color: #ff453a; border: 2px solid rgba(255, 69, 58, 0.3); border-radius: 12px; font-weight: 600; cursor: pointer; letter-spacing: 1px; font-family: 'Playfair Display', serif; transition: 0.4s; }
        .btn-danger:hover { background: rgba(255, 69, 58, 0.1); border-color: #ff453a; box-shadow: 0 0 20px rgba(255, 69, 58, 0.2); }
        .api-wrapper input { font-family: 'Courier New', monospace; letter-spacing: 2px; color: var(--accent-gold); background: rgba(0,0,0,0.6); border: 1px dashed var(--accent-gold); }
        .copy-btn { background: rgba(212, 175, 55, 0.1); border: 1px solid var(--accent-gold); border-radius: 12px; width: 60px; cursor: pointer; color: var(--accent-gold); transition: all 0.3s ease; display: flex; align-items: center; justify-content: center; }
        .copy-btn:hover { background: var(--accent-gold); color: #000; box-shadow: 0 0 15px var(--accent-gold); }
        .grid-container { display: grid; grid-template-columns: 1.2fr 2fr; gap: 40px; }
        table { width: 100%; border-collapse: separate; border-spacing: 0 12px; }
        td { padding: 20px; background: rgba(255,255,255,0.03); color: #e0e0e0; font-size: 16px; border-top: 1px solid rgba(255,255,255,0.05); border-bottom: 1px solid rgba(255,255,255,0.05); transition: 0.3s; }
        tr:hover td { background: rgba(255,255,255,0.08); color: #fff; transform: scale(1.01); }
        td:first-child { border-radius: 15px 0 0 15px; border-left: 1px solid rgba(255,255,255,0.05); }
        td:last-child { border-radius: 0 15px 15px 0; border-right: 1px solid rgba(255,255,255,0.05); }
        @media(max-width: 1100px) { .grid-container { grid-template-columns: 1fr; } .main { margin-left: 0; padding: 20px; } .sidebar { display: none; } .hero-section { flex-direction: column; text-align: center; } }
        .alert { padding: 15px 20px; border-radius: 12px; margin-bottom: 30px; display: flex; align-items: center; gap: 15px; animation: fadeIn 0.8s ease; }
        .success { background: rgba(48, 209, 88, 0.15); border: 1px solid #30d158; color: #30d158; }
        .error { background: rgba(255, 69, 58, 0.15); border: 1px solid #ff453a; color: #ff453a; }
    </style>
</head>
<body>

    <div class="sidebar">
        <div class="logo-text">PhishSafeguard</div>
        <a href="index.php"><i class="fa fa-home"></i> Dashboard</a>
        <a href="#" class="active"><i class="fa fa-user-astronaut"></i> My Profile</a>
        <a href="logout.php" class="logout"><i class="fa fa-arrow-right-from-bracket"></i> Logout</a>
    </div>

    <div class="main">
        
        <?php if($message): ?>
            <div class="alert <?php echo $msg_type; ?>">
                <i class="fa <?php echo $msg_type=='success'?'fa-check-circle':'fa-triangle-exclamation'; ?>"></i>
                <span><?php echo $message; ?></span>
            </div>
        <?php endif; ?>

        <div class="glass-card hero-section" data-aos="fade-down" data-aos-duration="1200">
            <form id="avatarForm" method="POST" enctype="multipart/form-data" style="position:relative;">
                <div class="avatar-container">
                    <?php 
                        $img_src = (!empty($avatar) && file_exists("uploads/".$avatar)) ? "uploads/".$avatar : "https://ui-avatars.com/api/?name=".urlencode($display_header_name)."&background=0D8ABC&color=fff&size=128";
                    ?>
                    <img src="<?php echo $img_src; ?>?t=<?php echo time(); ?>" class="avatar-img" id="previewImg">
                    
                    <label for="profile_image" class="avatar-upload-label" title="Change Photo">
                        <i class="fa fa-camera"></i>
                    </label>
                    <input type="file" id="profile_image" name="profile_image" style="display:none;" accept="image/*" onchange="document.getElementById('saveProfileBtn').click();">
                    
                    <?php if(!empty($avatar)): ?>
                    <button type="submit" name="remove_profile_photo" class="remove-avatar-btn" title="Remove Photo" onclick="return confirm('Remove profile photo?');">
                        <i class="fa fa-xmark"></i>
                    </button>
                    <?php endif; ?>
                </div>
                
                <input type="hidden" name="full_name" value="<?php echo $input_value_name; ?>">
                <input type="hidden" name="phone" value="<?php echo htmlspecialchars($phone); ?>">
                <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">
                <input type="hidden" name="website" value="<?php echo htmlspecialchars($website); ?>">
                <input type="submit" name="update_profile" id="saveProfileBtn" style="display:none;">
            </form>

            <div style="flex:1;">
                <h1 class="profile-name"><?php echo $display_header_name; ?></h1>
                
                <div style="font-size:16px; color: var(--text-muted); display:flex; gap:25px; flex-wrap:wrap; margin-bottom: 25px;">
                    <span><i class="fa fa-envelope" style="color:var(--primary-color); margin-right:8px;"></i> <?php echo htmlspecialchars($email); ?></span>
                    <?php if(!empty($phone)): ?><span><i class="fa fa-phone" style="color:#30d158; margin-right:8px;"></i> <?php echo htmlspecialchars($phone); ?></span><?php endif; ?>
                    <?php if(!empty($website)): ?><span><a href="<?php echo htmlspecialchars($website); ?>" target="_blank" style="color:#ccc; text-decoration:none; transition:0.3s;" onmouseover="this.style.color='#fff'" onmouseout="this.style.color='#ccc'"><i class="fa fa-globe" style="color:var(--accent-gold); margin-right:8px;"></i> Website</a></span><?php endif; ?>
                </div>

                <div style="display:flex; gap:15px;">
                    <div style="padding: 6px 15px; border-radius: 30px; background: rgba(255,255,255,0.1); font-size: 13px; text-transform: uppercase; letter-spacing: 1px;"><i class="fa fa-circle" style="font-size:8px; color: #30d158;"></i> <?php echo ucfirst($status); ?></div>
                    <?php if($is_premium): ?><div style="padding: 6px 15px; border-radius: 30px; background: rgba(212, 175, 55, 0.15); border: 1px solid var(--accent-gold); color: var(--accent-gold); font-size: 13px; font-weight: bold;"><i class="fa fa-crown"></i> Premium</div><?php endif; ?>
                </div>
            </div>

            <div style="text-align:right; min-width: 240px; display: none; @media(min-width: 768px){ display: block; }">
                <div style="font-size:13px; color: var(--accent-gold); margin-bottom:10px; font-family: 'Playfair Display'; letter-spacing: 1px;">DAILY USAGE</div>
                <div style="font-size:32px; font-weight:500; font-family: 'Playfair Display';"><?php echo $scan_usage; ?> <span style="font-size:18px; color:rgba(255,255,255,0.3);">/ <?php echo $scan_limit; ?></span></div>
                <div style="width:100%; height:4px; background:rgba(255,255,255,0.1); border-radius:10px; margin-top:15px; overflow:hidden;">
                    <div style="height:100%; width:<?php echo $usage_percent; ?>%; background:linear-gradient(90deg, var(--primary-color), var(--secondary-color)); box-shadow: 0 0 10px var(--primary-color);"></div>
                </div>
            </div>
        </div>

        <div class="grid-container">
            
            <div style="display:flex; flex-direction:column;">
                
                <div class="glass-card" data-aos="fade-right" data-aos-delay="200" data-aos-duration="1000">
                    <div style="margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center; gap: 12px;">
                        <i class="fa fa-user-pen" style="color: var(--primary-color);"></i> <h3>Edit Details</h3>
                    </div>
                    <form method="POST">
                        <div class="input-group">
                            <label>Full Name</label>
                            <i class="fa fa-user field-icon"></i>
                            <input type="text" name="full_name" value="<?php echo $input_value_name; ?>" required>
                        </div>
                        <div class="input-group">
                            <label>Email Address</label>
                            <i class="fa fa-envelope field-icon"></i>
                            <input type="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
                        </div>
                        <div class="input-group">
                            <label>Phone Number</label>
                            <i class="fa fa-phone field-icon"></i>
                            <input type="text" name="phone" value="<?php echo htmlspecialchars($phone); ?>">
                        </div>
                        <div class="input-group">
                            <label>Website / Social</label>
                            <i class="fa fa-link field-icon"></i>
                            <input type="url" name="website" value="<?php echo htmlspecialchars($website); ?>" placeholder="https://">
                        </div>
                        <button type="submit" name="update_profile" class="btn-primary">Save Changes</button>
                    </form>
                </div>

                <div class="glass-card" style="border-color: rgba(255, 69, 58, 0.2);" data-aos="fade-right" data-aos-delay="300" data-aos-duration="1000">
                    <div style="margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,69,58,0.2); display: flex; align-items: center; gap: 12px;">
                        <i class="fa fa-skull-crossbones" style="color: #ff453a;"></i> <h3 style="color: #ff453a;">Danger Zone</h3>
                    </div>
                    <form method="POST" onsubmit="return confirm('Are you sure? This action is irreversible.');">
                        <p style="font-size:14px; color:rgba(255,255,255,0.5); margin-bottom:20px; font-style: italic;">To delete your account permanently, please verify your identity.</p>
                        <div class="input-group">
                            <label style="color:#ff453a;">Confirm Password</label>
                            <i class="fa fa-lock field-icon" style="color:#ff453a;"></i>
                            <input type="password" name="delete_password" id="del_pass" required style="border-color: rgba(255, 69, 58, 0.3);">
                            <i class="fa fa-eye eye-btn" onclick="togglePass('del_pass', this)"></i>
                        </div>
                        <button type="submit" name="delete_account" class="btn-danger">Delete Account</button>
                    </form>
                </div>
            </div>

            <div style="display:flex; flex-direction:column;">
                
                <div class="glass-card" data-aos="fade-left" data-aos-delay="200" data-aos-duration="1000">
                    <div style="margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center; justify-content: space-between;">
                        <div style="display:flex; gap:10px; align-items:center;">
                            <i class="fa fa-code" style="color: var(--accent-gold);"></i> <h3>Developer API</h3>
                        </div>
                        <?php if($is_premium): ?><span style="background:var(--accent-gold); color:#000; font-size:11px; padding:3px 8px; border-radius:4px; font-weight:bold;">ACTIVE</span><?php endif; ?>
                    </div>
                    
                    <div class="input-group" style="margin-bottom:0;">
                        <label>Your API Key</label>
                        <div class="api-wrapper" style="display: flex; gap: 10px;">
                            <input type="text" value="************************" readonly style="cursor: default;">
                            <input type="hidden" id="realApiKey" value="<?php echo htmlspecialchars($api_key); ?>">
                            <button type="button" class="copy-btn" onclick="copyApi()" title="Copy Key"><i class="fa fa-copy"></i></button>
                        </div>
                    </div>
                </div>

                <div class="glass-card" data-aos="fade-left" data-aos-delay="300" data-aos-duration="1000">
                    <div style="margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center; gap: 12px;">
                        <i class="fa fa-shield-halved" style="color: #fff;"></i> <h3>Security</h3>
                    </div>
                    <form method="POST">
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:25px;">
                            
                            <div class="input-group">
                                <label>New Password</label>
                                <i class="fa fa-key field-icon"></i>
                                <input type="password" name="new_password" id="n_pass" required onkeyup="checkPasswordStrength(this.value)">
                                <i class="fa fa-eye eye-btn" onclick="togglePass('n_pass', this)"></i>
                                
                                <div class="strength-line-bg" id="strengthBg">
                                    <div class="strength-line-fill" id="strengthBar"></div>
                                </div>
                                <div id="strengthText" class="strength-text"></div>
                            </div>

                            <div class="input-group">
                                <label>Confirm</label>
                                <i class="fa fa-check-double field-icon"></i>
                                <input type="password" name="confirm_password" id="c_pass" required>
                                <i class="fa fa-eye eye-btn" onclick="togglePass('c_pass', this)"></i>
                            </div>
                        </div>
                        <div class="input-group">
                            <label>Current Password</label>
                            <i class="fa fa-unlock field-icon"></i>
                            <input type="password" name="current_password" id="cur_pass" required>
                            <i class="fa fa-eye eye-btn" onclick="togglePass('cur_pass', this)"></i>
                        </div>
                        <button type="submit" name="update_password" class="btn-primary">Update Password</button>
                    </form>
                </div>

                <div class="glass-card" style="flex:1;" data-aos="fade-up" data-aos-delay="400" data-aos-duration="1000">
                    <div style="margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center; gap: 12px;">
                        <i class="fa fa-history" style="color: #ccc;"></i> <h3>Login Activity</h3>
                    </div>
                    <table style="width:100%;">
                        <tbody>
                            <?php if(count($logs) > 0): foreach($logs as $log): ?>
                            <tr>
                                <td>
                                    <i class="fa fa-desktop" style="color:rgba(255,255,255,0.4); margin-right:10px;"></i> 
                                    <?php echo htmlspecialchars(explode(' ', $log['browser'])[0]); ?>
                                </td>
                                <td style="color: var(--accent-gold); font-family: 'Courier New';"><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                <td style="color:#aaa; font-size:14px; text-align:right; font-style: italic;">
                                    <?php echo date('M d, H:i', strtotime($log['login_time'])); ?>
                                </td>
                            </tr>
                            <?php endforeach; else: ?>
                                <tr><td colspan="3" style="text-align:center; padding:25px; color:#777; font-style: italic;">No recent activity found</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

            </div>
        </div>
    </div>

    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script>
        AOS.init({ duration: 1000, easing: 'ease-out-cubic', once: true });

        function togglePass(id, icon) {
            const input = document.getElementById(id);
            if (input.type === "password") {
                input.type = "text";
                icon.classList.remove("fa-eye"); icon.classList.add("fa-eye-slash");
                icon.style.color = "#2575fc";
            } else {
                input.type = "password";
                icon.classList.remove("fa-eye-slash"); icon.classList.add("fa-eye");
                icon.style.color = "rgba(255,255,255,0.3)";
            }
        }

        function copyApi() {
            const realKey = document.getElementById("realApiKey").value;
            navigator.clipboard.writeText(realKey).then(() => {
                const btn = document.querySelector('.copy-btn');
                const originalHTML = btn.innerHTML;
                btn.innerHTML = '<i class="fa fa-check"></i>';
                setTimeout(() => btn.innerHTML = originalHTML, 2000);
            });
        }
        
        // Password Strength Checker Logic
        function checkPasswordStrength(password) {
            const bg = document.getElementById('strengthBg');
            const bar = document.getElementById('strengthBar');
            const text = document.getElementById('strengthText');

            if (password.length === 0) {
                bg.style.display = 'none';
                text.innerText = "";
                return;
            } else {
                bg.style.display = 'block';
            }

            let score = 0;
            if (password.length > 5) score++;
            if (password.length > 8) score++;
            if (/[A-Z]/.test(password)) score++;
            if (/[0-9]/.test(password)) score++;
            if (/[^A-Za-z0-9]/.test(password)) score++;

            let width = (score / 5) * 100;
            bar.style.width = width + '%';

            // Reset classes
            bar.className = 'strength-line-fill';
            text.className = 'strength-text';

            if (score <= 2) {
                bar.classList.add('bg-weak'); text.classList.add('text-weak'); text.innerText = "Weak";
            } else if (score == 3) {
                bar.classList.add('bg-medium'); text.classList.add('text-medium'); text.innerText = "Medium";
            } else if (score == 4) {
                bar.classList.add('bg-good'); text.classList.add('text-good'); text.innerText = "Good";
            } else {
                bar.classList.add('bg-strong'); text.classList.add('text-strong'); text.innerText = "Very Strong";
            }
        }

        document.getElementById('profile_image').addEventListener('change', function(e) {
            const reader = new FileReader();
            reader.onload = function(evt) { document.getElementById('previewImg').src = evt.target.result; }
            reader.readAsDataURL(this.files[0]);
        });
    </script>
</body>
</html>