<?php
require_once __DIR__ . '/helpers_db.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = trim($_POST['otp'] ?? '');
    $new_pass = $_POST['new_password'] ?? '';
    $confirm_pass = $_POST['confirm_password'] ?? '';

    if (!$otp) $errors[] = "Please enter OTP.";
    if (strlen($new_pass) < 6) $errors[] = "Password must be at least 6 characters.";
    if ($new_pass !== $confirm_pass) $errors[] = "Passwords do not match.";

    if (empty($errors)) {
        if (!isset($_SESSION['reset_otp'], $_SESSION['reset_user'], $_SESSION['reset_expire'])) {
            $errors[] = "No OTP session found. Please try again.";
        } elseif (time() > $_SESSION['reset_expire']) {
            $errors[] = "OTP expired. Please request again.";
        } elseif ($otp != $_SESSION['reset_otp']) {
            $errors[] = "Invalid OTP.";
        } else {
            // Update password
            $user_id = $_SESSION['reset_user'];
            $hash = password_hash($new_pass, PASSWORD_DEFAULT);

            $conn = db();
            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE id = ? LIMIT 1");
            $stmt->bind_param("si", $hash, $user_id);
            if ($stmt->execute()) {
                $success = "Password reset successful! You can now login.";
                unset($_SESSION['reset_otp'], $_SESSION['reset_user'], $_SESSION['reset_expire']);
                header("Location: login.php?reset=1");
                exit;
            } else {
                $errors[] = "Failed to update password.";
            }
            $stmt->close();
            $conn->close();
        }
    }
}
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Verify OTP</title></head>
<body>
<h2>Reset Password</h2>

<?php if (!empty($errors)): ?>
  <?php foreach ($errors as $e): ?>
    <p style="color:red;"><?php echo htmlspecialchars($e); ?></p>
  <?php endforeach; ?>
<?php endif; ?>

<?php if ($success): ?>
  <p style="color:green;"><?php echo htmlspecialchars($success); ?></p>
<?php endif; ?>

<form method="post">
  <label>Enter OTP:</label><br>
  <input type="text" name="otp" required><br><br>

  <label>New Password:</label><br>
  <input type="password" name="new_password" required><br><br>

  <label>Confirm Password:</label><br>
  <input type="password" name="confirm_password" required><br><br>

  <button type="submit">Reset Password</button>
</form>
</body>
</html>
