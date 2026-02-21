<?php
// user_dashboard.php — minimal dashboard to verify session persistence
session_start();

// Debug log to server error log (optional)
// error_log("DASHBOARD SESSION: ".json_encode($_SESSION));

if (!isset($_SESSION['user_id'])) {
    // not logged in -> back to login
    header('Location: login.php');
    exit();
}
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Dashboard</title></head>
<body>
  <h2>Welcome, <?= htmlspecialchars($_SESSION['username'] ?? 'User') ?></h2>
  <p>Your user_id: <?= htmlspecialchars($_SESSION['user_id']) ?></p>
  <p><a href="logout.php">Logout</a></p>
  <hr>
  <p>Session dump (safe):</p>
  <pre><?= htmlspecialchars(json_encode($_SESSION, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)) ?></pre>
</body>
</html>
