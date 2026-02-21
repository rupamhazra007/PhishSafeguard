<?php
// plan_sync.php — keep session plan accurate with DB
if (session_status() === PHP_SESSION_NONE) session_start();

if (!empty($_SESSION['user_id'])) {
    $needSync = false;

    // Refresh every 10 mins or if missing
    if (empty($_SESSION['subscribed_plan']) || empty($_SESSION['plan_sync_at'])) {
        $needSync = true;
    } elseif (time() - (int)$_SESSION['plan_sync_at'] > 600) {
        $needSync = true;
    }

    if ($needSync) {
        $conn = @new mysqli("localhost", "root", "", "phishing_db");
        if (!$conn->connect_error) {
            $stmt = $conn->prepare("SELECT COALESCE(plan_name,'Basic'), COALESCE(is_premium,0) FROM users WHERE id=? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param("i", $_SESSION['user_id']);
                $stmt->execute();
                $stmt->bind_result($plan_name, $is_premium);
                if ($stmt->fetch()) {
                    $_SESSION['subscribed_plan'] = $plan_name;
                    $_SESSION['user_tier']       = $plan_name;
                    $_SESSION['is_premium']      = (int)$is_premium;
                    $_SESSION['plan_sync_at']    = time();
                }
                $stmt->close();
            }
            $conn->close();
        }
    }
} else {
    // user not logged in → reset any stale premium data
    unset($_SESSION['subscribed_plan'], $_SESSION['user_tier'], $_SESSION['is_premium'], $_SESSION['plan_sync_at']);
}
?>
