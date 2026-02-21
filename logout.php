<?php
// logout.php — secure session destroy + remember_token cleanup

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ---------------------------------------------------
   1) Clear all session data safely
--------------------------------------------------- */
$_SESSION = [];

/* If you store flash messages or tokens,
   you can optionally preserve one here */
// $keep = $_SESSION['flash'] ?? null;

/* ---------------------------------------------------
   2) Delete session cookie
--------------------------------------------------- */
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );
}

/* ---------------------------------------------------
   3) Destroy PHP session
--------------------------------------------------- */
session_destroy();

/* ---------------------------------------------------
   4) Clear persistent “remember me” cookie if set
--------------------------------------------------- */
if (!empty($_COOKIE['remember_token'])) {
    setcookie(
        'remember_token',
        '',
        time() - 3600,
        '/',
        '',
        isset($_SERVER['HTTPS']),
        true
    );
}

/* ---------------------------------------------------
   5) Optional flash message after logout
--------------------------------------------------- */
session_start();
$_SESSION['flash'] = 'You have been logged out successfully.';

/* ---------------------------------------------------
   6) Redirect to login page
--------------------------------------------------- */
header('Location: login.php');
exit();
?>
