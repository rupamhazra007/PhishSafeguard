<?php
session_start();

// এখানে তুমি DB তে সেভ করতে পারো অথবা ইমেইল পাঠাতে পারো
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $msg = trim($_POST['message'] ?? '');

    if (isset($_POST['send'])) {
        // সাধারণ মেসেজ সেভ করা
        file_put_contents("support_logs.txt", "User: ".$_SESSION['user_id']." | Msg: $msg\n", FILE_APPEND);
        echo "<p>✅ Your message has been sent to Support Assistant.</p>";
        echo '<a href="contact.php">Go Back</a>';
    }
    elseif (isset($_POST['escalate'])) {
        // Escalation করলে ইমেইল পাঠানো যাবে (example)
        $to = "support@yourdomain.com";
        $subject = "Escalated Support Request";
        $body = "User: ".$_SESSION['user_id']."\nMessage:\n$msg";
        // mail($to, $subject, $body); // Enable when mail configured
        echo "<p>🚨 Your issue has been escalated to support team. You will get an email reply soon.</p>";
        echo '<a href="contact.php">Go Back</a>';
    }
}
else {
    header("Location: contact.php");
    exit;
}
