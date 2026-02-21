<?php
// error_reporting(0); // লাইভ সার্ভারে এটি uncomment করতে পারেন

// ব্রাউজারকে জানানো হচ্ছে যে এটি একটি JSON রেসপন্স পাঠাবে
header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // ফর্মের ডেটা গ্রহণ এবং সুরক্ষিত করা
    $name = strip_tags(trim($_POST["name"]));
    $email = filter_var(trim($_POST["email"]), FILTER_SANITIZE_EMAIL);
    $subject = strip_tags(trim($_POST["subject"]));
    $message = trim($_POST["message"]);

    // সাধারণ ভ্যালিডেশন
    if (empty($name) || empty($subject) || empty($message) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Please fill all fields correctly.']);
        exit;
    }

    // --- এখানে আপনার আসল ইমেল পাঠানোর কোড থাকবে ---
    // mail("your-email@example.com", $subject, $message, "From: $email");
    
    // ডেমো পারপাসে এবং লোকাল সার্ভারে টেস্ট করার জন্য আমরা সবসময় success পাঠাচ্ছি
    // লাইভ সার্ভারে mail() ফাংশন কাজ করবে
    echo json_encode(['success' => true]);

} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}
?>