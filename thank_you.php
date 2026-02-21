<?php require_once('init.php'); ?>
<!DOCTYPE html>
<html lang="<?php echo $_SESSION['lang']; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo ($_SESSION['lang'] == 'bn') ? 'ধন্যবাদ' : 'Thank You'; ?> - PhishSafeguard</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display.swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        :root {
            --bg-dark-navy: #0a192f;
            --bg-light-navy: #112240;
            --text-lightest: #ccd6f6;
            --accent-cyan: #64ffda;
        }
        body {
            font-family: 'Poppins', sans-serif;
            background-color: var(--bg-dark-navy);
            color: var(--text-lightest);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }
        .thank-you-container {
            background-color: var(--bg-light-navy);
            padding: 50px 60px;
            border-radius: 10px;
            border-top: 4px solid var(--accent-cyan);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            max-width: 500px;
        }
        .icon {
            font-size: 4rem;
            color: var(--accent-cyan);
            margin-bottom: 20px;
        }
        h1 {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        p {
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 30px;
        }
        a.button {
            background-color: var(--accent-cyan);
            color: var(--bg-dark-navy);
            text-decoration: none;
            padding: 12px 25px;
            border-radius: 5px;
            font-weight: 600;
            transition: opacity 0.3s ease;
        }
        a.button:hover {
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="thank-you-container">
        <div class="icon"><i class="fas fa-check-circle"></i></div>
        <?php if ($_SESSION['lang'] == 'bn'): ?>
            <h1>ধন্যবাদ!</h1>
            <p>আপনার বার্তাটি সফলভাবে পাঠানো হয়েছে। আমরা শীঘ্রই আপনার সাথে যোগাযোগ করব।</p>
            <a href="support.php" class="button">সাপোর্ট পেজে ফিরে যান</a>
        <?php else: ?>
            <h1>Thank You!</h1>
            <p>Your message has been sent successfully. We will get back to you shortly.</p>
            <a href="support.php" class="button">Back to Support Page</a>
        <?php endif; ?>
    </div>
</body>
</html>