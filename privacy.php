<?php require_once('init.php'); ?>
<!DOCTYPE html>
<html lang="<?php echo $_SESSION['lang']; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <title><?php echo ($_SESSION['lang'] == 'bn') ? 'গোপনীয়তা নীতি' : 'Privacy Policy'; ?> - PhishSafeguard</title>
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">

    <style>
        /* welcome.php থেকে কপি করা মূল CSS */
        :root{--bg-dark-navy:#0a192f;--bg-light-navy:#112240;--text-lightest:#ccd6f6;--text-light:#a8b2d1;--text-dark:#8892b0;--accent-cyan:#64ffda;--accent-orange:#f5a623;--border-color:rgba(100, 255, 218, 0.1);}
        *{margin:0;padding:0;box-sizing:border-box}
        html{scroll-behavior:smooth}
        body{font-family:'Poppins',sans-serif;background-color:var(--bg-dark-navy);color:var(--text-light);line-height:1.6; overflow-x: hidden;} /* Added overflow-x to prevent horizontal scroll from animations */
        .container{max-width:1100px;margin:0 auto;padding:0 25px}
        .header{padding:20px 0;position:fixed;width:100%;top:0;z-index:1000;transition:all .3s ease-in-out;background-color:rgba(10, 25, 47, 0.85);backdrop-filter:blur(10px);box-shadow:0 5px 15px rgba(0,0,0,.3);}
        .navbar{display:flex;justify-content:space-between;align-items:center}
        .logo{font-size:1.8rem;font-weight:800;color:var(--accent-cyan);text-decoration:none}
        .nav-menu{display:flex;align-items:center}
        .nav-links{list-style:none;display:flex}
        .nav-links li{margin-left:35px}
        .nav-links a{color:var(--text-lightest);text-decoration:none;font-weight:500;transition:color .3s ease}
        .nav-links a:hover{color:var(--accent-cyan)}
        .lang-selector-wrapper{position:relative;margin-left:35px;display:flex;align-items:center}
        .lang-selector-wrapper .fa-globe{color:var(--text-dark);position:absolute;left:12px;top:50%;transform:translateY(-50%);pointer-events:none}
        #language-select{-webkit-appearance:none;-moz-appearance:none;appearance:none;background-color:var(--bg-light-navy);border:1px solid var(--border-color);padding:8px 15px 8px 35px;border-radius:5px;color:var(--text-lightest);font-family:'Poppins',sans-serif;font-size:14px;cursor:pointer;transition:all .3s ease}
        #language-select:hover{border-color:var(--accent-cyan)}
        #language-select option{background:var(--bg-light-navy);color:var(--text-lightest)}
        .lang-selector-wrapper::after{content:'\f078';font-family:'Font Awesome 6 Free';font-weight:900;position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--text-dark);pointer-events:none;font-size:12px}
        .nav-buttons{display:flex;align-items:center}
        .nav-buttons a{text-decoration:none;padding:10px 22px;border-radius:5px;margin-left:15px;font-weight:500;transition:all .3s ease;border:1px solid var(--accent-cyan)}
        .btn-login{color:var(--accent-cyan)}
        .btn-login:hover{background-color:rgba(100, 255, 218, 0.1)}
        .btn-signup{background-color:var(--accent-cyan);color:var(--bg-dark-navy)}
        .btn-signup:hover{opacity:.85}
        .footer{padding:60px 0 30px;text-align:center;border-top:1px solid var(--border-color); margin-top: 100px;} /* Added margin-top */
        .footer-logo{font-size:1.8rem;font-weight:800;color:var(--accent-cyan);text-decoration:none;display:block;margin-bottom:20px}
        .footer-links{list-style:none;display:flex;justify-content:center;gap:30px;margin-bottom:20px}
        .footer-links a{color:var(--text-light);text-decoration:none;transition:color .3s ease}
        .footer-links a:hover{color:var(--accent-cyan)}
        .copyright{font-size:.9rem;color:var(--text-dark)}
        
        /* এই পেজের জন্য নতুন এবং উন্নত CSS */
        .static-page-container {
            padding-top: 150px; /* Header এর নিচে থেকে শুরু করার জন্য */
            padding-bottom: 50px;
            max-width: 800px;
            margin: 0 auto;
        }
        .static-page-container h1 {
            font-size: 2.8rem;
            color: var(--text-lightest);
            margin-bottom: 15px;
            border-bottom: 2px solid var(--accent-cyan);
            padding-bottom: 15px;
        }
        .static-page-container .last-updated {
            font-style: italic;
            color: var(--text-dark);
            margin-bottom: 40px;
        }
        .static-page-container h2 {
            font-size: 1.8rem;
            color: var(--text-lightest);
            margin-top: 40px;
            margin-bottom: 15px;
        }
        .static-page-container p, .static-page-container ul {
            line-height: 1.8;
            margin-bottom: 20px;
            color: var(--text-light);
        }
        .static-page-container ul {
            list-style-position: inside;
            padding-left: 20px;
        }
        .static-page-container li {
            margin-bottom: 10px;
        }

        /* --- দুর্দান্ত এনিমেশন --- */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* এনিমেশন প্রয়োগ */
        .animated-item {
            opacity: 0; /* ডিফল্টভাবে অদৃশ্য থাকবে */
            animation: fadeInUp 0.7s ease-out forwards;
        }

        /* বিভিন্ন এলিমেন্টে দেরি (delay) যোগ করা হয়েছে */
        .static-page-container h1 { animation-delay: 0.2s; }
        .static-page-container .last-updated { animation-delay: 0.4s; }
        .static-page-container > p:nth-of-type(1) { animation-delay: 0.6s; }
        
        /* প্রতিটি সেকশন আলাদাভাবে এনিমেট হবে */
        .content-section {
            opacity: 0;
            animation: fadeInUp 0.7s ease-out forwards;
        }

    </style>
</head>
<body>

    <header class="header">
        <nav class="navbar container">
            <a href="welcome.php" class="logo">PhishSafeguard</a>
            <div class="nav-menu">
                <ul class="nav-links">
                    <li><a href="welcome.php#features"><?php echo ($_SESSION['lang'] == 'bn') ? 'বৈশিষ্ট্য' : 'Features'; ?></a></li>
                    <li><a href="welcome.php#stats"><?php echo ($_SESSION['lang'] == 'bn') ? 'প্রভাব' : 'Impact'; ?></a></li>
                </ul>
                <div class="lang-selector-wrapper">
                    <i class="fas fa-globe"></i>
                    <select name="language" id="language-select" onchange="window.location.href='privacy.php?lang=' + this.value;">
                        <option value="en" <?php if($_SESSION['lang'] == 'en') echo 'selected'; ?>>English</option>
                        <option value="bn" <?php if($_SESSION['lang'] == 'bn') echo 'selected'; ?>>বাংলা</option>
                    </select>
                </div>
                <div class="nav-buttons">
                    <a href="login.php" class="btn-login"><?php echo ($_SESSION['lang'] == 'bn') ? 'লগইন' : 'Log In'; ?></a>
                    <a href="register.php" class="btn-signup"><?php echo ($_SESSION['lang'] == 'bn') ? 'সাইন আপ' : 'Sign Up'; ?></a>
                </div>
            </div>
        </nav>
    </header>

    <main>
        <div class="static-page-container">
            <?php if ($_SESSION['lang'] == 'bn'): ?>
                <h1 class="animated-item">গোপনীয়তা নীতি</h1>
                <p class="last-updated animated-item">শেষ আপডেট: ১২ই অক্টোবর, ২০২৫</p>
                
                <p class="animated-item">PhishSafeguard-এ স্বাগতম। আমরা আপনার গোপনীয়তাকে সম্মান করি এবং আপনার ব্যক্তিগত তথ্য সুরক্ষিত রাখতে প্রতিশ্রুতিবদ্ধ। এই নীতিটি ব্যাখ্যা করে যে আমরা কীভাবে আপনার তথ্য সংগ্রহ, ব্যবহার এবং সুরক্ষিত রাখি।</p>

                <div class="content-section" style="animation-delay: 0.8s;">
                    <h2>আমরা যে তথ্য সংগ্রহ করি</h2>
                    <p>আমরা আপনার কাছ থেকে বিভিন্ন ধরনের তথ্য সংগ্রহ করতে পারি, যার মধ্যে রয়েছে:</p>
                    <ul>
                        <li><strong>অ্যাকাউন্ট তথ্য:</strong> যখন আপনি নিবন্ধন করেন, তখন আমরা আপনার নাম, ইমেল ঠিকানা এবং পাসওয়ার্ড সংগ্রহ করি।</li>
                        <li><strong>ব্যবহারের ডেটা:</strong> আপনি কীভাবে আমাদের পরিষেবা ব্যবহার করেন, যেমন আপনার আইপি অ্যাড্রেস, ব্রাউজারের ধরন, এবং আপনি যে পৃষ্ঠাগুলি পরিদর্শন করেন, সেই সংক্রান্ত তথ্য আমরা সংগ্রহ করি।</li>
                        <li><strong>জমা দেওয়া লিঙ্ক:</strong> ফিশিং শনাক্তকরণের জন্য আপনি যে URL বা লিঙ্কগুলো আমাদের সিস্টেমে জমা দেন, আমরা সেগুলো বিশ্লেষণ ও সংরক্ষণের জন্য সংগ্রহ করি।</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.0s;">
                    <h2>আপনার তথ্য কীভাবে ব্যবহার করা হয়</h2>
                    <p>আপনার সংগৃহীত তথ্য আমরা নিম্নলিখিত উদ্দেশ্যে ব্যবহার করি:</p>
                    <ul>
                        <li>আমাদের পরিষেবা প্রদান এবং রক্ষণাবেক্ষণ করার জন্য।</li>
                        <li>আপনার অ্যাকাউন্ট পরিচালনা এবং আপনাকে সহায়তা প্রদান করার জন্য।</li>
                        <li>আমাদের পরিষেবার মান উন্নত করতে এবং নতুন বৈশিষ্ট্য তৈরি করতে।</li>
                        <li>নিরাপত্তা নিরীক্ষণ এবং প্রতারণামূলক কার্যকলাপ প্রতিরোধ করার জন্য।</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.2s;">
                    <h2>তথ্য শেয়ারিং এবং প্রকাশ</h2>
                    <p>আমরা আপনার ব্যক্তিগত তথ্য কোনো তৃতীয় পক্ষের কাছে বিক্রি বা ভাড়া দিই না। তবে, নিম্নলিখিত ক্ষেত্রে আমরা তথ্য শেয়ার করতে পারি:</p>
                    <ul>
                        <li>আইনি বাধ্যবাধকতা পূরণের জন্য, যেমন আদালতের আদেশ বা সরকারি অনুরোধের জবাবে।</li>
                        <li>আমাদের পরিষেবা প্রদানকারী, যারা আমাদের হয়ে কাজ করে (যেমন হোস্টিং পার্টনার), তাদের সাথে।</li>
                        <li>আমাদের অধিকার, সম্পত্তি বা নিরাপত্তা রক্ষা করার জন্য।</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.4s;">
                    <h2>ডেটা সুরক্ষা</h2>
                    <p>আপনার তথ্যের নিরাপত্তা আমাদের কাছে অত্যন্ত গুরুত্বপূর্ণ। আমরা আপনার ডেটা সুরক্ষিত রাখতে শিল্প-মানের নিরাপত্তা ব্যবস্থা, যেমন এনক্রিপশন এবং নিরাপদ সার্ভার ব্যবহার করি। তবে, ইন্টারনেটের মাধ্যমে কোনো তথ্য প্রেরণই ১০০% নিরাপদ নয়।</p>
                </div>
                
                <div class="content-section" style="animation-delay: 1.6s;">
                    <h2>আমাদের সাথে যোগাযোগ</h2>
                    <p>এই গোপনীয়তা নীতি সম্পর্কে আপনার কোনো প্রশ্ন বা উদ্বেগ থাকলে, অনুগ্রহ করে আমাদের সাথে <a href="mailto:hazrarupam222@gmail.com" style="color: var(--accent-cyan);">hazrarupam222@gmail.com</a>-এ ইমেল করে যোগাযোগ করুন।</p>
                </div>

            <?php else: ?>
                <h1 class="animated-item">Privacy Policy</h1>
                <p class="last-updated animated-item">Last Updated: October 12, 2025</p>

                <p class="animated-item">Welcome to PhishSafeguard. We respect your privacy and are committed to protecting your personal information. This policy explains how we collect, use, and safeguard your data.</p>

                <div class="content-section" style="animation-delay: 0.8s;">
                    <h2>Information We Collect</h2>
                    <p>We may collect several types of information from you, including:</p>
                    <ul>
                        <li><strong>Account Information:</strong> When you register, we collect your name, email address, and password.</li>
                        <li><strong>Usage Data:</strong> We gather information on how you use our service, such as your IP address, browser type, and the pages you visit.</li>
                        <li><strong>Submitted Links:</strong> We collect the URLs you submit for phishing detection to analyze and store them for research and improvement.</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.0s;">
                    <h2>How We Use Your Information</h2>
                    <p>The information we collect is used for the following purposes:</p>
                    <ul>
                        <li>To provide and maintain our service.</li>
                        <li>To manage your account and provide you with customer support.</li>
                        <li>To improve our service and develop new features.</li>
                        <li>To monitor for security and prevent fraudulent activities.</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.2s;">
                    <h2>Data Sharing and Disclosure</h2>
                    <p>We do not sell or rent your personal information to third parties. However, we may share information in the following circumstances:</p>
                    <ul>
                        <li>To comply with legal obligations, such as a court order or government request.</li>
                        <li>With our service providers who perform tasks on our behalf (e.g., hosting partners).</li>
                        <li>To protect our rights, property, or safety.</li>
                    </ul>
                </div>
                
                <div class="content-section" style="animation-delay: 1.4s;">
                    <h2>Data Security</h2>
                    <p>The security of your data is a top priority for us. We use industry-standard security measures, such as encryption and secure servers, to protect your data. However, no method of transmission over the Internet is 100% secure.</p>
                </div>

                <div class="content-section" style="animation-delay: 1.6s;">
                    <h2>Contact Us</h2>
                    <p>If you have any questions or concerns about this Privacy Policy, please contact us via email at <a href="mailto:hazrarupam222@gmail.com" style="color: var(--accent-cyan);">hazrarupam222@gmail.com</a>.</p>
                </div>

            <?php endif; ?>
        </div>
    </main>

    <footer class="footer">
        <div class="container">
            <a href="welcome.php" class="footer-logo">PhishSafeguard</a>
            <ul class="footer-links">
                <li><a href="privacy.php"><?php echo ($_SESSION['lang'] == 'bn') ? 'গোপনীয়তা নীতি' : 'Privacy Policy'; ?></a></li>
                <li><a href="terms.php"><?php echo ($_SESSION['lang'] == 'bn') ? 'ব্যবহারের শর্তাবলী' : 'Terms of Service'; ?></a></li>
                <li><a href="mailto:hazrarupam222@gmail.com"><?php echo ($_SESSION['lang'] == 'bn') ? 'যোগাযোগ' : 'Contact'; ?></a></li>
            </ul>
            <p class="copyright"><?php echo ($_SESSION['lang'] == 'bn') ? '© ২০২৫ PhishSafeguard। সর্বস্বত্ব সংরক্ষিত।' : '© 2025 PhishSafeguard. All rights reserved.'; ?></p>
        </div>
    </footer>

</body>
</html>