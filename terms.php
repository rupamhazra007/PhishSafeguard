<?php require_once('init.php'); ?>
<!DOCTYPE html>
<html lang="<?php echo $_SESSION['lang']; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <title><?php echo ($_SESSION['lang'] == 'bn') ? 'ব্যবহারের শর্তাবলী' : 'Terms of Service'; ?> - PhishSafeguard</title>
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display.swap" rel="stylesheet">
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
        .footer{padding:60px 0 30px;text-align:center;border-top:1px solid var(--border-color); margin-top: 100px;}
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
            list-style-type: disc;
            list-style-position: inside;
            padding-left: 20px;
        }
        .static-page-container li {
            margin-bottom: 10px;
        }

        /* --- অ্যানিমেশন --- */
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
        .animated-item, .content-section {
            opacity: 0; /* ডিফল্টভাবে অদৃশ্য থাকবে */
            animation: fadeInUp 0.7s ease-out forwards;
        }
        .static-page-container h1 { animation-delay: 0.2s; }
        .static-page-container .last-updated { animation-delay: 0.4s; }
        .static-page-container > p:first-of-type { animation-delay: 0.6s; }
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
                    <select name="language" id="language-select" onchange="window.location.href='terms.php?lang=' + this.value;">
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
                <h1 class="animated-item">ব্যবহারের শর্তাবলী</h1>
                <p class="last-updated animated-item">শেষ আপডেট: ১৩ই অক্টোবর, ২০২৫</p>
                
                <p class="animated-item">PhishSafeguard ("আমাদের", "আমরা", বা "আমাদের পরিষেবা") ব্যবহার করার জন্য আপনাকে ধন্যবাদ। আমাদের পরিষেবা ব্যবহার করার আগে অনুগ্রহ করে এই ব্যবহারের শর্তাবলী ("শর্তাবলী") মনোযোগ সহকারে পড়ুন। আমাদের পরিষেবা অ্যাক্সেস বা ব্যবহার করে, আপনি এই শর্তাবলী দ্বারা আবদ্ধ হতে সম্মত হন।</p>

                <div class="content-section" style="animation-delay: 0.8s;">
                    <h2>১. শর্তাবলীর স্বীকৃতি</h2>
                    <p>আমাদের পরিষেবা ব্যবহার করে, আপনি এই শর্তাবলী এবং আমাদের গোপনীয়তা নীতি মেনে চলতে সম্মত হচ্ছেন। আপনি যদি এই শর্তাবলীর কোনো অংশের সাথে একমত না হন, তবে আপনি আমাদের পরিষেবা ব্যবহার করতে পারবেন না।</p>
                </div>

                <div class="content-section" style="animation-delay: 1.0s;">
                    <h2>২. ব্যবহারকারীর অ্যাকাউন্ট</h2>
                    <p>আমাদের পরিষেবার কিছু বৈশিষ্ট্য ব্যবহার করার জন্য আপনাকে একটি অ্যাকাউন্ট তৈরি করতে হতে পারে। আপনি আপনার অ্যাকাউন্টের তথ্যের গোপনীয়তা বজায় রাখার জন্য দায়ী এবং আপনার অ্যাকাউন্টের অধীনে ঘটে যাওয়া সমস্ত কার্যকলাপের জন্য আপনি সম্পূর্ণরূপে দায়ী থাকবেন।</p>
                </div>

                <div class="content-section" style="animation-delay: 1.2s;">
                    <h2>৩. নিষিদ্ধ কার্যকলাপ</h2>
                    <p>আপনি আমাদের পরিষেবা কোনো অবৈধ বা অননুমোদিত উদ্দেশ্যে ব্যবহার করতে পারবেন না। পরিষেবা ব্যবহার করার সময়, আপনাকে অবশ্যই নিম্নলিখিত কাজগুলি থেকে বিরত থাকতে হবে:</p>
                    <ul>
                        <li>অন্য কোনো ব্যক্তির ছদ্মবেশ ধারণ করা বা মিথ্যা পরিচয় দেওয়া।</li>
                        <li>আমাদের সিস্টেম বা নেটওয়ার্কের নিরাপত্তা লঙ্ঘন বা লঙ্ঘনের চেষ্টা করা।</li>
                        <li>কোনো ভাইরাস, ম্যালওয়্যার বা ক্ষতিকারক কোড আপলোড বা প্রেরণ করা।</li>
                        <li>অবৈধ কার্যকলাপের জন্য আমাদের পরিষেবা ব্যবহার করা।</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.4s;">
                    <h2>৪. দায়বদ্ধতার সীমাবদ্ধতা</h2>
                    <p>আইন দ্বারা অনুমোদিত সীমার মধ্যে, PhishSafeguard কোনো প্রকার পরোক্ষ, আনুষঙ্গিক, বা শাস্তিমূলক ক্ষতির জন্য দায়ী থাকবে না, এমনকি যদি আমাদের এই ধরনের ক্ষতির সম্ভাবনা সম্পর্কে অবহিত করা হয়ে থাকে। আমাদের পরিষেবা "যেমন আছে" এবং "যেভাবে উপলব্ধ" ভিত্তিতে প্রদান করা হয়।</p>
                </div>

                <div class="content-section" style="animation-delay: 1.6s;">
                    <h2>৫. শর্তাবলী পরিবর্তন</h2>
                    <p>আমরা যেকোনো সময় এই শর্তাবলী পরিবর্তন বা প্রতিস্থাপন করার অধিকার সংরক্ষণ করি। পরিবর্তনের পর আমাদের পরিষেবা ব্যবহার চালিয়ে যাওয়ার মাধ্যমে, আপনি সংশোধিত শর্তাবলী দ্বারা আবদ্ধ হতে সম্মত হন।</p>
                </div>

            <?php else: ?>
                <h1 class="animated-item">Terms of Service</h1>
                <p class="last-updated animated-item">Last Updated: October 13, 2025</p>

                <p class="animated-item">Thank you for using PhishSafeguard ("us", "we", or "our"). Please read these Terms of Service ("Terms") carefully before using our service. By accessing or using the service, you agree to be bound by these Terms.</p>

                <div class="content-section" style="animation-delay: 0.8s;">
                    <h2>1. Acceptance of Terms</h2>
                    <p>By using our service, you agree to comply with and be bound by these Terms and our Privacy Policy. If you do not agree with any part of the terms, then you may not access the service.</p>
                </div>

                <div class="content-section" style="animation-delay: 1.0s;">
                    <h2>2. User Accounts</h2>
                    <p>To use certain features of our service, you may be required to create an account. You are responsible for maintaining the confidentiality of your account information and are fully responsible for all activities that occur under your account.</p>
                </div>
                
                <div class="content-section" style="animation-delay: 1.2s;">
                    <h2>3. Prohibited Activities</h2>
                    <p>You may not use the service for any illegal or unauthorized purpose. While using the service, you must refrain from:</p>
                    <ul>
                        <li>Impersonating any person or entity or falsely stating your affiliation.</li>
                        <li>Breaching or attempting to breach the security of our systems or network.</li>
                        <li>Uploading or transmitting any viruses, malware, or other malicious code.</li>
                        <li>Using our service to conduct any illegal activities.</li>
                    </ul>
                </div>

                <div class="content-section" style="animation-delay: 1.4s;">
                    <h2>4. Limitation of Liability</h2>
                    <p>To the fullest extent permitted by law, PhishSafeguard shall not be liable for any indirect, incidental, or consequential damages, even if we have been advised of the possibility of such damages. Our service is provided on an "as is" and "as available" basis.</p>
                </div>

                <div class="content-section" style="animation-delay: 1.6s;">
                    <h2>5. Changes to Terms</h2>
                    <p>We reserve the right to modify or replace these Terms at any time. By continuing to use our service after any revisions, you agree to be bound by the revised terms.</p>
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