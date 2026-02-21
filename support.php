<?php
require_once('init.php');
// Ensure session is started for language and CSRF token usage
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Create a simple CSRF token if not present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Helper to escape output for HTML
function e($str) {
    return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="<?php echo e($_SESSION['lang'] ?? 'en'); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo (($_SESSION['lang'] ?? 'en') == 'bn') ? 'সাপোর্ট হাব' : 'Support Hub'; ?> - PhishSafeguard</title>

    <meta http-equiv="Content-Security-Policy" content="default-src 'self' https:; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com;">

    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">

    <meta name="description" content="Contact support for PhishSafeguard — secure reporting and assistance.">

    <style>
        :root{--bg-dark-navy:#0a192f;--bg-light-navy:#0f2236;--card:#0e2433;--glass:rgba(255,255,255,0.04);--text-lightest:#e6f0ff;--text-light:#b8c6df;--accent-cyan:#64ffda;--accent-pink:#ff66b3;--border-color:rgba(100,255,218,0.08);}        
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Poppins',sans-serif;background:linear-gradient(180deg,#051426 0%, #07172b 50%, #0a2033 100%);color:var(--text-light);line-height:1.6; overflow-x: hidden;}
        .container{max-width:1100px;margin:0 auto;padding:0 25px}
        .header{padding:20px 0;position:fixed;width:100%;top:0;z-index:1000;background:linear-gradient(90deg,rgba(10,25,47,0.6), rgba(10,25,47,0.25));backdrop-filter:blur(8px);}        
        .navbar{display:flex;justify-content:space-between;align-items:center}.logo{font-size:1.8rem;font-weight:800;color:var(--accent-cyan);text-decoration:none}
        .footer{padding:60px 0 30px;text-align:center;border-top:1px solid var(--border-color); margin-top: 100px;}
        .footer-logo{font-size:1.8rem;font-weight:800;color:var(--accent-cyan);text-decoration:none;display:block;margin-bottom:20px}

        /* --- Smooth opening animation --- */
        @keyframes smoothFadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .animated-item {
            opacity: 0;
            animation: smoothFadeInUp 0.8s cubic-bezier(0.25, 0.46, 0.45, 0.94) forwards;
        }


        /* --- Grid Layout --- */
        .support-wrapper { 
            padding-top: 120px; 
            padding-bottom: 100px; 
            max-width: 1200px; /* Wider container for grid */
            display: grid;
            grid-template-columns: 2fr 1.2fr; /* 2-column layout */
            gap: 30px;
            align-items: start; /* Align cards to the top */
        }

        /* --- Page Heading styles --- */
        .page-heading {
            grid-column: 1 / -1; /* Span both columns */
            text-align: center;
            margin-bottom: 20px;
            opacity: 0;
            animation: smoothFadeInUp 0.7s cubic-bezier(0.25, 0.46, 0.45, 0.94) forwards;
            animation-delay: 0.1s;
        }
        .page-heading h1 { 
            font-size: 2.5rem; 
            color: var(--text-lightest); 
            margin-bottom: 8px; 
            line-height: 1.15; 
        }
        .page-heading p.intro { 
            font-size: 1rem; 
            text-align: center; 
            color: var(--text-light); 
            max-width: 680px; 
            margin: 0 auto;
        }


        /* --- Card styles --- */
        .support-card { 
            background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); 
            border-radius: 16px; 
            padding: 40px; 
            box-shadow: 0 10px 40px rgba(2,6,23,0.6), inset 0 1px 0 rgba(255,255,255,0.02); 
            border: 1px solid var(--border-color); 
            transition: transform .35s cubic-bezier(.2,.9,.3,1);
            animation-delay: 0.25s; /* Staggered animation */
        }
        .support-card:hover{ transform: translateY(-6px); }

        /* --- Sidebar Card --- */
        .info-sidebar {
            background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(255,255,255,0.02));
            padding: 30px;
            border-radius: 16px;
            border: 1px solid var(--border-color);
            box-shadow: 0 10px 40px rgba(2,6,23,0.6);
            opacity: 0;
            animation: smoothFadeInUp 0.8s cubic-bezier(0.25, 0.46, 0.45, 0.94) forwards;
            animation-delay: 0.4s; /* Staggered animation */
        }
        

        /* --- [NEW] Form Styles --- */
        form { 
            display: grid; 
            grid-template-columns: 1fr 1fr; /* 2 columns for name/email */
            gap: 20px; /* Gap between fields */
            align-items: start; 
        }
        .form-group {
            width: 100%;
        }
        .form-group.full-width {
            grid-column: 1 / -1; /* Make subject/message span full width */
        }

        /* [NEW] Label styles */
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text-light);
        }

        /* [NEW] Input/Textarea styles */
        input[type="text"], input[type="email"], textarea { 
            width:100%; 
            padding: 14px 16px; /* Removed left-padding for icon */
            border-radius:10px; 
            background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(255,255,255,0.015)); 
            border: 1px solid var(--border-color); /* Changed from transparent */
            color:var(--text-lightest); 
            font-size:0.98rem; 
            transition: box-shadow .18s ease, border-color .18s ease, transform .18s ease;
            box-shadow: 0 4px 12px rgba(2,8,23,0.5); /* Slightly updated shadow */
        }
        textarea{ min-height:150px; resize:vertical; }
        
        input:focus, textarea:focus { 
            outline: none; 
            border-color: rgba(100,255,218,0.5); /* Brighter focus border */
            box-shadow: 0 6px 20px rgba(100,255,218,0.08); /* Brighter focus shadow */
            transform: translateY(-2px); 
        }

        /* Button */
        .form-button { 
            grid-column: 1 / -1; 
            padding:14px 22px; 
            border-radius:12px; border:none; 
            font-weight:700; font-size:1rem; 
            cursor:pointer; 
            background: linear-gradient(90deg,var(--accent-cyan), #7bffdf 60%); 
            color:#042233; 
            box-shadow: 0 10px 30px rgba(100,255,218,0.08); 
            transition: all .25s ease; /* Changed transition */
            margin-top: 10px; /* Added margin on top */
        }
        .form-button:hover{ 
            transform: translateY(-4px); 
            box-shadow: 0 18px 50px rgba(100,255,218,0.12); 
        }
        
        .form-button:disabled {
            background: var(--text-light);
            color: var(--bg-dark-navy);
            cursor: not-allowed;
            opacity: 0.6;
            transform: translateY(0);
            box-shadow: none;
        }
        .form-button .fa-spinner {
            margin-right: 8px;
        }
        /* --- [END NEW FORM STYLES] --- */


        hr { display: none; } /* No longer needed */

        .extra-info h3 { text-align: center; color: var(--text-lightest); margin-bottom: 18px; font-size: 1.05rem; }
        .info-grid { display: grid; grid-template-columns: 1fr; /* Stacked in sidebar */ gap: 14px; text-align: center; }
        .info-box { background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(255,255,255,0.02)); padding: 18px; border-radius: 10px; }
        .info-box .icon { font-size: 1.4rem; color: var(--accent-cyan); margin-bottom: 8px; }
        .info-box strong { color: var(--text-lightest); }
        .info-box a { color: var(--text-light); text-decoration: none; word-break: break-all; }

        /* Success */
        .success-content { display: none; text-align: center; }
        .success-content .icon { font-size: 4rem; color: var(--accent-cyan); margin-bottom: 18px; }
        .success-content h2 { font-size: 1.8rem; color: var(--text-lightest); margin-bottom: 10px; }


        /* --- [NEW] Toast Notification Styles --- */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .toast {
            display: flex;
            align-items: center;
            padding: 14px 20px;
            border-radius: 10px;
            background: var(--bg-light-navy);
            color: var(--text-lightest);
            border: 1px solid var(--border-color);
            box-shadow: 0 10px 30px rgba(2, 6, 23, 0.7);
            font-size: 0.95rem;
            transform: translateX(120%);
            opacity: 0;
            transition: all 0.4s cubic-bezier(0.215, 0.610, 0.355, 1);
        }
        .toast.show {
            transform: translateX(0);
            opacity: 1;
        }
        .toast.hide {
            transform: translateX(120%);
            opacity: 0;
        }
        .toast i {
            font-size: 1.2rem;
            margin-right: 12px;
        }
        .toast.success {
            border-left: 4px solid var(--accent-cyan);
        }
        .toast.success i {
            color: var(--accent-cyan);
        }
        .toast.error {
            border-left: 4px solid var(--accent-pink);
        }
        .toast.error i {
            color: var(--accent-pink);
        }
        /* --- [END TOAST] --- */


        @media (max-width: 880px) {
            .support-wrapper {
                grid-template-columns: 1fr; /* Stack columns on mobile */
                padding-top: 100px;
            }
            form { grid-template-columns: 1fr; } /* Stack form fields on mobile */
            .form-group i { left: 12px; }
            .support-card { padding: 28px; }
            .info-sidebar { padding: 28px; }
            .page-heading h1 { font-size: 2rem; }
        }

        /* Accessibility */
        .sr-only { position: absolute !important; height: 1px; width: 1px; overflow: hidden; clip: rect(1px, 1px, 1px, 1px); white-space: nowrap; }
    </style>
</head>
<body>

    <header class="header" role="banner">
        <div class="container navbar">
            <a class="logo" href="welcome.php">PhishSafeguard</a>
            <nav aria-label="Main navigation">
                <a href="welcome.php" style="color:var(--text-light);text-decoration:none">Home</a>
            </nav>
        </div>
    </header>

    <main>
        <div class="container support-wrapper">

            <?php if (($_SESSION['lang'] ?? 'en') == 'bn'): ?>
                
                <div class="page-heading">
                    <h1 id="support-heading">আপনার সরাসরি সাপোর্ট লাইন</h1>
                    <p class="intro">আপনার মানসিক শান্তিই আমাদের প্রধান লক্ষ্য। নিচের ফর্মটি ব্যবহার করে আমাদের একটি বিস্তারিত বার্তা পাঠান, এবং আমাদের বিশেষজ্ঞ টিম দ্রুত সহায়তা প্রদান করবে।</p>
                </div>

                <div class="support-card animated-item" role="region">
                    <div id="initial-content"> 
                        <form id="support-form" novalidate aria-describedby="support-instructions">
                            <p id="support-instructions" class="sr-only">ফর্মটি পূরণ করে "Send Secure Message" প্রেস করুন।</p>
                            
                            <div class="form-group">
                                <label for="name">আপনার সম্পূর্ণ নাম</label>
                                <input id="name" type="text" name="name" placeholder="John Doe" required aria-required="true">
                            </div>
                            
                            <div class="form-group">
                                <label for="email">আপনার কাজের ইমেল</label>
                                <input id="email" type="email" name="email" placeholder="you@example.com" required aria-required="true">
                            </div>

                            <div class="form-group full-width">
                                <label for="subject">বার্তার বিষয়</label>
                                <input id="subject" type="text" name="subject" placeholder="যেমন: লগইন সমস্যা" required aria-required="true">
                            </div>
                            
                            <div class="form-group full-width">
                                <label for="message">আপনার সমস্যাটি</label>
                                <textarea id="message" name="message" placeholder="আপনার সমস্যাটি এখানে বিস্তারিতভাবে লিখুন..." required aria-required="true"></textarea>
                            </div>

                            <div class="sr-only" aria-hidden="true">
                                <label for="website">Leave this field empty</label>
                                <input id="website" type="text" name="website" tabindex="-1" autocomplete="off">
                            </div>
                            <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                            
                            <button type="submit" class="form-button">নিরাপদভাবে বার্তা পাঠান</button>
                        </form>
                        </div>

                    <div id="success-content" class="success-content" role="status" aria-live="polite">
                        <div class="icon" aria-hidden="true"><i class="fas fa-check-circle"></i></div>
                        <h2>আপনার বার্তাটি গৃহীত হয়েছে!</h2>
                        <p>আমাদের সাথে যোগাযোগ করার জন্য ধন্যবাদ। আমাদের টিম আপনার বার্তাটি পর্যালোচনা করছে এবং সাধারণত ২৪ ঘণ্টার মধ্যে আপনার দেওয়া ইমেল ঠিকানায় উত্তর পাঠাবে।</p>
                        <a href="welcome.php" class="success-button">হোমপেজে ফিরে যান</a>
                    </div>
                </div>

                <div class="info-sidebar">
                    <div class="extra-info">
                        <h3>যোগাযোগের বিকল্প মাধ্যম</h3>
                        <div class="info-grid">
                            <div class="info-box"><div class="icon" aria-hidden="true"><i class="fas fa-headset"></i></div><strong>আমাদের প্রতিশ্রুতি</strong><br><span>২৪ কর্মঘন্টার মধ্যে উত্তর।</span></div>
                            <div class="info-box"><div class="icon" aria-hidden="true"><i class="fas fa-envelope-open-text"></i></div><strong>সরাসরি ইমেল</strong><br><a href="mailto:hazrarupam222@gmail.com">hazrarupam222@gmail.com</a></div>
                        </div>
                    </div>
                </div>

            <?php else: ?>

                <div class="page-heading">
                    <h1 id="support-heading">Your Direct Line to Support</h1>
                    <p class="intro">Your peace of mind is our priority. Use the form below to send us a detailed message, and our expert team will provide swift assistance.</p>
                </div>
                
                <div class="support-card animated-item" role="region">
                    <div id="initial-content">
                        <form id="support-form" novalidate aria-describedby="support-instructions">
                            <p id="support-instructions" class="sr-only">Fill out the form and press Send Secure Message.</p>
                            
                            <div class="form-group">
                                <label for="name">Your Full Name</label>
                                <input id="name" type="text" name="name" placeholder="John Doe" required aria-required="true">
                            </div>
                            
                            <div class="form-group">
                                <label for="email">Your Work Email</label>
                                <input id="email" type="email" name="email" placeholder="you@example.com" required aria-required="true">
                            </div>
                            
                            <div class="form-group full-width">
                                <label for="subject">Subject of Your Message</label>
                                <input id="subject" type="text" name="subject" placeholder="e.g., Trouble logging in" required aria-required="true">
                            </div>
                            
                            <div class="form-group full-width">
                                <label for="message">Your Message</label>
                                <textarea id="message" name="message" placeholder="Please describe your issue in detail here..." required aria-required="true"></textarea>
                            </div>
                            
                            <div class="sr-only" aria-hidden="true">
                                <label for="website">Leave this field empty</label>
                                <input id="website" type="text" name="website" tabindex="-1" autocomplete="off">
                            </div>
                            <input type="hidden" name="csrf_token" value="<?php echo e($_SESSION['csrf_token']); ?>">
                            
                            <button type="submit" class="form-button">Send Secure Message</button>
                        </form>
                        </div>

                    <div id="success-content" class="success-content" role="status" aria-live="polite">
                        <div class="icon" aria-hidden="true"><i class="fas fa-check-circle"></i></div>
                        <h2>Your Request Has Been Received!</h2>
                        <p>Thank you for reaching out. Our team is reviewing your message and will get back to you at the email address you provided, typically within 24 business hours.</p>
                        <a href="welcome.php" class="success-button">Back to Homepage</a>
                    </div>
                </div>

                <div class="info-sidebar">
                    <div class="extra-info">
                        <h3>Alternative Ways to Reach Us</h3>
                        <div class="info-grid">
                            <div class="info-box"><div class="icon" aria-hidden="true"><i class="fas fa-headset"></i></div><strong>Our Commitment</strong><br><span>A response within 24 business hours.</span></div>
                            <div class="info-box"><div class="icon" aria-hidden="true"><i class="fas fa-envelope-open-text"></i></div><strong>Direct Email</strong><br><a href="mailto:hazrarupam222@gmail.com">hazrarupam222@gmail.com</a></div>
                        </div>
                    </div>
                </div>

            <?php endif; ?>
        </div>
    </main>

    <footer class="footer" role="contentinfo">
        <div class="container">
            <a class="footer-logo" href="welcome.php">PhishSafeguard</a>
            <p class="copyright">&copy; <?php echo date('Y'); ?> PhishSafeguard. All rights reserved.</p>
        </div>
    </footer>

    <noscript>
        <div style="background:#ffefc2;padding:12px;text-align:center;color:#111">JavaScript is disabled in your browser. The form will still submit but validation may be limited.</div>
    </noscript>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const lang = document.documentElement.lang;
            const supportForm = document.getElementById('support-form');
            const initialContent = document.getElementById('initial-content');
            const successContent = document.getElementById('success-content');

            // --- [NEW] Toast Notification Function ---
            function showToast(message, type = 'success') {
                let container = document.querySelector('.toast-container');
                if (!container) {
                    container = document.createElement('div');
                    container.className = 'toast-container';
                    document.body.appendChild(container);
                }

                const toast = document.createElement('div');
                toast.className = `toast ${type}`;
                
                const iconClass = type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle';
                toast.innerHTML = `<i class="fas ${iconClass}"></i> ${message}`;
                
                container.appendChild(toast);

                // Show the toast
                setTimeout(() => {
                    toast.classList.add('show');
                }, 100); // 100ms delay for entry animation

                // Hide the toast after 4 seconds
                setTimeout(() => {
                    toast.classList.add('hide');
                }, 4000);

                // Remove the toast from DOM after animation
                setTimeout(() => {
                    toast.remove();
                }, 4500);
            }
            // --- [END NEW TOAST FUNCTION] ---


            // [UNCHANGED] Button glow / micro-interaction
            const style = document.createElement('style');
            style.textContent = `
                .form-button.glow { box-shadow: 0 6px 30px rgba(100,255,218,0.12), 0 0 60px rgba(100,255,218,0.06) inset; transform: translateY(-6px) scale(1.01); }
            `;
            document.head.appendChild(style);
            function addGlowListeners(btn) {
                btn.addEventListener('mouseenter', () => btn.classList.add('glow'));
                btn.addEventListener('mouseleave', () => btn.classList.remove('glow'));
                btn.addEventListener('focus', () => btn.classList.add('glow'));
                btn.addEventListener('blur', () => btn.classList.remove('glow'));
            }
            const allButtons = document.querySelectorAll('.form-button');
            allButtons.forEach(addGlowListeners);

            // [UNCHANGED] Particle background
            (function createParticles() {
                if (window.matchMedia('(max-width:720px)').matches) return;
                const canvas = document.createElement('canvas');
                canvas.id = 'particles-canvas';
                canvas.style.cssText = 'position:fixed;inset:0;z-index:0;pointer-events:none;opacity:0.35;';
                document.body.appendChild(canvas);
                const ctx = canvas.getContext('2d');
                let w, h, particles;
                function resize() { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; }
                function initParticles() {
                    particles = Array.from({length: Math.round((w*h)/90000)}, () => ({
                        x: Math.random()*w,
                        y: Math.random()*h,
                        r: 0.6 + Math.random()*1.6,
                        vx: (Math.random()-0.5)*0.3,
                        vy: (Math.random()-0.5)*0.3
                    }));
                }
                function step() {
                    ctx.clearRect(0,0,w,h);
                    for (let p of particles) {
                        p.x += p.vx; p.y += p.vy;
                        if (p.x < -10) p.x = w + 10;
                        if (p.x > w + 10) p.x = -10;
                        if (p.y < -10) p.y = h + 10;
                        if (p.y > h + 10) p.y = -10;
                        ctx.beginPath();
                        const g = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.r*8);
                        g.addColorStop(0, 'rgba(100,255,218,0.12)');
                        g.addColorStop(0.4, 'rgba(100,255,218,0.06)');
                        g.addColorStop(1, 'rgba(100,255,218,0)');
                        ctx.fillStyle = g;
                        ctx.fillRect(p.x - p.r*8, p.y - p.r*8, p.r*16, p.r*16);
                    }
                    requestAnimationFrame(step);
                }
                function start() { resize(); initParticles(); step(); }
                window.addEventListener('resize', () => { resize(); initParticles(); });
                start();
            })();

            // --- [UPDATED] Form Submission Logic ---
            if (supportForm) {
                supportForm.addEventListener('submit', function (event) {
                    event.preventDefault();

                    // HTML5 validation check
                    if (!supportForm.checkValidity()) {
                        supportForm.reportValidity();
                        // Show an error toast to make it clear why it's not submitting
                        showToast((lang === 'bn') ? 'অনুগ্রহ করে সমস্ত প্রয়োজনীয় ফিল্ড পূরণ করুন।' : 'Please fill out all required fields.', 'error');
                        return;
                    }

                    // Honeypot check
                    const honeypot = supportForm.querySelector('input[name="website"]');
                    if (honeypot && honeypot.value.trim() !== '') {
                        console.warn('Honeypot filled, aborting submission.');
                        return;
                    }

                    const form = this;
                    const button = form.querySelector('button[type="submit"]');
                    const origText = button.textContent; // Store original text

                    // disable and show progress with spinner
                    button.disabled = true;
                    button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${ (lang === 'bn') ? 'পাঠানো হচ্ছে...' : 'Sending...' }`;
                    button.classList.add('glow');

                    fetch('send_mail.php', {
                        method: 'POST',
                        body: new FormData(form),
                        credentials: 'same-origin'
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data && data.success) {
                            // --- [NEW] Show success toast ---
                            showToast((lang === 'bn') ? 'বার্তা পাঠানো হয়েছে!' : 'Message sent successfully!', 'success');
                            
                            // Reset form and show inline success (for non-JS or fallback)
                            form.reset();
                            if (initialContent) initialContent.style.display = 'none';
                            if (successContent) successContent.style.display = 'block';

                            // Re-enable button after a short delay
                            setTimeout(() => {
                                button.disabled = false;
                                button.innerHTML = origText;
                                button.classList.remove('glow');
                            }, 1000); // Re-enable after 1 sec

                        } else {
                            // --- [NEW] Show error toast ---
                            showToast(data.message || ((lang === 'bn') ? 'একটি ত্রুটি ঘটেছে।' : 'An error occurred.'), 'error');
                            button.disabled = false;
                            button.innerHTML = origText;
                            button.classList.remove('glow');
                        }
                    })
                    .catch(error => {
                        console.error('Fetch Error:', error);
                        // --- [NEW] Show error toast ---
                        showToast((lang === 'bn') ? 'নেটওয়ার্ক ত্রুটি ঘটেছে।' : 'A network error occurred.', 'error');
                        button.disabled = false;
                        button.innerHTML = origText;
                        button.classList.remove('glow');
                    });
                });
            }

        });
    </script>
</body>
</html>