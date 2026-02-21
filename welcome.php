<?php require_once('init.php'); ?>
<!DOCTYPE html>
<html lang="<?php echo $_SESSION['lang']; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishSafeguard - Your Advanced Shield Against Online Threats</title>
    <meta name="description" content="PhishSafeguard provides elite, AI-powered protection against phishing and malicious links. Scan any URL in real-time and browse with confidence.">

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@800&family=Poppins:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link rel="stylesheet" href="https://unpkg.com/aos@2.3.1/dist/aos.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.css"/>

    <style>
        :root{--bg-dark-navy:#0a192f;--bg-light-navy:#112240;--text-lightest:#ccd6f6;--text-light:#a8b2d1;--text-dark:#8892b0;--accent-cyan:#64ffda;--accent-orange:#f5a623;--border-color:rgba(100, 255, 218, 0.1);--shadow-color:rgba(2, 12, 27, 0.7);--header-height:80px}*{margin:0;padding:0;box-sizing:border-box}html{scroll-behavior:smooth}body{font-family:'Poppins',sans-serif;background-color:var(--bg-dark-navy);color:var(--text-light);line-height:1.6; position: relative;}
        #particles-js{position:fixed;width:100%;height:100%;top:0;left:0;z-index:-1}
        .container{max-width:1100px;margin:0 auto;padding:0 25px}section{padding:100px 0; position: relative;}
        .section-title{text-align:center;font-size:3rem;font-weight:700;color:var(--text-lightest);margin-bottom:60px;position:relative}.section-title::after{content:'';display:block;width:80px;height:4px;background:var(--accent-cyan);margin:15px auto 0;border-radius:2px}
        
        .header{padding:20px 0;position:fixed;width:100%;top:0;z-index:1000;
            transition: background-color .3s ease-in-out, backdrop-filter .3s ease-in-out, box-shadow .3s ease-in-out, padding .3s ease-in-out;}
        .header.scrolled{background-color:rgba(10, 25, 47, 0.85);backdrop-filter:blur(10px);box-shadow:0 5px 15px rgba(0,0,0,.3);padding:15px 0}

        .navbar{display:flex;justify-content:space-between;align-items:center}
        
        /* --- START: PREMIUM ANIMATED LOGO CSS --- */
        .brand-logo {
            font-family: 'Montserrat', sans-serif;
            font-weight: 800; 
            font-size: 1.8rem; 
            color: var(--accent-cyan);
            letter-spacing: -0.5px;
            text-shadow: 0 2px 10px rgba(100, 255, 218, 0.3); 
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
        }

        .brand-logo .logo-text {
            background: linear-gradient(to right, #64ffda 0%, #ffffff 50%, #64ffda 100%);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: logoShine 5s linear infinite;
        }

        .brand-logo i {
            animation: shieldPulse 3s infinite;
            color: var(--accent-cyan);
        }

        @keyframes logoShine { to { background-position: 200% center; } }
        @keyframes shieldPulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.15); filter: drop-shadow(0 0 8px var(--accent-cyan)); } }
        /* --- END: PREMIUM ANIMATED LOGO CSS --- */

        /* --- START: Developer Badge CSS --- */
        .dev-badge {
            font-size: 0.85rem; 
            font-weight: 600; 
            color: var(--accent-cyan); 
            display: flex;
            align-items: center;
            gap: 8px; 
            padding: 4px 8px; 
            border-radius: 5px; 
            background-color: rgba(100, 255, 218, 0.08); 
            box-shadow: 0 0 12px rgba(100, 255, 218, 0.3); 
            text-shadow: 0 0 5px rgba(100, 255, 218, 0.5); 
            opacity: 0;
            animation: fadeInBadge 1.5s ease-out 1s forwards; 
        }

        .dev-badge .badge-icon {
            display: inline-block;
            width: 10px; 
            height: 10px; 
            background-color: var(--accent-cyan); 
            border-radius: 50%;
            animation: pulseBadge 2s infinite ease-in-out;
        }

        @keyframes fadeInBadge {
            from { opacity: 0; transform: translateY(-5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes pulseBadge {
            0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(100, 255, 218, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(100, 255, 218, 0); }
            100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(100, 255, 218, 0); }
        }
        /* --- END: Developer Badge CSS --- */
        
        .nav-menu{display:flex;align-items:center}.nav-links{list-style:none;display:flex;align-items:center}.nav-links li{margin-left:28px}
        
        .nav-links a{color:var(--text-lightest);text-decoration:none;font-weight:500;
            transition:color .3s ease, transform 0.3s ease; 
            display: inline-block;}
        .nav-links a:hover{color:var(--accent-cyan); transform: translateY(-2px);}

        /* Wrapper for Language + Admin Link */
        .lang-admin-group {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-left: 18px;
        }

        .lang-selector-wrapper{position:relative; display:flex;align-items:center}.lang-selector-wrapper .fa-globe{color:var(--text-dark);position:absolute;left:12px;top:50%;transform:translateY(-50%);pointer-events:none}#language-select{-webkit-appearance:none;-moz-appearance:none;appearance:none;background-color:var(--bg-light-navy);border:1px solid var(--border-color);padding:8px 15px 8px 35px;border-radius:5px;color:var(--text-lightest);font-family:'Poppins',sans-serif;font-size:14px;cursor:pointer;transition:border-color .3s ease}#language-select:hover{border-color:var(--accent-cyan)}#language-select option{background:var(--bg-light-navy);color:var(--text-lightest)}.lang-selector-wrapper::after{content:'\f078';font-family:'Font Awesome 6 Free';font-weight:900;position:absolute;right:12px;top:50%;transform:translateY(-50%);color:var(--text-dark);pointer-events:none;font-size:12px}.nav-buttons{display:flex;align-items:center}.nav-buttons a{text-decoration:none;padding:10px 18px;border-radius:5px;margin-left:15px;font-weight:500;border:1px solid var(--accent-cyan);
            transition:background-color .3s ease, opacity .3s ease, color .3s ease;}
        .btn-login{color:var(--accent-cyan)}.btn-login:hover{background-color:rgba(100, 255, 218, 0.1)}.btn-signup{background-color:var(--accent-cyan);color:var(--bg-dark-navy)}.btn-signup:hover{opacity:.85}
        
        /* --- PROFESSIONAL ADMIN LINK CSS (New Elegant Design) --- */
        .know-admin-link {
            font-size: 0.75rem; 
            font-weight: 500;
            margin-top: 10px; /* Perfect spacing */
            
            /* Clean & Professional Look */
            color: var(--accent-cyan); 
            background: linear-gradient(45deg, rgba(100, 255, 218, 0.05), transparent);
            
            text-decoration: none;
            border: 1px solid rgba(100, 255, 218, 0.3);
            padding: 5px 14px;
            border-radius: 50px; /* Smooth rounded shape */
            
            display: flex;
            align-items: center;
            gap: 8px; /* Space between icon and text */
            
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .know-admin-link i {
            font-size: 0.9rem; /* Icon size */
        }

        .know-admin-link:hover {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(100, 255, 218, 0.15); /* Soft professional glow */
            transform: translateY(-2px);
            background: rgba(100, 255, 218, 0.1);
        }

        /* Subtle Shimmer Effect on Hover */
        .know-admin-link::before {
            content: '';
            position: absolute;
            top: 0; left: -100%;
            width: 100%; height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            transition: 0.5s;
        }
        .know-admin-link:hover::before {
            left: 100%;
        }
        /* --- END ADMIN LINK --- */

        .hero{padding-top:calc(var(--header-height) + 100px);text-align:center;min-height:80vh;display:flex;align-items:center;justify-content:center}.hero h1{font-size:4rem;font-weight:800;color:var(--text-lightest);margin-bottom:20px}.hero h1 span{color:var(--accent-cyan)}.hero .subtitle{font-size:1.2rem;max-width:650px;margin:0 auto 40px}
        .cta-button{display:inline-block;padding:14px 28px;font-size:1.05rem;font-weight:700;border-radius:5px;text-decoration:none; position: relative; z-index: 1;
            transition:transform .3s ease, box-shadow .3s ease, opacity .3s ease;}
        .hero .cta-button{background-color:var(--accent-orange);color:#000;box-shadow:0 4px 15px rgba(245, 166, 35, 0.4)}
        .hero .cta-button:hover{transform:translateY(-5px);box-shadow:0 8px 25px rgba(245, 166, 35, 0.6)}
        
        #trusted-by { padding: 60px 0; border-bottom: 1px solid var(--border-color); }
        .trusted-title { text-align: center; color: var(--text-dark); font-weight: 500; margin-bottom: 30px; letter-spacing: 1px; }
        .logos { display: flex; flex-wrap: wrap; justify-content: center; align-items: center; gap: 50px; }
        .logos img { height: 35px; opacity: 0.6; filter: grayscale(100%); 
            transition: opacity 0.3s ease, filter 0.3s ease, transform 0.3s ease; }
        .logos img:hover { opacity: 1; filter: grayscale(0%); transform: scale(1.1); }

        /* --- START: FEATURE CARD TILT FIX --- */
        .features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:30px; /* perspective removed */ }
        .feature-card{
            background:var(--bg-light-navy);
            padding:30px;
            border-radius:10px;
            border:1px solid var(--border-color);
            cursor: pointer;
            box-shadow: 0 8px 22px rgba(2,12,27,0.45);
            /* Shudhu matro hover effect-er jonno transition */
            transition:transform 0.3s ease-out, box-shadow 0.3s ease-out, border-color 0.3s ease-out;
            /* 3D tilt properties removed */
        }
        
        .feature-card:hover{
            transform: translateY(-8px); /* Simple lift effect */
            box-shadow:0 20px 40px -15px var(--shadow-color);
            border-color: var(--accent-cyan);
        }
        /* --- END: FEATURE CARD TILT FIX --- */

        .feature-card .icon{font-size:2.2rem;color:var(--accent-cyan);margin-bottom:18px}.feature-card h3{font-size:1.2rem;color:var(--text-lightest);margin-bottom:12px}

/* --- START: Pricing CSS --- */
        .pricing-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:30px;align-items:center;}
        .pricing-card{background:var(--bg-light-navy);Padding:30px;border-radius:10px;border:1px solid var(--border-color);text-align:center;position:relative;overflow:hidden;
            transition:transform .3s ease, box-shadow .3s ease, border-color .3s ease;}
        .pricing-card:hover{transform:translateY(-10px);box-shadow:0 20px 40px -15px var(--shadow-color);border-color:var(--accent-cyan);}
        .pricing-card.recommended{border-color:var(--accent-cyan);transform:scale(1.05); z-index: 1;}
        .recommended-badge{position:absolute;top:15px;right:-45px;background:var(--accent-cyan);color:var(--bg-dark-navy);padding:5px 40px;font-size:.9rem;font-weight:700;transform:rotate(45deg);letter-spacing:1px;}
        .pricing-card h3{font-size:1.3rem;color:var(--text-lightest);margin-bottom:15px;}
        .pricing-card .price{font-size:2.2rem;font-weight:800;color:var(--accent-cyan);margin-bottom:10px;}.pricing-card .price span{font-size:0.9rem;font-weight:400;color:var(--text-dark);}
        .pricing-card .plan-desc{font-size:.9rem;color:var(--text-dark);margin-bottom:20px;min-height:40px;}
        .pricing-card ul{list-style:none;margin-bottom:30px;text-align:left;}.pricing-card ul li{margin-bottom:12px;display:flex;align-items:center;}.pricing-card ul li .fa-check-circle{color:var(--accent-cyan);margin-right:10px;}
        .pricing-card .cta-button{display:block;width:100%;background-color:transparent;border:1px solid var(--accent-cyan);color:var(--accent-cyan);padding:12px 0;}
        .pricing-card .cta-button:hover{background-color:rgba(100, 255, 218, 0.1);}
        .pricing-card.recommended .cta-button{background-color:var(--accent-cyan);color:var(--bg-dark-navy);}.pricing-card.recommended .cta-button:hover{opacity:.85;}
        .pricing-notice{max-width:900px;margin:0 auto 30px;padding:12px 18px;border-radius:10px;background:linear-gradient(90deg, rgba(245,166,35,0.08), rgba(100,255,218,0.04));border:1px solid rgba(245,166,35,0.12);color:var(--accent-orange);font-weight:600;text-align:center;box-shadow:0 6px 18px rgba(2,12,27,0.45)}
/* --- END: Pricing CSS --- */

/* --- START: How it works CSS --- */
        .how-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:20px;align-items:start}
        .how-step{background:linear-gradient(180deg, rgba(255,255,255,0.02), transparent);padding:22px;border-radius:10px;border:1px solid var(--border-color);text-align:left;}
        .how-step .step-num{display:inline-flex;width:44px;height:44px;border-radius:50%;align-items:center;justify-content:center;background:rgba(100,255,218,0.08);color:var(--accent-cyan);font-weight:700;margin-bottom:12px}
        .how-step h4{margin:6px 0 10px;color:var(--text-lightest)}
        .how-step p{color:var(--text-dark);font-size:0.95rem;line-height:1.5}
/* --- END: How it works CSS --- */

/* --- START: Blog CSS --- */
        .blog-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px}
        .blog-card{background:var(--bg-light-navy);border-radius:10px;overflow:hidden;border:1px solid var(--border-color);display:flex;flex-direction:column;
            transition:transform .25s ease, box-shadow .25s ease, border-color .25s ease;}
        .blog-card .thumb{height:160px;background-size:cover;background-position:center}
        .blog-card .card-body{padding:18px;flex:1;display:flex;flex-direction:column}
        .blog-card h3{font-size:1.05rem;margin-bottom:8px;color:var(--text-lightest)}
        .blog-card p{color:var(--text-dark);font-size:0.95rem;flex:1}
        .blog-card .meta{font-size:0.85rem;color:var(--text-dark);margin-bottom:10px}
        .blog-card .read-more{margin-top:12px;text-decoration:none;color:var(--accent-cyan);font-weight:600}
        .blog-card:hover{transform:translateY(-6px);box-shadow:0 18px 40px -20px var(--shadow-color);border-color:var(--accent-cyan)}
/* --- END: Blog CSS --- */

        #stats{background-color:var(--bg-light-navy)}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:30px;text-align:center}.stat-item .stat-number{font-size:3.5rem;font-weight:700;color:var(--accent-cyan);display:block}.stat-item .stat-label{font-size:1.1rem;color:var(--text-dark)}
        #testimonials { position: relative; }
        .swiper-container { width: 100%; padding-top: 20px; padding-bottom: 60px; overflow: hidden; }
        .swiper-slide { display: flex; justify-content: center; align-items: center; }
        .testimonial-card{background:var(--bg-light-navy); width: 85%; max-width: 450px; padding:30px;border-radius:10px;border-left:5px solid var(--accent-cyan); display: flex; flex-direction: column; height: 100%;}
        .testimonial-card p{font-style:italic;margin-bottom:20px; flex-grow: 1;}
        .testimonial-author{display:flex;align-items:center}.testimonial-author img{width:50px;height:50px;border-radius:50%;margin-right:15px}.author-info h4{color:var(--text-lightest)}.author-info span{font-size:.9rem;color:var(--text-dark)}.stars{color:var(--accent-orange)}
        .swiper-button-next, .swiper-button-prev { color: var(--accent-cyan); }
        .swiper-pagination-bullet-active { background-color: var(--accent-cyan); }
        
        .faq-container{max-width:800px;margin:0 auto}.faq-item{border-bottom:1px solid var(--border-color)}
        .faq-question{width:100%;background:0 0;border:none;text-align:left;padding:20px 0;font-size:1.2rem;font-weight:500;color:var(--text-lightest);cursor:pointer;display:flex;justify-content:space-between;align-items:center}
        .faq-question::after{content:'\f067';font-family:'Font Awesome 6 Free';font-weight:900;transition:transform .3s ease}
        .faq-item.active .faq-question::after{transform:rotate(45deg)}
        .faq-answer{max-height:0;overflow:hidden;
            transition:max-height .4s ease-in-out;}
        .faq-answer p{padding: 5px 0 20px; line-height: 1.8;}

        #cta{background:linear-gradient(45deg,#112240,#0a192f);text-align:center}#cta h2{font-size:2.8rem}#cta p{max-width:600px;margin:0 auto 30px}
        #cta .cta-button {background-color: var(--accent-cyan); color: var(--bg-dark-navy); box-shadow: 0 4px 15px rgba(100, 255, 218, 0.3);}
        #cta .cta-button:hover {transform: translateY(-5px); box-shadow: 0 8px 25px rgba(100, 255, 218, 0.4);}

        .footer{padding:60px 0 30px;text-align:center;border-top:1px solid var(--border-color)}
        .footer-links{list-style:none;display:flex;justify-content:center;gap:30px;margin-bottom:20px}.footer-links a{color:var(--text-light);text-decoration:none;transition:color .3s ease}.footer-links a:hover{color:var(--accent-cyan)}.copyright{font-size:.9rem;color:var(--text-dark)}
        
        #cookie-banner{position:fixed;bottom:-100%;left:0;width:100%;background-color:var(--bg-light-navy);color:var(--text-light);padding:20px;box-shadow:0 -5px 15px rgba(0,0,0,.3);display:flex;justify-content:center;align-items:center;gap:20px;z-index:1001;transition:bottom .5s ease-in-out}
        #cookie-banner.show{bottom:0}#cookie-banner p{margin:0}#accept-cookies{background-color:var(--accent-orange);color:#000;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;font-weight:600}@media (max-width:992px){.nav-links,.lang-admin-group{display:none}}@media (max-width:768px){.section-title{font-size:2.2rem}.hero h1{font-size:2.2rem}#cookie-banner{flex-direction:column;text-align:center} .pricing-notice{margin: 0 18px 20px;} .how-grid{grid-template-columns:1fr;} .blog-grid{grid-template-columns:1fr;} }

/* --- START: 3D scene CSS --- */
.hero { position: relative; overflow: visible; }
#three-scene {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 0;
}
.hero .container { position: relative; z-index: 2; }

@media (max-width: 768px) {
  #three-scene { height: 60vh; display: none; }
}
/* --- END: 3D scene CSS --- */
    </style>
</head>
<body>

    <div id="particles-js"></div>

    <header class="header" id="header">
        <nav class="navbar container">
            <div style="display:flex;flex-direction:column;gap:2px"> 
                <a href="welcome.php" class="brand-logo">
                    <i class="fa-solid fa-shield-halved"></i>
                    <span class="logo-text">PhishSafeguard</span>
                </a>
                
                <div class="dev-badge">
                    <span class="badge-icon"></span> Developed By Rupam
                </div>
                <?php if (!empty($_SESSION['user_name'])): ?>
                    <div style="font-size:0.95rem;color:var(--text-lightest); margin-top: 5px;"> 
                      Welcome, <strong style="color:var(--accent-cyan)"><?php echo htmlspecialchars($_SESSION['user_name'], ENT_QUOTES, 'UTF-8'); ?></strong>
                    </div>
                <?php endif; ?>
            </div>
            <div class="nav-menu">
                <ul class="nav-links">
                    <li><a href="#about"><?php echo isset($lang['nav_about']) ? $lang['nav_about'] : 'About Us'; ?></a></li>
                    <li><a href="#features"><?php echo isset($lang['nav_features']) ? $lang['nav_features'] : 'Features'; ?></a></li>
                    <li><a href="#how-it-works"><?php echo isset($lang['nav_how_it_works']) ? $lang['nav_how_it_works'] : 'How it works'; ?></a></li>
                    <li><a href="#pricing"><?php echo isset($lang['nav_pricing']) ? $lang['nav_pricing'] : 'Pricing'; ?></a></li>
                    <li><a href="#blog"><?php echo isset($lang['nav_blog']) ? $lang['nav_blog'] : 'Blog'; ?></a></li>
                    <li><a href="#stats"><?php echo isset($lang['nav_impact']) ? $lang['nav_impact'] : 'Impact'; ?></a></li>
                    <li><a href="#testimonials"><?php echo isset($lang['nav_reviews']) ? $lang['nav_reviews'] : 'Reviews'; ?></a></li>
                    <li><a href="#faq"><?php echo isset($lang['nav_faq']) ? $lang['nav_faq'] : 'FAQ'; ?></a></li>
                </ul>
                
                <div class="lang-admin-group">
                    <div class="lang-selector-wrapper">
                        <i class="fas fa-globe"></i>
                        <select name="language" id="language-select" onchange="window.location.href='welcome.php?lang=' + this.value;">
                            <option value="en" <?php if($_SESSION['lang'] == 'en') echo 'selected'; ?>>English</option>
                            <option value="es" <?php if($_SESSION['lang'] == 'es') echo 'selected'; ?>>Español</option>
                            <option value="bn" <?php if($_SESSION['lang'] == 'bn') echo 'selected'; ?>>বাংলা</option>
                            <option value="hi" <?php if($_SESSION['lang'] == 'hi') echo 'selected'; ?>>हिन्दी</option>
                            <option value="fr" <?php if($_SESSION['lang'] == 'fr') echo 'selected'; ?>>Français</option>
                            <option value="de" <?php if($_SESSION['lang'] == 'de') echo 'selected'; ?>>Deutsch</option>
                            <option value="pt" <?php if($_SESSION['lang'] == 'pt') echo 'selected'; ?>>Português</option>
                            <option value="ru" <?php if($_SESSION['lang'] == 'ru') echo 'selected'; ?>>Русский</option>
                            <option value="zh" <?php if($_SESSION['lang'] == 'zh') echo 'selected'; ?>>中文</option>
                            <option value="ja" <?php if($_SESSION['lang'] == 'ja') echo 'selected'; ?>>日本語</option>
                        </select>
                    </div>
                    <a href="admin_info.php" class="know-admin-link">
                        <i class="fas fa-user-shield"></i> Know About Admin
                    </a>
                </div>
                <div class="nav-buttons">
                    <a href="register.php" class="btn-signup"><?php echo isset($lang['btn_signup']) ? $lang['btn_signup'] : 'Sign up'; ?></a>
                </div>
            </div>
        </nav>
    </header>

    <main>
        <section class="hero" id="home">
            <div id="three-scene" aria-hidden="true"></div>

            <div class="container">
                <h1 data-aos="fade-up" data-aos-duration="1000"><?php echo isset($lang['hero_title']) ? $lang['hero_title'] : 'Protect your clicks. Protect your data.'; ?></h1>
                <p class="subtitle" data-aos="fade-up" data-aos-delay="200"><?php echo isset($lang['hero_subtitle']) ? $lang['hero_subtitle'] : 'AI-driven phishing protection that scans URLs and warns users in real-time.'; ?></p>
                <a href="register.php" class="cta-button" data-aos="fade-up" data-aos-delay="400"><?php echo isset($lang['hero_cta_button']) ? $lang['hero_cta_button'] : 'Get started — it\'s free'; ?></a>
            </div>
        </section>

        <section id="trusted-by">
            <div class="container" data-aos="zoom-in-up">
                <h3 class="trusted-title"><?php echo isset($lang['trusted_by_title']) ? $lang['trusted_by_title'] : 'Trusted by security teams worldwide'; ?></h3>
                <div class="logos">
                    <img src="images/logo1.png" alt="SecureNet Logo">
                    <img src="images/logo2.png" alt="CyberCorp Logo">
                    <img src="images/logo3.png" alt="DataGuard Logo">
                    <img src="images/logo4.png" alt="NetProtect Logo">
                    <img src="images/logo5.png" alt="InfoSafe Logo">
                </div>
            </div>
        </section>
<section id="about">
    <div class="container">
        <h2 class="section-title" data-aos="fade-up">
            <?php echo isset($lang['about_title']) ? $lang['about_title'] : 'About Us'; ?>
        </h2>
        <p style="text-align:justify;color:var(--text-dark);max-width:850px;margin:0 auto 30px;line-height:1.7;" data-aos="fade-up" data-aos-delay="100">
            <?php echo isset($lang['about_desc']) ? $lang['about_desc'] : 
            'PhishSafeguard is an advanced AI-powered security platform designed to protect individuals, businesses, 
             and organizations from phishing attacks, malicious websites, and online fraud. Our system scans links in 
             real-time, analyzes domain reputation, SSL certificates, redirects, and suspicious behaviors, and instantly 
             delivers a clear risk verdict. 

             Built with state-of-the-art machine learning models, PhishSafeguard not only detects known phishing campaigns 
             but also identifies emerging threats that traditional security tools often miss. We believe that security 
             should be simple, fast, and reliable — that is why our solution combines ease of use with enterprise-grade 
             intelligence. 

             Our mission is to make browsing safe for everyone. Whether you are an individual user, a professional, 
             or part of a large security team, PhishSafeguard empowers you with the tools and insights needed to avoid 
             cyber threats and build digital trust.'; ?>
        </p>
    </div>
</section>
        <section id="how-it-works">
            <div class="container">
                <h2 class="section-title" data-aos="fade-up"><?php echo isset($lang['how_title']) ? $lang['how_title'] : 'How it works'; ?></h2>
                <p style="text-align:center;color:var(--text-dark);max-width:880px;margin:0 auto 30px;" data-aos="fade-up" data-aos-delay="100">
                    <?php echo isset($lang['how_subtitle']) ? $lang['how_subtitle'] : 'PhishSafeguard analyzes link structure, reputation signals and content heuristics in real-time to give you an instant risk score.'; ?>
                </p>
                <div class="how-grid">
                    <div class="how-step" data-aos="fade-up" data-aos-delay="100">
                        <div class="step-num">1</div>
                        <h4><?php echo isset($lang['how_step_1_title']) ? $lang['how_step_1_title'] : 'Input or paste a URL'; ?></h4>
                        <p><?php echo isset($lang['how_step_1_desc']) ? $lang['how_step_1_desc'] : 'Submit any suspicious link via the scanner or browser extension.'; ?></p>
                    </div>
                    <div class="how-step" data-aos="fade-up" data-aos-delay="200">
                        <div class="step-num">2</div>
                        <h4><?php echo isset($lang['how_step_2_title']) ? $lang['how_step_2_title'] : 'AI risk analysis'; ?></h4>
                        <p><?php echo isset($lang['how_step_2_desc']) ? $lang['how_step_2_desc'] : 'Our models analyze domain age, SSL, redirects, content, and known threat feeds.'; ?></p>
                    </div>
                    <div class="how-step" data-aos="fade-up" data-aos-delay="300">
                        <div class="step-num">3</div>
                        <h4><?php echo isset($lang['how_step_3_title']) ? $lang['how_step_3_title'] : 'Actionable verdict'; ?></h4>
                        <p><?php echo isset($lang['how_step_3_desc']) ? $lang['how_step_3_desc'] : 'Receive a clear verdict (safe / suspicious / malicious) and recommended steps.'; ?></p>
                    </div>
                    <div class="how-step" data-aos="fade-up" data-aos-delay="400">
                        <div class="step-num">4</div>
                        <h4><?php echo isset($lang['how_step_4_title']) ? $lang['how_step_4_title'] : 'Community & alerts'; ?></h4>
                        <p><?php echo isset($lang['how_step_4_desc']) ? $lang['how_step_4_desc'] : 'Report phishing to improve the system and get notified about threats.'; ?></p>
                    </div>
                </div>
            </div>
        </section>

        <section id="features">
            <div class="container">
                <h2 class="section-title" data-aos="fade-up"><?php echo isset($lang['features_title']) ? $lang['features_title'] : 'Features'; ?></h2>
                <div class="features-grid">
                    <div class="feature-card" data-aos="flip-left" data-aos-delay="100">
                        <div class="icon"><i class="fas fa-bolt"></i></div>
                        <h3><?php echo isset($lang['feature_1_title']) ? $lang['feature_1_title'] : 'Real-time scanning'; ?></h3>
                        <p><?php echo isset($lang['feature_1_desc']) ? $lang['feature_1_desc'] : 'Detect phishing attacks before you click with millisecond scans.'; ?></p>
                    </div>
                    <div class="feature-card" data-aos="flip-left" data-aos-delay="200">
                        <div class="icon"><i class="fas fa-brain"></i></div>
                        <h3><?php echo isset($lang['feature_2_title']) ? $lang['feature_2_title'] : 'AI heuristics'; ?></h3>
                        <p><?php echo isset($lang['feature_2_desc']) ? $lang['feature_2_desc'] : 'Multiple ML models, ensemble decisions, and explainability.'; ?></p>
                    </div>
                    <div class="feature-card" data-aos="flip-left" data-aos-delay="300">
                        <div class="icon"><i class="fas fa-chart-line"></i></div>
                        <h3><?php echo isset($lang['feature_3_title']) ? $lang['feature_3_title'] : 'Threat analytics'; ?></h3>
                        <p><?php echo isset($lang['feature_3_desc']) ? $lang['feature_3_desc'] : 'Dashboard and logs for security teams.'; ?></p>
                    </div>
                    <div class="feature-card" data-aos="flip-left" data-aos-delay="100">
                        <div class="icon"><i class="fas fa-puzzle-piece"></i></div>
                        <h3><?php echo isset($lang['feature_4_title']) ? $lang['feature_4_title'] : 'Integrations'; ?></h3>
                        <p><?php echo isset($lang['feature_4_desc']) ? $lang['feature_4_desc'] : 'Browser extension, API, and SIEM connectors.'; ?></p>
                    </div>
                    <div class="feature-card" data-aos="flip-left" data-aos-delay="200">
                        <div class="icon"><i class="fas fa-envelope-open-text"></i></div>
                        <h3><?php echo isset($lang['feature_5_title']) ? $lang['feature_5_title'] : 'Email protection'; ?></h3>
                        <p><?php echo isset($lang['feature_5_desc']) ? $lang['feature_5_desc'] : 'Phishing detection for inbound emails and attachments.'; ?></p>
                    </div>
                    <div class="feature-card" data-aos="flip-left" data-aos-delay="300">
                        <div class="icon"><i class="fas fa-bell"></i></div>
                        <h3><?php echo isset($lang['feature_6_title']) ? $lang['feature_6_title'] : 'Instant alerts'; ?></h3>
                        <p><?php echo isset($lang['feature_6_desc']) ? $lang['feature_6_desc'] : 'Real-time notifications and recommended remediation steps.'; ?></p>
                    </div>
                </div>
            </div>
        </section>

        <section id="pricing">
            <div class="container">
                <h2 class="section-title" data-aos="fade-up"><?php echo isset($lang['pricing_title']) ? $lang['pricing_title'] : 'Pricing Plans'; ?></h2>

                <div class="pricing-notice" data-aos="fade-up" data-aos-delay="150">
                    <?php echo isset($lang['pricing_notice']) ? $lang['pricing_notice'] : "Now it's free — time limited offer."; ?>
                    <small><?php echo isset($lang['pricing_notice_small']) ? $lang['pricing_notice_small'] : 'Grab access now. Pricing will apply after the promotional period ends.'; ?></small>
                </div>

                <div class="pricing-grid">
                    <div class="pricing-card" data-aos="zoom-in-up" data-aos-delay="100">
                        <h3><?php echo isset($lang['plan_1_name']) ? $lang['plan_1_name'] : 'Basic'; ?></h3>
                        <div class="price"><?php echo isset($lang['plan_1_price']) ? $lang['plan_1_price'] : '$0'; ?><span>/<?php echo isset($lang['plan_per_month']) ? $lang['plan_per_month'] : 'mo'; ?></span></div>
                        <p class="plan-desc"><?php echo isset($lang['plan_1_desc']) ? $lang['plan_1_desc'] : 'Starter pack for individual users.'; ?></p>
                        <ul>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_1_feature_1']) ? $lang['plan_1_feature_1'] : 'Real-time URL scanning'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_1_feature_2']) ? $lang['plan_1_feature_2'] : 'Community reports'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_1_feature_3']) ? $lang['plan_1_feature_3'] : 'Email alerts'; ?></li>
                        </ul>
                       <a href="login.php?next=<?php echo urlencode('payment.php?plan=basic'); ?>" class="cta-button">
  <?php echo isset($lang['plan_cta_button']) ? $lang['plan_cta_button'] : 'Choose Basic'; ?>
</a>

                    </div>

                    <div class="pricing-card recommended" data-aos="zoom-in-up" data-aos-delay="200">
                        <div class="recommended-badge"><?php echo isset($lang['plan_recommended_badge']) ? $lang['plan_recommended_badge'] : 'Recommended'; ?></div>
                        <h3><?php echo isset($lang['plan_2_name']) ? $lang['plan_2_name'] : 'Pro'; ?></h3>
                        <div class="price"><?php echo isset($lang['plan_2_price']) ? $lang['plan_2_price'] : '$9'; ?><span>/<?php echo isset($lang['plan_per_month']) ? $lang['plan_per_month'] : 'mo'; ?></span></div>
                        <p class="plan-desc"><?php echo isset($lang['plan_2_desc']) ? $lang['plan_2_desc'] : 'Advanced protection for power users.'; ?></p>
                        <ul>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_2_feature_1']) ? $lang['plan_2_feature_1'] : 'Priority scanning'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_2_feature_2']) ? $lang['plan_2_feature_2'] : 'API access'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_2_feature_3']) ? $lang['plan_2_feature_3'] : 'Detailed reports'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_2_feature_4']) ? $lang['plan_2_feature_4'] : 'Integration support'; ?></li>
                        </ul>
                          <a href="login.php?next=<?php echo urlencode('payment.php?plan=pro'); ?>" class="cta-button">
  <?php echo isset($lang['plan_cta_button']) ? $lang['plan_cta_button'] : 'Choose Pro'; ?>
</a>

                    </div>

                    <div class="pricing-card" data-aos="zoom-in-up" data-aos-delay="300">
                        <h3><?php echo isset($lang['plan_3_name']) ? $lang['plan_3_name'] : 'Enterprise'; ?></h3>
                        <div class="price"><?php echo isset($lang['plan_3_price']) ? $lang['plan_3_price'] : 'Custom'; ?></div>
                        <p class="plan-desc"><?php echo isset($lang['plan_3_desc']) ? $lang['plan_3_desc'] : 'Custom solutions for teams and orgs.'; ?></p>
                        <ul>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_3_feature_1']) ? $lang['plan_3_feature_1'] : 'SAML SSO'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_3_feature_2']) ? $lang['plan_3_feature_2'] : 'SLAs'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_3_feature_3']) ? $lang['plan_3_feature_3'] : 'Onboarding & training'; ?></li>
                            <li><i class="fas fa-check-circle"></i><?php echo isset($lang['plan_3_feature_4']) ? $lang['plan_3_feature_4'] : 'Dedicated support'; ?></li>
                        </ul>
                        <a href="support.php" class="cta-button"><?php echo isset($lang['plan_3_cta_button']) ? $lang['plan_3_cta_button'] : 'Contact Sales'; ?></a>
                    </div>
                </div>
            </div>
        </section>

        <section id="blog">
            <div class="container">
                <h2 class="section-title" data-aos="fade-up"><?php echo isset($lang['blog_title']) ? $lang['blog_title'] : 'Latest from our Blog'; ?></h2>
                <p style="text-align:center;color:var(--text-dark);max-width:880px;margin:0 auto 30px;" data-aos="fade-up" data-aos-delay="100">
                    <?php echo isset($lang['blog_subtitle']) ? $lang['blog_subtitle'] : 'Security insights, how-tos, and research updates from the PhishSafeguard team.'; ?>
                </p>

                <div class="blog-grid">
                    <article class="blog-card" data-aos="fade-up" data-aos-delay="100">
                        <div class="thumb" style="background-image:url('images/blog1.jpg');"></div>
                        <div class="card-body">
                            <div class="meta"><?php echo isset($lang['blog_post_1_date']) ? $lang['blog_post_1_date'] : 'Sep 01, 2025'; ?> • <?php echo isset($lang['blog_post_1_author']) ? $lang['blog_post_1_author'] : 'Team'; ?></div>
                            <h3><?php echo isset($lang['blog_post_1_title']) ? $lang['blog_post_1_title'] : '5 Signs a URL is Malicious'; ?></h3>
                            <p><?php echo isset($lang['blog_post_1_excerpt']) ? $lang['blog_post_1_excerpt'] : 'Quick checks you can do to spot phishing links before clicking.'; ?></p>
                            <a class="read-more" href="blog1.php"><?php echo isset($lang['read_more']) ? $lang['read_more'] : 'Read more'; ?> →</a>
                        </div>
                    </article>

                    <article class="blog-card" data-aos="fade-up" data-aos-delay="200">
                        <div class="thumb" style="background-image:url('images/blog2.jpg');"></div>
                        <div class="card-body">
                            <div class="meta"><?php echo isset($lang['blog_post_2_date']) ? $lang['blog_post_2_date'] : 'Aug 20, 2025'; ?> • <?php echo isset($lang['blog_post_2_author']) ? $lang['blog_post_2_author'] : 'Research'; ?></div>
                            <h3><?php echo isset($lang['blog_post_2_title']) ? $lang['blog_post_2_title'] : 'Why Domain Age Matters'; ?></h3>
                            <p><?php echo isset($lang['blog_post_2_excerpt']) ? $lang['blog_post_2_excerpt'] : 'How registrant age influences trust signals in ML models.'; ?></p>
                            <a class="read-more" href="blog2.php"><?php echo isset($lang['read_more']) ? $lang['read_more'] : 'Read more'; ?> →</a>
                        </div>
                    </article>

                    <article class="blog-card" data-aos="fade-up" data-aos-delay="300">
                        <div class="thumb" style="background-image:url('images/blog3.jpg');"></div>
                        <div class="card-body">
                            <div class="meta"><?php echo isset($lang['blog_post_3_date']) ? $lang['blog_post_3_date'] : 'Jul 30, 2025'; ?> • <?php echo isset($lang['blog_post_3_author']) ? $lang['blog_post_3_author'] : 'Engineering'; ?></div>
                            <h3><?php echo isset($lang['blog_post_3_title']) ? $lang['blog_post_3_title'] : 'Building a Fast URL Scanner'; ?></h3>
                            <p><?php echo isset($lang['blog_post_3_excerpt']) ? $lang['blog_post_3_excerpt'] : 'Techniques behind low-latency link analysis at scale.'; ?></p>
                            <a class="read-more" href="blog3.php"><?php echo isset($lang['read_more']) ? $lang['read_more'] : 'Read more'; ?> →</a>
                        </div>
                    </article>
                </div>

                <div style="text-align:center;margin-top:28px;">
                    <a href="blogindex.php" class="cta-button" style="background-color:transparent;border:1px solid var(--accent-cyan);color:var(--accent-cyan)"><?php echo isset($lang['blog_view_all']) ? $lang['blog_view_all'] : 'View all posts'; ?></a>
                </div>
            </div>
        </section>

        <section id="stats">
            <div class="container">
                <h2 class="section-title" data-aos="zoom-in-up"><?php echo isset($lang['impact_title']) ? $lang['impact_title'] : 'Our Impact'; ?></h2>
                <div class="stats-grid">
                    <div class="stat-item" data-aos="fade-up" data-aos-delay="100"><span class="stat-number" data-target="1572890">0</span><p class="stat-label"><?php echo isset($lang['impact_stat_1']) ? $lang['impact_stat_1'] : 'Links scanned'; ?></p></div>
                    <div class="stat-item" data-aos="fade-up" data-aos-delay="200"><span class="stat-number" data-target="325460">0</span><p class="stat-label"><?php echo isset($lang['impact_stat_2']) ? $lang['impact_stat_2'] : 'Threats detected'; ?></p></div>
                    <div class="stat-item" data-aos="fade-up" data-aos-delay="300"><span class="stat-number" data-target="95000">0</span><p class="stat-label"><?php echo isset($lang['impact_stat_3']) ? $lang['impact_stat_3'] : 'Protected users'; ?></p></div>
                </div>
            </div>
        </section>
        
        <section id="testimonials">
            <div class="container">
                <h2 class="section-title" data-aos="fade-up"><?php echo isset($lang['reviews_title']) ? $lang['reviews_title'] : 'What users say'; ?></h2>
                <div class="swiper-container" data-aos="fade-up" data-aos-delay="200">
                    <div class="swiper-wrapper">
                        <?php for ($i = 1; $i <= 10; $i++): ?>
                        <div class="swiper-slide">
                            <div class="testimonial-card">
                                <p><?php echo isset($lang['testimonial_'.$i.'_text']) ? $lang['testimonial_'.$i.'_text'] : 'PhishSafeguard stopped a phishing attempt I would have clicked.'; ?></p>
                                <div class="testimonial-author">
                                    <img src="https://i.pravatar.cc/150?u=user<?php echo $i; ?>" alt="User <?php echo $i; ?>">
                                    <div class="author-info">
                                        <h4><?php echo isset($lang['testimonial_'.$i.'_author']) ? $lang['testimonial_'.$i.'_author'] : 'User '.$i; ?></h4>
                                        <span><?php echo isset($lang['testimonial_'.$i.'_role']) ? $lang['testimonial_'.$i.'_role'] : 'Customer'; ?></span>
                                        <div class="stars"><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <?php endfor; ?>
                    </div>
                    <div class="swiper-pagination"></div>
                    <div class="swiper-button-next"></div>
                    <div class="swiper-button-prev"></div>
                </div>
            </div>
        </section>
        
        <section id="faq">
            <div class="container">
                <h2 class="section-title" data-aos="fade-up"><?php echo isset($lang['faq_title']) ? $lang['faq_title'] : 'Frequently asked questions'; ?></h2>
                <div class="faq-container" data-aos="fade-up" data-aos-delay="200">
                    <?php for ($i = 1; $i <= 10; $i++): ?>
                    <div class="faq-item">
                        <button class="faq-question"><?php echo isset($lang['faq_'.$i.'_q']) ? $lang['faq_'.$i.'_q'] : 'Question '.$i; ?></button>
                        <div class="faq-answer"><p><?php echo isset($lang['faq_'.$i.'_a']) ? $lang['faq_'.$i.'_a'] : 'Answer to question '.$i; ?></p></div>
                    </div>
                    <?php endfor; ?>
                </div>
            </div>
        </section>

        <section id="cta">
            <div class="container" data-aos="zoom-in" data-aos-duration="1000">
                <h2><?php echo isset($lang['cta_title']) ? $lang['cta_title'] : 'Start protecting today'; ?></h2>
                <p><?php echo isset($lang['cta_desc']) ? $lang['cta_desc'] : 'Sign up and get access to our time-limited free plan.'; ?></p>
                <a href="register.php" class="cta-button"><?php echo isset($lang['cta_button']) ? $lang['cta_button'] : 'Create account'; ?></a>
            </div>
        </section>
    </main>

    <footer class="footer">
        <div class="container">
            <a href="welcome.php" class="brand-logo" style="justify-content: center; margin-bottom: 20px;">
                <i class="fa-solid fa-shield-halved"></i>
                <span class="logo-text">PhishSafeguard</span>
            </a>
            
            <ul class="footer-links">
                <li><a href="privacy.php"><?php echo isset($lang['footer_privacy']) ? $lang['footer_privacy'] : 'Privacy'; ?></a></li>
                <li><a href="terms.php"><?php echo isset($lang['footer_terms']) ? $lang['footer_terms'] : 'Terms'; ?></a></li>
                <li><a href="support.php"><?php echo isset($lang['footer_contact']) ? $lang['footer_contact'] : 'Contact'; ?></a></li>
            </ul>
            <p class="copyright"><?php echo isset($lang['footer_copyright']) ? $lang['footer_copyright'] : '© '.date('Y').' PhishSafeguard. All rights reserved.'; ?></p>
        </div>
    </footer>
    
    <div id="cookie-banner">
        <p><?php echo isset($lang['cookie_text']) ? $lang['cookie_text'] : 'We use cookies to improve your experience.'; ?></p>
        <button id="accept-cookies"><?php echo isset($lang['cookie_button']) ? $lang['cookie_button'] : 'Accept'; ?></button>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/tsparticles@2.12.0/tsparticles.bundle.min.js"></script>
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.js"></script>
    <script src="https://unpkg.com/typed.js@2.1.0/dist/typed.umd.js"></script>

    <script src="https://unpkg.com/three@0.152.0/build/three.min.js"></script>

    <script>
        AOS.init({ duration: 800, once: true, easing: 'ease-out-cubic', offset: 50 });
        
        const backgroundChoice = 'matrix'; // 'particles' or 'matrix' or 'none'

        const particlesConfig = {
            background: { color: { value: "#0a192f" } }, fpsLimit: 60,
            interactivity: { events: { onHover: { enable: true, mode: "grab" }, resize: true, }, modes: { grab: { distance: 140, line_linked: { opacity: 1 } }, }, },
            particles: { color: { value: "#ffffff" }, links: { color: "#ffffff", distance: 150, enable: true, opacity: 0.1, width: 1, }, collisions: { enable: true }, move: { direction: "none", enable: true, outMode: "bounce", random: false, speed: 1, straight: false, }, number: { density: { enable: true, area: 800 }, value: 80 }, opacity: { value: 0.1 }, shape: { type: "circle" }, size: { value: { min: 1, max: 5 } }, },
            detectRetina: true,
        };

        const matrixConfig = {
            background: { color: { value: "#0a192f" } },
            fpsLimit: 60,
            particles: {
                number: { value: 150, density: { enable: true, value_area: 800 } },
                color: { value: "#64ffda" },
                shape: {
                    type: "character",
                    character: { value: ["0", "1"], font: "Poppins", style: "", weight: "400" },
                },
                opacity: { value: {min: 0.1, max: 0.6}, animation: { enable: true, speed: 1.5, minimumValue: 0.1, sync: false } },
                size: { value: 10 },
                move: { enable: true, direction: "bottom", speed: 1.5, random: false, straight: true, out_mode: "out" },
            },
            interactivity: { detect_on: "canvas", events: { onhover: { enable: false }, onclick: { enable: false }, resize: true } },
            detectRetina: true,
        };
        
        if (backgroundChoice === 'matrix') {
            tsParticles.load("particles-js", matrixConfig);
        } else if (backgroundChoice === 'particles') {
            tsParticles.load("particles-js", particlesConfig);
        } else {
            // do nothing
        }

        const swiper = new Swiper('.swiper-container', {
            loop: true,
            slidesPerView: 1,
            spaceBetween: 30,
            autoplay: { delay: 4000, disableOnInteraction: false, },
            pagination: { el: '.swiper-pagination', clickable: true, },
            navigation: { nextEl: '.swiper-button-next', prevEl: '.swiper-button-prev', },
            breakpoints: { 640: { slidesPerView: 1, }, 768: { slidesPerView: 2, }, 1024: { slidesPerView: 3, } }
        });
        
        document.addEventListener('DOMContentLoaded', function () {
            // Typed.js initialization
            try {
                const typedStrings = [
                    <?php echo isset($lang['typed_string_1']) ? json_encode($lang['typed_string_1']) : json_encode('Detect threats'); ?>,
                    <?php echo isset($lang['typed_string_2']) ? json_encode($lang['typed_string_2']) : json_encode('Block malicious links'); ?>,
                    <?php echo isset($lang['typed_string_3']) ? json_encode($lang['typed_string_3']) : json_encode('Stay secure online'); ?>
                ];
                const heroTitleElement = document.querySelector('.hero h1');
                if (heroTitleElement) {
                    const staticTitlePart = (<?php echo json_encode(isset($lang['hero_title']) ? $lang['hero_title'] : 'Protect your clicks. Protect your data.'); ?>).split('<span>')[0];
                    heroTitleElement.innerHTML = staticTitlePart + '<span></span>';
                    new Typed(heroTitleElement.querySelector('span'), {
                        strings: typedStrings, typeSpeed: 50, backSpeed: 25, backDelay: 2000, loop: true,
                    });
                }
            } catch (e) { /* silent */ }

            // Header scroll
            const header = document.getElementById('header');
            window.addEventListener('scroll', () => header.classList.toggle('scrolled', window.scrollY > 50));

            // Cookie banner
            const cookieBanner = document.getElementById('cookie-banner');
            const acceptCookiesBtn = document.getElementById('accept-cookies');
            if (!localStorage.getItem('cookie_consent')) {
                 setTimeout(() => { cookieBanner.classList.add('show'); }, 2000);
            }
            acceptCookiesBtn.addEventListener('click', () => {
                cookieBanner.classList.remove('show');
                localStorage.setItem('cookie_consent', 'accepted');
            });

            // FAQ toggle
            const faqItems = document.querySelectorAll('.faq-item');
            faqItems.forEach(item => {
                const question = item.querySelector('.faq-question');
                question.addEventListener('click', () => {
                    const currentlyActive = document.querySelector('.faq-item.active');
                    if (currentlyActive && currentlyActive !== item) {
                        currentlyActive.classList.remove('active');
                        currentlyActive.querySelector('.faq-answer').style.maxHeight = 0;
                    }
                    item.classList.toggle('active');
                    const answer = item.querySelector('.faq-answer');
                    answer.style.maxHeight = item.classList.contains('active') ? answer.scrollHeight + "px" : 0;
                });
            });

            // Stats counter when visible
            const statsObserver = new IntersectionObserver((entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const counters = entry.target.querySelectorAll('.stat-number');
                        counters.forEach(counter => {
                            const target = +counter.getAttribute('data-target');
                            const duration = 2000;
                            let current = 0;
                            const increment = target / (duration / 16);
                            const updateCount = () => {
                                current += increment;
                                if (current < target) {
                                    counter.innerText = Math.ceil(current).toLocaleString();
                                    requestAnimationFrame(updateCount);
                                } else {
                                    counter.innerText = target.toLocaleString();
                                }
                            };
                            requestAnimationFrame(updateCount);
                        });
                        observer.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.5 });
            const statsSection = document.getElementById('stats');
            if(statsSection) {
                 statsObserver.observe(statsSection);
            }

            // --- TILT FUNCTION REMOVED (As per your request in the previous step) ---
            /*
            (function initTilt() {
              ...
            })();
            */
        });

        // --- THREE.JS HERO SCENE (immediately executed) ---
        (function initThreeHero() {
            const container = document.getElementById('three-scene');
            if (!container) return;

            if (window.innerWidth < 768) {
                return;
            }

            const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
            renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
            renderer.setSize(container.clientWidth, container.clientHeight);
            renderer.domElement.style.display = 'block';
            container.appendChild(renderer.domElement);

            const scene = new THREE.Scene();
            const camera = new THREE.PerspectiveCamera(45, container.clientWidth / container.clientHeight, 0.1, 1000);
            camera.position.set(0, 0, 50);

            const hemi = new THREE.HemisphereLight(0xffffff, 0x080820, 0.6);
            scene.add(hemi);
            const dir = new THREE.DirectionalLight(0xffffff, 0.8);
            dir.position.set(5, 10, 10);
            scene.add(dir);

            const geom = new THREE.TorusKnotGeometry(10, 2.8, 160, 28);
            const mat = new THREE.MeshStandardMaterial({
                color: 0x64ffda,
                metalness: 0.25,
                roughness: 0.3,
                emissive: 0x002a21,
                emissiveIntensity: 0.8,
                transparent: true,
                opacity: 0.95
            });
            const mesh = new THREE.Mesh(geom, mat);
            mesh.rotation.x = Math.PI * 0.15;
            scene.add(mesh);

            const ptsGeom = new THREE.BufferGeometry();
            const count = 300;
            const pos = new Float32Array(count * 3);
            for (let i = 0; i < count; i++) {
                const r = 30 + Math.random() * 40;
                const phi = Math.random() * Math.PI * 2;
                const theta = (Math.random() - 0.5) * Math.PI;
                pos[i*3] = Math.cos(phi) * Math.cos(theta) * r;
                pos[i*3+1] = Math.sin(theta) * r * 0.6;
                pos[i*3+2] = Math.sin(phi) * Math.cos(theta) * r;
            }
            ptsGeom.setAttribute('position', new THREE.BufferAttribute(pos, 3));
            const ptsMat = new THREE.PointsMaterial({ size: 0.7, color: 0x64ffda, opacity: 0.06, transparent: true });
            const points = new THREE.Points(ptsGeom, ptsMat);
            scene.add(points);

            function onResize() {
                const w = container.clientWidth;
                const h = container.clientHeight;
                renderer.setSize(w, h);
                camera.aspect = w / h;
                camera.updateProjectionMatrix();
            }
            window.addEventListener('resize', onResize);

            let mouseX = 0, mouseY = 0;
            window.addEventListener('mousemove', (e) => {
                mouseX = (e.clientX / window.innerWidth) * 2 - 1;
                mouseY = -(e.clientY / window.innerHeight) * 2 + 1;
            });

            let t = 0;
            function animate() {
                t += 0.01;
                mesh.rotation.y += 0.005;
                mesh.rotation.x += 0.002;
                mesh.position.y = Math.sin(t * 0.7) * 1.5;
                points.rotation.y = t * 0.1;

                camera.position.x += (mouseX * 8 - camera.position.x) * 0.05;
                camera.position.y += (mouseY * 6 - camera.position.y) * 0.05;
                camera.lookAt(scene.position);

                renderer.render(scene, camera);
                requestAnimationFrame(animate);
            }
            animate();

            window.addEventListener('unload', () => {
                renderer.dispose();
            });
        })();
    </script>
</body>
</html>