<?php
if (session_status() === PHP_SESSION_NONE) { session_start(); }

/* NEW: always keep plan in sync from DB (refresh if missing/old)
   create plan_sync.php as shared earlier and place it in same folder */
require_once __DIR__ . '/plan_sync.php';

$tier      = strtolower($_SESSION['user_tier'] ?? $_SESSION['subscribed_plan'] ?? '');
$isPremium = (int)($_SESSION['is_premium'] ?? 0);
$flash     = $_SESSION['flash'] ?? '';
if ($flash) unset($_SESSION['flash']);

// Simple active link helper
$current = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
function active($file, $current) { return $current === $file ? 'class="nav-link active"' : 'class="nav-link"'; }
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishSafeguard</title>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
  :root{
    --bg:#071427; --panel:#0f1e39; --panel2:#0b1628; --text:#cfe1ff; --muted:#8ea0c7;
    --accent:#64ffda; --border:rgba(100,255,218,.12); --ok:#30d158; --error:#ff6b6b;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:Poppins,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}
  /* page entrance */
  body:not(.loaded) .topbar{opacity:0;transform:translateY(-8px);filter:blur(6px)}
  body.loaded .topbar{animation:topIn .5s cubic-bezier(.2,.9,.2,1) both}
  @keyframes topIn{from{opacity:0;transform:translateY(-8px);filter:blur(6px)}to{opacity:1;transform:none;filter:none}}

  .topbar{
    position:sticky; top:0; z-index:1000;
    display:flex; align-items:center; justify-content:space-between; gap:12px;
    padding:10px 16px;
    background:#0f1e39cc; backdrop-filter:saturate(1.2) blur(6px);
    border-bottom:1px solid var(--border);
    box-shadow:0 8px 24px rgba(0,0,0,.35);
  }
  .brand{display:flex;align-items:center;gap:10px;font-weight:800;color:var(--accent)}
  .logo{height:32px;width:32px;border-radius:8px;background:linear-gradient(180deg,#08243f,#0b2a4a);
        display:flex;align-items:center;justify-content:center;font-weight:900;color:#d8fff0}
  .right{display:flex;align-items:center;gap:10px}
  .badge{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;
         background:rgba(100,255,218,.10);border:1px solid rgba(100,255,218,.35);color:var(--accent);font-weight:700}
  .nav-link{color:#cfe1ff;text-decoration:none;padding:6px 10px;border-radius:8px;border:1px solid transparent}
  .nav-link:hover{background:rgba(255,255,255,.04);border-color:rgba(255,255,255,.06)}
  .nav-link.active{background:rgba(100,255,218,.10);border-color:rgba(100,255,218,.35);color:var(--accent)}

  .flash{
    max-width:980px;margin:14px auto 0; padding:10px 14px;border-radius:12px;
    background:rgba(48,209,88,.08); border:1px solid rgba(48,209,88,.25); color:#c8ffd9;
    box-shadow:0 10px 30px rgba(0,0,0,.35);
    opacity:0; transform:translateY(-6px);
    animation:flashIn .4s ease-out .1s forwards;
  }
  @keyframes flashIn{to{opacity:1;transform:none}}

  /* page container to wrap content (footer closes it) */
  .page-wrap{max-width:980px;margin:18px auto;padding:0 16px 24px}
</style>
</head>
<body>
<script>document.addEventListener('DOMContentLoaded',()=>document.body.classList.add('loaded'));</script>

<!-- Topbar -->
<div class="topbar">
  <div class="brand">
    <div class="logo">PS</div>
    <div>PhishSafeguard</div>
  </div>
  <div class="right">
    <?php if (!empty($_SESSION['user_id']) && $isPremium === 1): ?>
      <span class="badge"><i class="fa-solid fa-crown"></i> Premium user</span>
    <?php endif; ?>
    <a <?=active('index.php', $current)?> href="index.php"><i class="fa-solid fa-house"></i> Home</a>
    <a <?=active('pricing.php', $current)?> href="pricing.php"><i class="fa-solid fa-tag"></i> Pricing</a>
    <?php if (!empty($_SESSION['user_id'])): ?>
      <a class="nav-link" href="logout.php"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
    <?php else: ?>
      <a class="nav-link" href="login.php"><i class="fa-solid fa-right-to-bracket"></i> Login</a>
    <?php endif; ?>
  </div>
</div>

<?php if (!empty($flash)): ?>
  <div class="flash"><i class="fa-solid fa-circle-check"></i> <?=htmlspecialchars($flash)?></div>
<?php endif; ?>

<!-- Page content starts -->
<main class="page-wrap">
