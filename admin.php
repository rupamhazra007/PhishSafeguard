<?php
// admin.php — PhishSafeguard (The Godfather Style Intro)
// Requires: helpers.php (ensure_auth, current_user, db)

require_once __DIR__ . '/helpers_db.php';

ensure_auth();
if(!(isset(current_user()['is_admin']) ? current_user()['is_admin'] : 0)){
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$conn = db();

// Ensure session & CSRF token
if(session_status() !== PHP_SESSION_ACTIVE) session_start();
if(empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(24));
}
$csrf = $_SESSION['csrf_token'];

// ------------- Handle POST actions ----------------
if($_SERVER['REQUEST_METHOD'] === 'POST') {
    $valid_csrf = true;
    if($csrf) {
        if(!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $csrf) {
            $valid_csrf = false;
        }
    }

    // 1) Single verify
    if(isset($_POST['verify']) && isset($_POST['id'])) {
        if($valid_csrf) {
            $id = (int)$_POST['id'];
            $stmt = $conn->prepare("UPDATE url_checks SET verified_by_admin=1 WHERE id=?");
            if($stmt){ $stmt->bind_param("i",$id); $stmt->execute(); $stmt->close(); }
            header("Location: admin.php"); exit;
        }
    }
    // 1b) Unverify single
    if(isset($_POST['unverify']) && isset($_POST['id'])) {
        if($valid_csrf) {
            $id = (int)$_POST['id'];
            $stmt = $conn->prepare("UPDATE url_checks SET verified_by_admin=0 WHERE id=?");
            if($stmt){ $stmt->bind_param("i",$id); $stmt->execute(); $stmt->close(); }
            header("Location: admin.php"); exit;
        }
    }
    // 2) Delete single
    if(isset($_POST['delete']) && isset($_POST['id'])) {
        if($valid_csrf) {
            $id = (int)$_POST['id'];
            $stmt = $conn->prepare("DELETE FROM url_checks WHERE id=?");
            if($stmt){ $stmt->bind_param("i",$id); $stmt->execute(); $stmt->close(); }
            header("Location: admin.php"); exit;
        }
    }
    // 3) Bulk verify
    if(isset($_POST['bulk_verify']) && !empty($_POST['ids']) && is_array($_POST['ids'])) {
        if($valid_csrf) {
            $ids = array_map('intval', $_POST['ids']);
            if(count($ids) > 0) {
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $types = str_repeat('i', count($ids));
                $sql = "UPDATE url_checks SET verified_by_admin=1 WHERE id IN ($placeholders)";
                $stmt = $conn->prepare($sql);
                if($stmt){
                    $refs = []; foreach($ids as $k => $v) $refs[$k] = &$ids[$k];
                    array_unshift($refs, $types); call_user_func_array([$stmt, 'bind_param'], $refs);
                    $stmt->execute(); $stmt->close();
                } else { $conn->query("UPDATE url_checks SET verified_by_admin=1 WHERE id IN (".implode(',', $ids).")"); }
            }
            header("Location: admin.php"); exit;
        }
    }
    // 4) Export CSV
    if(isset($_POST['export_csv'])) {
        if($valid_csrf) {
            $ids = [];
            if(!empty($_POST['ids']) && is_array($_POST['ids'])) $ids = array_map('intval', $_POST['ids']);
            if(count($ids)>0) {
                $placeholders = implode(',', array_fill(0,count($ids),'?'));
                $res = $conn->query("SELECT id,url,result,checked_at,verified_by_admin FROM url_checks WHERE id IN (" . implode(',', $ids) . ") ORDER BY checked_at DESC");
            } else {
                $res = $conn->query("SELECT id,url,result,checked_at,verified_by_admin FROM url_checks ORDER BY checked_at DESC LIMIT 300");
            }
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename=phishsafeguard_checks_'.date('Ymd_His').'.csv');
            $out = fopen('php://output','w');
            fputcsv($out, ['ID','URL','Result','Checked At','Verified']);
            while($row = $res->fetch_assoc()) {
                fputcsv($out, [$row['id'],$row['url'],$row['result'],$row['checked_at'],$row['verified_by_admin'] ? 'Yes' : 'No']);
            }
            fclose($out); exit;
        }
    }
    // 5) Blacklist add
    if(isset($_POST['add_blacklist']) && !empty($_POST['domain'])) {
        if($valid_csrf) {
            $domain = preg_replace('/^https?:\\/\\//','', trim($_POST['domain']));
            $domain = preg_replace('/^www\\./','', $domain);
            $domain = strtolower($domain);
            if($domain) {
                $stmt = $conn->prepare("INSERT INTO blacklist (domain, added_by) VALUES (?, ?)");
                if($stmt){
                    $uid = isset(current_user()['id']) ? current_user()['id'] : null;
                    $stmt->bind_param("si", $domain, $uid); $stmt->execute(); $stmt->close();
                }
            }
            header("Location: admin.php"); exit;
        }
    }
    // 6) Blacklist remove
    if(isset($_POST['remove_blacklist']) && isset($_POST['bid'])) {
        if($valid_csrf) {
            $bid = (int)$_POST['bid'];
            $stmt = $conn->prepare("DELETE FROM blacklist WHERE id=?");
            if($stmt){ $stmt->bind_param("i",$bid); $stmt->execute(); $stmt->close(); }
            header("Location: admin.php"); exit;
        }
    }
}

// ----------------- Load data --------------------
$counts = ['total' => 0, 'phishing' => 0, 'safe' => 0, 'suspicious' => 0];
$cres = $conn->query("SELECT COUNT(*) AS total, SUM(result LIKE '%phish%') AS phish, SUM(result LIKE '%safe%') AS safe, SUM(result LIKE '%susp%') AS susp FROM url_checks");
if($cres){
    $c = $cres->fetch_assoc();
    $counts['total'] = (int)$c['total'];
    $counts['phishing'] = (int)$c['phish'];
    $counts['safe'] = (int)$c['safe'];
    $counts['suspicious'] = (int)$c['susp'];
}

$res = $conn->query("SELECT id,url,result,checked_at,verified_by_admin FROM url_checks ORDER BY checked_at DESC LIMIT 300");
$rows = [];
if($res){ while($r = $res->fetch_assoc()) $rows[] = $r; }

$bl = $conn->query("SELECT id,domain,added_by,added_at FROM blacklist ORDER BY added_at DESC LIMIT 200");
$blacklist = [];
if($bl) while($b = $bl->fetch_assoc()) $blacklist[] = $b;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Dashboard | PhishSafeguard</title>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap/dist/css/jsvectormap.min.css" />
<script src="https://cdn.jsdelivr.net/npm/jsvectormap/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap/dist/maps/world.js"></script>

<style>
  :root {
    /* Base Theme */
    --bg-body: #0f172a; 
    --glass-bg: rgba(30, 41, 59, 0.45); 
    --glass-border: rgba(255, 255, 255, 0.15);
    --glass-shine: rgba(255, 255, 255, 0.05);
    
    --text-main: #f1f5f9;
    --text-muted: #94a3b8;
    
    --primary: #6366f1;
    --primary-hover: #4f46e5;
    --accent: #38bdf8;
    --danger: #f43f5e;
    --success: #10b981;
    --warning: #f59e0b;
    
    --card-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.25);
    --input-bg: rgba(15, 23, 42, 0.6); 
    --border-radius: 20px;
    --backdrop-blur: 20px;
  }

  body.light-mode {
    --bg-body: #f1f5f9;
    --glass-bg: rgba(255, 255, 255, 0.70);
    --glass-border: rgba(0, 0, 0, 0.08);
    --text-main: #0f172a;
    --text-muted: #475569;
    --input-bg: rgba(255, 255, 255, 0.7);
    --card-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.1);
  }

  * { box-sizing: border-box; outline: none; -webkit-font-smoothing: antialiased; }
  html { scroll-behavior: smooth; }

  body { 
    margin: 0; 
    font-family: 'Plus Jakarta Sans', sans-serif; 
    background-color: var(--bg-body); 
    background-image: linear-gradient(to bottom, rgba(15, 23, 42, 0.7), rgba(15, 23, 42, 0.8)), url('G.jpg'); 
    background-size: cover; 
    background-position: center; 
    background-attachment: fixed; 
    color: var(--text-main); 
    min-height: 100vh; 
    transition: background 0.3s ease, color 0.3s ease; 
    overflow-x: hidden; 
  }

  /* --- POWERFUL BOSS INTRO --- */
  #welcome-splash { 
      position: fixed; inset: 0; background: #000; z-index: 10000; 
      display: flex; flex-direction: column; justify-content: center; align-items: center; 
      /* Reduced delay, snappy exit */
      animation: splashExit 0.6s cubic-bezier(0.7, 0, 0.3, 1) 4.0s forwards; 
  }
  
  .power-container {
      text-align: center;
      /* STRONG SERIF FONT FOR THAT "BOSS" VIBE */
      font-family: 'Times New Roman', Times, serif;
      text-transform: uppercase;
  }

  .line-1, .line-2 {
      font-weight: 700;
      letter-spacing: 3px;
      color: var(--text-muted);
      opacity: 0;
      font-size: 1.5rem;
      transform: translateY(20px);
  }

  .line-1 { animation: quickFadeUp 0.5s ease forwards 0.5s; } /* Welcome Back */
  .line-2 { animation: quickFadeUp 0.5s ease forwards 1.2s; color: #fff; font-size: 2rem; letter-spacing: 5px; } /* BOSS */

  .power-name-reveal {
      margin-top: 20px;
      font-size: 4rem;
      font-weight: 900;
      line-height: 1;
      opacity: 0;
      /* "Boom" effect */
      animation: powerReveal 0.8s cubic-bezier(0.19, 1, 0.22, 1) forwards 2.0s;
      position: relative;
  }

  /* Glitch & Glow Effect on Name */
  .glitch {
      position: relative;
      color: #fff;
      font-style: italic; /* Adds a bit more class */
      text-shadow: 0 0 20px rgba(255, 255, 255, 0.5);
  }
  .glitch::before, .glitch::after {
      content: attr(data-text);
      position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.8;
  }
  .glitch::before {
      color: var(--accent); z-index: -1; animation: glitch-anim 0.3s infinite;
  }
  .glitch::after {
      color: var(--primary); z-index: -2; animation: glitch-anim-2 0.3s infinite linear alternate-reverse;
  }

  @keyframes quickFadeUp { to { opacity: 1; transform: translateY(0); } }
  @keyframes powerReveal { 
      0% { opacity: 0; transform: scale(1.3); filter: blur(10px); }
      100% { opacity: 1; transform: scale(1); filter: blur(0); }
  }
  @keyframes splashExit { to { opacity: 0; pointer-events: none; visibility: hidden; transform: scale(1.05); } }
  
  @keyframes glitch-anim {
    0% { clip-path: inset(10% 0 85% 0); transform: translate(-2px); }
    100% { clip-path: inset(85% 0 10% 0); transform: translate(2px); }
  }
  @keyframes glitch-anim-2 {
    0% { clip-path: inset(20% 0 70% 0); transform: translate(2px); }
    100% { clip-path: inset(70% 0 20% 0); transform: translate(-2px); }
  }

  /* Standard UI */
  .container { max-width: 1450px; margin: 0 auto; padding: 40px 24px; }
  .reveal-on-scroll { opacity: 0; transform: translateY(50px) scale(0.98); transition: all 1s cubic-bezier(0.2, 0.8, 0.2, 1); }
  .reveal-on-scroll.active { opacity: 1; transform: translateY(0) scale(1); }

  .glass-panel { background: var(--glass-bg); backdrop-filter: blur(var(--backdrop-blur)); border: 1px solid var(--glass-border); border-top: 1px solid var(--glass-shine); border-radius: var(--border-radius); box-shadow: var(--card-shadow); padding: 30px; margin-bottom: 30px; position: relative; overflow: hidden; transition: transform 0.3s ease; }
  .glass-panel:hover { transform: translateY(-2px); }
  
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; padding: 20px 30px; background: var(--glass-bg); backdrop-filter: blur(var(--backdrop-blur)); border: 1px solid var(--glass-border); border-radius: var(--border-radius); }
  .brand-logo { width: 48px; height: 48px; background: linear-gradient(135deg, var(--primary), #818cf8); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 800; font-size: 20px; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4); }
  
  .nav-btn { display: inline-flex; align-items: center; gap: 8px; padding: 10px 18px; border-radius: 10px; background: var(--input-bg); border: 1px solid var(--glass-border); color: var(--text-muted); font-weight: 600; font-size: 14px; cursor: pointer; transition: all 0.2s; }
  .nav-btn:hover { background: rgba(255,255,255,0.1); color: var(--text-main); border-color: rgba(255,255,255,0.3); }
  .nav-btn.primary { background: var(--primary); color: #fff; border: 1px solid transparent; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4); }

  /* Toolbar */
  .toolbar { display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: center; margin-bottom: 30px; }
  .search-group { display: flex; align-items: center; gap: 12px; background: var(--input-bg); padding: 10px 16px; border-radius: 12px; border: 1px solid var(--glass-border); transition: all 0.2s; width: 100%; max-width: 420px; }
  .search-group input { background: transparent !important; border: none !important; width: 100%; font-size: 14px; color: var(--text-main) !important; }
  .search-group i { color: var(--text-muted); font-size: 14px; }

  select { padding: 10px 32px 10px 16px; border-radius: 12px; cursor: pointer; font-family: inherit; font-size: 14px; background: var(--input-bg) !important; border: 1px solid var(--glass-border) !important; color: var(--text-main) !important; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2394a3b8' viewBox='0 0 16 16'%3E%3Cpath d='M7.247 11.14 2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; }
  select option { background: #0f172a; color: #fff; }
  body.light-mode select option { background: #fff; color: #000; }

  /* Stats */
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 24px; margin-bottom: 24px; }
  .stat-card { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: var(--border-radius); padding: 24px; display: flex; flex-direction: column; transition: 0.3s; }
  .stat-card:hover { transform: translateY(-5px); background: rgba(255,255,255,0.08); }
  .stat-val { font-size: 36px; font-weight: 700; margin-top: 12px; color: var(--text-main); }
  
  /* Analytics */
  .analytics-row { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 30px; }
  .analytics-row.reverse { grid-template-columns: 1fr 2fr; }
  @media(max-width: 900px) { .analytics-row, .analytics-row.reverse { grid-template-columns: 1fr; } }
  .chart-container { position: relative; height: 300px; width: 100%; }
  .chart-title { font-size: 16px; font-weight: 700; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; color: var(--text-main); text-transform: uppercase; letter-spacing: 1px; }
  
  /* Table */
  .table-responsive { overflow-x: auto; border-radius: 12px; border: 1px solid var(--glass-border); }
  table { width: 100%; border-collapse: collapse; }
  thead th { background: rgba(255,255,255,0.05); color: var(--text-muted); font-size: 12px; font-weight: 700; text-transform: uppercase; padding: 18px 24px; text-align: left; border-bottom: 1px solid var(--glass-border); }
  td { padding: 18px 24px; font-size: 14px; border-bottom: 1px solid var(--glass-border); color: var(--text-main); vertical-align: middle; }
  tbody tr { transition: background 0.2s; }
  tbody tr:hover { background: rgba(255,255,255,0.05); }
  
  .status-badge { padding: 6px 12px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; display: inline-flex; align-items: center; gap: 6px; }
  .status-badge.safe { background: rgba(16, 185, 129, 0.15); color: var(--success); }
  .status-badge.phish { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
  .status-badge.susp { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
  
  .icon-btn { width: 34px; height: 34px; border-radius: 8px; border: none; display: inline-flex; align-items: center; justify-content: center; background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s; }
  .icon-btn:hover { background: var(--glass-border); color: var(--text-main); transform: scale(1.1); }

  /* Modal */
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(12px); display: none; align-items: center; justify-content: center; z-index: 2000; }
  .modal-box { background: #0f172a; width: 90%; max-width: 650px; border-radius: 20px; border: 1px solid var(--glass-border); box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7); overflow: hidden; animation: slideUp 0.4s cubic-bezier(0.2, 0.8, 0.2, 1); }
  
  /* AI Panel */
  .ai-panel { background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; margin-top: 15px; border: 1px solid var(--glass-border); }
  .ai-score-bar { height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; margin: 8px 0 15px; overflow: hidden; }
  .ai-score-fill { height: 100%; border-radius: 4px; transition: width 1.5s cubic-bezier(0.2, 0.8, 0.2, 1); }
  .factor-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .factor-item { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text-muted); background: rgba(255,255,255,0.03); padding: 8px; border-radius: 8px; }
  .factor-item i { width: 20px; text-align: center; }
  
  #world-map { width: 100%; height: 300px; background: transparent; }
  .jvm-zoom-btn { background-color: var(--input-bg)!important; color: var(--text-main)!important; }
  .jvm-tooltip { background: var(--bg-body); color: var(--text-main); border: 1px solid var(--glass-border); }

  @keyframes slideUp { from { transform: translateY(40px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
</style>
</head>
<body>

<div id="welcome-splash">
    <div class="power-container">
        <div class="line-1">WELCOME BACK</div>
        <div class="line-2">BOSS</div>
        <div class="power-name-reveal">
            <span class="glitch" data-text="MR. RUPAM HAZRA">MR. RUPAM HAZRA</span>
        </div>
    </div>
</div>

<div class="container">
  <header class="header reveal-on-scroll">
    <div style="display:flex; gap:16px; align-items:center;">
      <div class="brand-logo">PS</div>
      <div>
        <h1 style="margin:0; font-size:24px; font-weight:700;">PhishSafeguard</h1>
        <p style="margin:2px 0 0; font-size:13px; color:var(--text-muted);">Admin & Analytics Console</p>
      </div>
    </div>
    <div class="top-actions">
      <button class="nav-btn" id="themeBtn"><i class="fa fa-circle-half-stroke"></i> Theme</button>
      <a href="users.php" class="nav-btn"><i class="fa fa-users"></i> Users</a>
      <a href="index.php" class="nav-btn primary"><i class="fa fa-home"></i> Dashboard</a>
    </div>
  </header>

  <div class="stats-grid reveal-on-scroll">
    <div class="stat-card">
      <div class="stat-label">Total Scans</div>
      <div class="stat-val"><?= number_format($counts['total']) ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Phishing Detected</div>
      <div class="stat-val" style="color:var(--danger)"><?= number_format($counts['phishing']) ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Safe Domains</div>
      <div class="stat-val" style="color:var(--success)"><?= number_format($counts['safe']) ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Suspicious</div>
      <div class="stat-val" style="color:var(--warning)"><?= number_format($counts['suspicious']) ?></div>
    </div>
  </div>

  <div class="analytics-row reveal-on-scroll">
      <div class="glass-panel" style="margin-bottom:0;">
          <div class="chart-title"><i class="fa fa-chart-pie" style="color:var(--primary)"></i> Threat Distribution</div>
          <div class="chart-container">
              <canvas id="distChart"></canvas>
          </div>
      </div>
      <div class="glass-panel" style="margin-bottom:0;">
          <div class="chart-title"><i class="fa fa-gauge-high" style="color:var(--warning)"></i> User Risk Score</div>
          <div class="chart-container" style="display:flex; justify-content:center; align-items:center; position:relative;">
              <canvas id="riskChart"></canvas>
              <div style="position:absolute; top:60%; left:50%; transform:translate(-50%, -50%); text-align:center;">
                  <div style="font-size:24px; font-weight:800; color:var(--text-main);">Low</div>
                  <div style="font-size:12px; color:var(--text-muted);">Avg Risk Level</div>
              </div>
          </div>
      </div>
  </div>

  <div class="analytics-row reverse reveal-on-scroll">
      <div class="glass-panel" style="margin-bottom:0;">
          <div class="chart-title"><i class="fa fa-earth-americas" style="color:var(--accent)"></i> Global Attack Heatmap</div>
          <div id="world-map"></div>
      </div>
      <div class="glass-panel" style="margin-bottom:0;">
          <div class="chart-title"><i class="fa fa-wave-square" style="color:var(--success)"></i> Threat Activity Timeline</div>
          <div class="chart-container">
              <canvas id="timelineChart"></canvas>
          </div>
      </div>
  </div>

  <div class="glass-panel reveal-on-scroll">
    <div class="toolbar">
      <div class="search-group">
        <i class="fa fa-search"></i>
        <input id="tableSearch" placeholder="Search URL or Result...">
      </div>
      <div class="filter-group" style="display:flex; gap:12px;">
        <select id="resultFilter">
          <option value="">All Results</option>
          <option value="safe">Safe Only</option>
          <option value="phishing">Phishing Only</option>
          <option value="suspicious">Suspicious Only</option>
        </select>
        <button class="nav-btn" onclick="selectUnverified()" title="Select Unverified URLs"><i class="fa fa-filter"></i> Unverified</button>
        <button class="nav-btn" onclick="selectAllVisible()"><i class="fa fa-check-double"></i> All</button>
      </div>
      <button class="nav-btn" onclick="exportVisible()"><i class="fa fa-download"></i> CSV</button>
    </div>

    <form id="bulkForm" method="POST" onsubmit="return confirm('Confirm bulk verify?')" class="bulk-bar">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
      <input type="hidden" name="bulk_verify" value="1">
      <span style="font-weight:600; font-size:14px; color:var(--primary);">Bulk:</span>
      <button type="submit" class="nav-btn primary" style="padding: 6px 12px; font-size:12px;">Verify</button>
      <span style="margin-left:auto; font-size:13px; color:var(--text-muted);"><span id="selectedCount" style="color:var(--text-main); font-weight:700;">0</span> selected</span>
    </form>

    <div class="table-responsive">
      <table id="checksTable">
        <thead>
          <tr>
            <th width="40"><input type="checkbox" id="masterCheckbox" style="cursor: pointer;"></th>
            <th width="80">ID</th>
            <th>Analyzed URL</th>
            <th>Verdict</th>
            <th>Time</th>
            <th class="text-center">Verified</th>
            <th style="text-align:right">Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach($rows as $r):
            $resTag = strtolower($r['result']);
            $badgeClass = 'status-badge safe'; $badgeIcon = 'fa-check';
            if(strpos($resTag,'phish')!==false) { $badgeClass='status-badge phish'; $badgeIcon='fa-ban'; }
            elseif(strpos($resTag,'susp')!==false) { $badgeClass='status-badge susp'; $badgeIcon='fa-exclamation'; }
          ?>
          <tr data-id="<?= (int)$r['id'] ?>" 
              data-url="<?= htmlspecialchars($r['url'], ENT_QUOTES) ?>" 
              data-result="<?= htmlspecialchars($r['result'], ENT_QUOTES) ?>"
              data-verified="<?= $r['verified_by_admin'] ? 1 : 0 ?>">
            <td><input type="checkbox" class="row-checkbox" name="ids[]" value="<?= (int)$r['id'] ?>"></td>
            <td style="color:var(--text-muted); font-family:monospace;">#<?= str_pad($r['id'], 4, '0', STR_PAD_LEFT) ?></td>
            <td class="url" style="max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><?= htmlspecialchars($r['url']) ?></td>
            <td><span class="<?= $badgeClass ?>"><i class="fa <?= $badgeIcon ?>"></i> <?= htmlspecialchars($r['result']) ?></span></td>
            <td style="font-size:13px; color:var(--text-muted)"><?= date('M d, H:i', strtotime($r['checked_at'])) ?></td>
            <td class="text-center verified-status"><?= $r['verified_by_admin'] ? '<i class="fa fa-check-circle" style="color:var(--success)"></i>' : '<span style="color:var(--glass-border)">•</span>' ?></td>
            <td style="text-align:right">
              <div style="display:inline-flex; gap:4px;">
                <form method="POST" style="margin:0"><input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= $r['id'] ?>"><button class="icon-btn verify" name="<?= $r['verified_by_admin']?'unverify':'verify' ?>" type="submit"><i class="fa <?= $r['verified_by_admin']?'fa-undo':'fa-check' ?>"></i></button></form>
                <form method="POST" style="margin:0" onsubmit="return confirm('Del?');"><input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="id" value="<?= $r['id'] ?>"><button class="icon-btn delete" name="delete" type="submit"><i class="fa fa-trash-alt"></i></button></form>
                <button class="icon-btn" onclick="previewRow(this)"><i class="fa fa-eye"></i></button>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    
    <div style="display:flex; justify-content:space-between; margin-top:20px;">
        <div style="font-size:13px; color:var(--text-muted);">Showing <span id="showingCount"><?= count($rows) ?></span> entries</div>
        <div style="display:flex; gap:8px;"><button class="nav-btn" onclick="prevPage()"><</button><span id="pageInfo" style="padding:5px;">1</span><button class="nav-btn" onclick="nextPage()">></button></div>
    </div>
  </div>

  <div class="glass-panel reveal-on-scroll" id="blacklistSection">
    <h3 style="margin:0 0 20px; font-size:18px;">Blacklist Management</h3>
    <form method="POST" class="bulk-bar" style="background:transparent; border:none; padding:0; margin-bottom:20px;">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
      <input type="text" name="domain" placeholder="malicious-site.com" style="padding:10px; border-radius:10px; border:1px solid var(--glass-border); background:var(--input-bg); color:var(--text-main); width:300px; margin-right:10px;">
      <button type="submit" name="add_blacklist" class="nav-btn primary" style="background:var(--danger); border:none;">Block</button>
    </form>
    <div style="display:flex; flex-wrap:wrap; gap:10px;">
      <?php foreach($blacklist as $b): ?>
        <form method="POST" style="display:inline;"><input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="bid" value="<?= (int)$b['id'] ?>"><div class="status-badge phish" style="cursor:default;"><?= htmlspecialchars($b['domain']) ?><button type="submit" name="remove_blacklist" style="background:none; border:none; color:inherit; cursor:pointer; margin-left:5px;"><i class="fa fa-times"></i></button></div></form>
      <?php endforeach; ?>
    </div>
  </div>
</div>

<form id="exportForm" method="POST" style="display:none;"><input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="export_csv" value="1"></form>
<form id="bulkSubmitForm" method="POST" style="display:none;"><input type="hidden" name="csrf_token" value="<?= $csrf ?>"><input type="hidden" name="bulk_verify" value="1"></form>

<div id="modalBack" class="modal-overlay">
  <div class="modal-box">
    <div class="modal-header">
       <h3 style="margin:0; font-size:16px;">AI Decision Breakdown</h3>
       <button class="icon-btn" onclick="closeModal()"><i class="fa fa-times"></i></button>
    </div>
    <div class="modal-body">
        <div style="margin-bottom:15px;">
            <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:700;">Target URL</div>
            <div id="modalUrl" style="word-break:break-all; font-family:monospace; color:var(--accent);"></div>
        </div>
        
        <div class="ai-panel">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span id="aiVerdict" style="font-weight:800; font-size:18px;"></span>
                <span id="aiConfidence" style="font-size:14px; color:var(--text-muted);">Confidence: 98%</span>
            </div>
            <div class="ai-score-bar"><div id="aiScoreFill" class="ai-score-fill"></div></div>
            <div class="factor-grid" id="aiFactors"></div>
        </div>
    </div>
    <div class="modal-footer"><button class="nav-btn primary" onclick="closeModal()">Done</button></div>
  </div>
</div>

<script>
  // --- 1. SPLASH SCREEN LOGIC (ALWAYS SHOW FOR TESTING) ---
  document.addEventListener("DOMContentLoaded", () => {
      const splash = document.getElementById('welcome-splash');
      
      // Ensure splash always shows for testing (Removed the check logic)
      sessionStorage.removeItem('splashShown'); 

      // Fade out after animation finishes (4.0s delay + 0.6s animation)
      setTimeout(() => { 
          splash.style.opacity = '0';
          setTimeout(() => { splash.style.display = 'none'; }, 600); // Wait for CSS transition
      }, 4600); 
  });

  // --- 2. REVEAL ANIMATION ---
  const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => { if (entry.isIntersecting) entry.target.classList.add('active'); });
  }, { threshold: 0.1 });
  document.querySelectorAll('.reveal-on-scroll').forEach(el => observer.observe(el));

  // --- 3. AI MODAL LOGIC ---
  const modalBack = document.getElementById('modalBack');
  function previewRow(btn){
    const tr = btn.closest('tr');
    const url = tr.dataset.url;
    const result = tr.dataset.result.toLowerCase();
    
    document.getElementById('modalUrl').textContent = url;
    
    const isPhish = result.includes('phish');
    const verdict = document.getElementById('aiVerdict');
    const fill = document.getElementById('aiScoreFill');
    const factors = document.getElementById('aiFactors');
    
    if(isPhish) {
        verdict.innerHTML = '<span style="color:var(--danger)">PHISHING DETECTED</span>';
        fill.style.width = '95%'; fill.style.background = 'var(--danger)';
        factors.innerHTML = `<div class="factor-item" style="color:var(--danger)"><i class="fa fa-xmark"></i> Invalid SSL</div><div class="factor-item" style="color:var(--danger)"><i class="fa fa-code"></i> Malicious JS</div>`;
    } else {
        verdict.innerHTML = '<span style="color:var(--success)">SAFE TO VISIT</span>';
        fill.style.width = '10%'; fill.style.background = 'var(--success)';
        factors.innerHTML = `<div class="factor-item" style="color:var(--success)"><i class="fa fa-check"></i> Valid SSL</div><div class="factor-item" style="color:var(--success)"><i class="fa fa-shield"></i> Clean Code</div>`;
    }
    modalBack.style.display='flex';
  }
  function closeModal(){ modalBack.style.display='none'; }

  // --- 4. CHARTS ---
  const colors = { safe: '#10b981', phish: '#ef4444', susp: '#f59e0b', text: '#94a3b8' };
  const chartConfig = { responsive: true, maintainAspectRatio: false };
  
  new Chart(document.getElementById('distChart'), {
      type: 'doughnut',
      data: {
          labels: ['Safe', 'Phishing', 'Suspicious'],
          datasets: [{ data: [<?= $counts['safe'] ?>, <?= $counts['phishing'] ?>, <?= $counts['suspicious'] ?>], backgroundColor: [colors.safe, colors.phish, colors.susp], borderWidth: 0 }]
      }, options: { ...chartConfig, plugins: { legend: { position: 'right', labels: { color: colors.text } } } }
  });

  new Chart(document.getElementById('riskChart'), {
      type: 'doughnut',
      data: { labels: ['Risk', 'Safe'], datasets: [{ data: [35, 65], backgroundColor: [colors.warning, 'rgba(255,255,255,0.05)'], borderWidth: 0, circumference: 180, rotation: 270, cutout: '80%' }] },
      options: { ...chartConfig, plugins: { legend: { display: false } } }
  });

  new Chart(document.getElementById('timelineChart'), {
      type: 'line',
      data: {
          labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
          datasets: [{ label: 'Threats', data: [2, 5, 12, 8, 20, 15], borderColor: colors.phish, backgroundColor: 'rgba(239, 68, 68, 0.1)', fill: true, tension: 0.4 }, 
                     { label: 'Safe', data: [50, 80, 120, 150, 130, 200], borderColor: colors.safe, backgroundColor: 'transparent', borderDash: [5,5], tension: 0.4 }]
      }, options: { ...chartConfig, plugins: { legend: { labels: { color: colors.text } } }, scales: { x: { ticks: { color: colors.text }, grid:{display:false} }, y: { ticks: { color: colors.text }, grid:{color:'rgba(255,255,255,0.05)'} } } }
  });

  new jsVectorMap({ selector: '#world-map', map: 'world', visualizeData: { scale: [colors.safe, colors.phish], values: { US: 50, CN: 80, RU: 70, IN: 40, BR: 30 } }, backgroundColor: 'transparent', regionStyle: { initial: { fill: 'rgba(255,255,255,0.1)', stroke: 'none' }, hover: { fill: colors.primary } } });

  // --- 5. CORE JS (Filtering, Selection) ---
  const rows = Array.from(document.querySelectorAll('#checksTable tbody tr'));
  const searchInput = document.getElementById('tableSearch');
  const filterSelect = document.getElementById('resultFilter');
  let page = 1; let pageSize = 25;

  function render() {
    const q = searchInput.value.trim().toLowerCase();
    const f = filterSelect.value.toLowerCase();
    
    const filtered = rows.filter(r=>{
      const url = r.dataset.url.toLowerCase();
      const res = r.dataset.result.toLowerCase();
      const matchesFilter = (f === '') || res.includes(f);
      const matchesSearch = (url.includes(q) || res.includes(q));
      return matchesFilter && matchesSearch;
    });

    const maxPage = Math.ceil(filtered.length/pageSize) || 1;
    if(page > maxPage) page = maxPage;
    
    rows.forEach(r => r.style.display = 'none');
    filtered.slice((page-1)*pageSize, page*pageSize).forEach(r => r.style.display = '');
    
    document.getElementById('showingCount').textContent = filtered.length;
    document.getElementById('pageInfo').textContent = `${page} / ${maxPage}`;
    updateSelection();
  }

  function updateSelection() { document.getElementById('selectedCount').textContent = document.querySelectorAll('.row-checkbox:checked').length; }

  searchInput.addEventListener('input', () => { page=1; render(); });
  filterSelect.addEventListener('change', () => { page=1; render(); });
  
  function prevPage() { if(page>1) { page--; render(); } }
  function nextPage() { const max = Math.ceil(document.getElementById('showingCount').textContent/pageSize); if(page<max) { page++; render(); } }

  // Select Logic
  document.getElementById('masterCheckbox').addEventListener('change', function(){
      const visible = Array.from(document.querySelectorAll('#checksTable tbody tr')).filter(r => r.style.display !== 'none');
      visible.forEach(r => r.querySelector('.row-checkbox').checked = this.checked);
      updateSelection();
  });
  
  function selectAllVisible() { document.getElementById('masterCheckbox').click(); }
  
  function clearSelection() { 
      document.querySelectorAll('.row-checkbox').forEach(c => c.checked = false); 
      document.getElementById('masterCheckbox').checked = false;
      updateSelection(); 
  }

  // ** Select Unverified Logic **
  function selectUnverified() {
      clearSelection();
      const visible = Array.from(document.querySelectorAll('#checksTable tbody tr')).filter(r => r.style.display !== 'none');
      visible.forEach(r => {
          if (r.dataset.verified == "0") {
              r.querySelector('.row-checkbox').checked = true;
          }
      });
      updateSelection();
  }

  function copyUrl(btn){
      navigator.clipboard.writeText(btn.dataset.url).then(() => {
          btn.innerHTML = '<i class="fa fa-check" style="color:var(--success)"></i>';
          setTimeout(() => btn.innerHTML = '<i class="fa fa-copy"></i>', 1500);
      });
  }

  function exportVisible() {
      const ids = Array.from(document.querySelectorAll('.row-checkbox')).filter(c => c.closest('tr').style.display !== 'none').map(c => c.value);
      if(!ids.length) return alert('No data');
      const f = document.getElementById('exportForm');
      f.querySelectorAll('input[name="ids[]"]').forEach(e=>e.remove());
      ids.forEach(id => { const i=document.createElement('input'); i.type='hidden'; i.name='ids[]'; i.value=id; f.appendChild(i); });
      f.submit();
  }

  document.getElementById('bulkForm').addEventListener('submit', function(e) {
      e.preventDefault();
      const ids = Array.from(document.querySelectorAll('.row-checkbox:checked')).map(c => c.value);
      if(!ids.length) return alert('Select items');
      if(!confirm('Verify '+ids.length+' items?')) return;
      const f = document.getElementById('bulkSubmitForm');
      ids.forEach(id => { const i=document.createElement('input'); i.type='hidden'; i.name='ids[]'; i.value=id; f.appendChild(i); });
      f.submit();
  });

  // Theme
  const themeBtn = document.getElementById('themeBtn');
  if(localStorage.getItem('theme') === 'light') document.body.classList.add('light-mode');
  themeBtn.addEventListener('click', () => {
      document.body.classList.toggle('light-mode');
      localStorage.setItem('theme', document.body.classList.contains('light-mode') ? 'light' : 'dark');
  });

  render();
</script>
</body>
</html>