<?php
// check.php — Final with classification: Safe / Suspicious / Phishing
// - Keep background.jpg in same folder (optional).
// - For PDF export install dompdf: composer require dompdf/dompdf

session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

date_default_timezone_set('Asia/Kolkata');

$servername="localhost"; $username="root"; $password=""; $dbname="phishing_db";
$conn=@new mysqli($servername,$username,$password,$dbname);

function sanitize($s){ return htmlspecialchars((string)$s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function normalize_url($u){ $u=trim((string)$u); if($u==='' ) return $u; if(!preg_match('#^https?://#i',$u)) $u='http://'.$u; return $u; }
function safe_get_headers($url){ return @get_headers($url,1); }
function safe_get_body($url,$timeout=6){ $opts=['http'=>['method'=>'GET','timeout'=>$timeout,'header'=>"User-Agent: PhishSafeguard/1.0\r\n"]]; $ctx=stream_context_create($opts); return @file_get_contents($url,false,$ctx); }
function get_ssl_info($host){
  $res=['issuer'=>null,'expires'=>null,'valid'=>false];
  $context=stream_context_create(["ssl"=>["capture_peer_cert"=>true,"verify_peer"=>false]]);
  $fp=@stream_socket_client("ssl://{$host}:443",$errno,$errstr,6,STREAM_CLIENT_CONNECT,$context);
  if($fp){
    $params=stream_context_get_params($fp);
    if(isset($params['options']['ssl']['peer_certificate'])){
      $cert=$params['options']['ssl']['peer_certificate'];
      $ci=@openssl_x509_parse($cert);
      if($ci){
        $res['issuer']=$ci['issuer']['O']??($ci['issuer']['CN']??null);
        if(isset($ci['validTo_time_t'])){
          $res['expires']=date('Y-m-d H:i:s',$ci['validTo_time_t']);
          $res['valid']=($ci['validTo_time_t']>time());
        }
      }
    }
    fclose($fp);
  }
  return $res;
}
function whois_lookup_simple($host){
  $domain=preg_replace('/^www\./i','',$host);
  $tld=strtolower(substr(strrchr($domain,'.'),1)?:'');
  $map=['com'=>'whois.verisign-grs.com','net'=>'whois.verisign-grs.com','org'=>'whois.pir.org','in'=>'whois.inregistry.net'];
  $server=$map[$tld]??'whois.iana.org';
  $out=''; $s=@fsockopen($server,43,$e,$es,6);
  if(!$s) $s=@fsockopen('whois.internic.net',43,$e,$es,6);
  if($s){ fwrite($s,$domain."\r\n"); stream_set_timeout($s,6); while(!feof($s)) $out.=fgets($s,128); fclose($s); }
  return $out;
}

// report container
$report=['url'=>'','host'=>'','ip'=>null,'ssl'=>null,'whois'=>null,'http_code'=>null,'headers'=>null,'body_sample'=>null,'timestamp'=>null,'notes'=>[]];

if($_SERVER['REQUEST_METHOD']==='POST' && !empty($_POST['url'])){
  $url=normalize_url($_POST['url']); $report['url']=$url;
  $parsed=parse_url($url); $host=$parsed['host']??$url; $report['host']=$host;
  $ip=@gethostbyname($host); if($ip===$host) $ip=null; $report['ip']=$ip;
  $report['ssl']=get_ssl_info($host);
  $report['whois']=whois_lookup_simple($host);
  $headers=safe_get_headers($url); $report['headers']=$headers;
  if(is_array($headers)&&isset($headers[0])&&preg_match('/HTTP\/[\d.]+\s+(\d{3})/i',$headers[0],$m)) $report['http_code']=intval($m[1]);
  $body=safe_get_body($url,6); $report['body_sample']=$body?substr($body,0,4000):'';
  $report['timestamp']=date('Y-m-d H:i:s');
  if($report['http_code']===429) $report['notes'][]='Remote server rate-limited (429) — results may be incomplete.';
  $_SESSION['last_check_full']=$report;
  if($conn && !$conn->connect_error){
    $u=$conn->real_escape_string($url);
    @$conn->query("INSERT INTO url_checks (url,result,checked_at) VALUES ('{$u}','checked',NOW())");
  }
} elseif(!empty($_SESSION['last_check_full'])) {
  $report=$_SESSION['last_check_full'];
}

// ----- checks -----
$checks=[];
function add_check(&$arr,$t,$d,$s,$e,$h){ $arr[]=['title'=>$t,'detected'=>$d,'severity'=>$s,'explanation'=>$e,'how_attack'=>$h]; }

// has https
$has_https=(stripos($report['url'],'https://')===0)&&!empty($report['ssl']['valid']);
add_check($checks,'Missing or insecure HTTPS',!$has_https,'High','No or invalid HTTPS',['MITM attack','Injection possible']);

// ssl expired/invalid
$ssl_problem=!empty($report['ssl']) && !$report['ssl']['valid'];
add_check($checks,'Invalid/expired SSL',$ssl_problem,$ssl_problem?'High':'Low','Certificate invalid/expired',['Fake cert could trick users']);

// ip as host
$is_ip=filter_var($report['host'],FILTER_VALIDATE_IP);
add_check($checks,'IP address as host',$is_ip,'Medium','URL uses raw IP',['Obfuscation','Bypass filters']);

// recently registered
$young=false;
if(!empty($report['whois']) && preg_match('/Creation Date:\s*([0-9T:\-Z]+)/i',$report['whois'],$m)){
  $t=strtotime($m[1]);
  if($t && (time()-$t) < 15552000) $young=true;
}
add_check($checks,'Recently registered domain',$young,'Medium','Domain < 6 months',['Low trust','Likely phishing']);

// risky tld
$risky=['xyz','top','club','pw','info','site','online','review','win'];
$tld=strtolower(substr(strrchr($report['host']??'','.'),1)?:'');
$is_risky=in_array($tld,$risky);
add_check($checks,'Risky TLD',$is_risky,$is_risky?'Medium':'Low','TLD often abused',['Cheap domains for phishing']);

// suspicious keywords
$kw=['login','verify','account','secure','update','password','confirm','bank','signin','otp'];
$found=null;
foreach($kw as $k) if(stripos($report['url']??'',$k)!==false){ $found=$k; break; }
add_check($checks,'Suspicious keywords',(bool)$found,$found?'Medium':'Low',$found?("Keyword '{$found}' found"):'None',['Social engineering']);

// redirects
$redirects=0;
if(is_array($report['headers']) && isset($report['headers']['Location'])){
  $loc=$report['headers']['Location']; $redirects=is_array($loc)?count($loc):1;
}
add_check($checks,'Redirects',$redirects>=3,$redirects>=3?'Medium':'Low',$redirects?("$redirects redirect(s)"):'None',['Hide destination']);

// password form detection
$pwd=false;
if(!empty($report['body_sample'])){
  if(stripos($report['body_sample'],'password')!==false) $pwd=true;
  if(preg_match('/<input[^>]+type=["\']?password["\']?/i',$report['body_sample'])) $pwd=true;
}
add_check($checks,'Password form',$pwd,$pwd?'High':'Low',$pwd?'Password field detected':'None',['Credential theft']);

// missing security headers
$need=['x-frame-options','content-security-policy','x-content-type-options','strict-transport-security'];
$hdrs=[]; if(is_array($report['headers'])) foreach($report['headers'] as $k=>$v) $hdrs[strtolower($k)]=$v;
$missing=[]; foreach($need as $h) if(!isset($hdrs[$h])) $missing[]=$h;
add_check($checks,'Missing headers',!empty($missing),!empty($missing)?'Medium':'Low',!empty($missing)?implode(', ',$missing):'All present',['Clickjacking','XSS risk']);

// server banner exposure
$server=$hdrs['server']??null; $expose=$server && preg_match('/apache|nginx|php/i',$server);
add_check($checks,'Server banner',$expose,'Low',$expose?"Server: $server":'None',['Fingerprinting']);

// compute score (risk percent)
$score=0;
foreach($checks as $c){
  if($c['detected']){
    if($c['severity']=='High') $score += 40;
    elseif($c['severity']=='Medium') $score += 15;
    else $score += 5;
  }
}
if($score>100) $score=100;

// classification thresholds
// score <=30 => Safe; 31-59 => Suspicious; >=60 => Phishing
if($score<=30) $classification='safe';
elseif($score<60) $classification='suspicious';
else $classification='phishing';

// prepare lists for display
$vuln_list = array_filter($checks, function($c){ return $c['detected']; });
$high_vulns = array_filter($checks, function($c){ return $c['detected'] && $c['severity']=='High'; });
$medium_vulns = array_filter($checks, function($c){ return $c['detected'] && $c['severity']=='Medium'; });
$low_vulns = array_filter($checks, function($c){ return $c['detected'] && $c['severity']=='Low'; });

// possible attacks (unique)
$attackSet=[];
foreach($vuln_list as $c){
  if(!empty($c['how_attack']) && is_array($c['how_attack'])){
    foreach($c['how_attack'] as $a) $attackSet[trim($a)] = true;
  } elseif(!empty($c['how_attack'])) $attackSet[trim($c['how_attack'])] = true;
}
$possible_attacks = array_keys($attackSet);

// PDF renderer
function render_pdf_html($report,$checks,$score,$classification,$attacks){
  ob_start(); ?>
  <html><head><meta charset="utf-8"><style>body{font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#111}h1{font-size:18px}</style></head><body>
  <h1>Vulnerability Report — <?= strtoupper($classification) ?></h1>
  <p><b>URL:</b> <?= sanitize($report['url']) ?><br>
  <b>Host:</b> <?= sanitize($report['host']) ?> | <b>IP:</b> <?= sanitize($report['ip']) ?><br>
  <b>Score:</b> <?= $score ?>%</p>
  <hr>
  <?php foreach($checks as $c): ?>
    <div><b><?= sanitize($c['title']) ?></b> — <?= $c['detected'] ? sanitize($c['severity']) : 'None' ?><br><?= sanitize(is_array($c['explanation'])?implode(', ',$c['explanation']):$c['explanation']) ?></div>
  <?php endforeach; ?>
  <hr><h3>Possible attacks</h3>
  <ul><?php if(empty($attacks)){ echo '<li>None identified</li>'; } else { foreach($attacks as $a){ echo '<li>'.sanitize($a).'</li>'; } } ?></ul>
  </body></html>
  <?php return ob_get_clean();
}
if(isset($_GET['export']) && $_GET['export']==='pdf'){
  if(!file_exists(__DIR__.'/vendor/autoload.php')){ die("PDF export not available (missing Dompdf)."); }
  require __DIR__.'/vendor/autoload.php';
  $dompdf = new \Dompdf\Dompdf();
  $dompdf->loadHtml(render_pdf_html($report,$checks,$score,$classification,$possible_attacks));
  $dompdf->setPaper('A4','portrait'); $dompdf->render(); $dompdf->stream('vulnerability-report.pdf',['Attachment'=>true]); exit;
}

// JS payloads
$js_report = ['url'=>$report['url'],'host'=>$report['host'],'ip'=>$report['ip'],'score'=>$score,'classification'=>$classification];
$js_checks = array_map(function($c){ return ['title'=>$c['title'],'detected'=>$c['detected'],'severity'=>$c['severity'],'explanation'=>is_array($c['explanation'])?implode(', ',$c['explanation']):$c['explanation']]; }, $checks);
$js_attacks = $possible_attacks;
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Report — Check</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Times+New+Roman&display=swap" rel="stylesheet">
<style>
:root{ --accent:#5b8cff; --muted:#6b7280; --success:#16a34a; --danger:#ef4444; --warn:#f59e0b; --radius:12px; }
*{box-sizing:border-box}
html,body{height:100%;margin:0;font-family:"Times New Roman",serif;color:#07223a}
/* background image (optional) + animated overlay */
body {
  background: url("background.jpg") no-repeat center center fixed;
  background-size: cover;
  position: relative;
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  background: linear-gradient(120deg, rgba(11,18,32,0.5), rgba(7,20,48,0.45), rgba(7,27,51,0.45));
  background-size: 300% 300%;
  animation: rgbShift 14s ease infinite;
  z-index: -1;
}
@keyframes rgbShift {
  0%{background-position:0% 50%}33%{background-position:50% 100%}66%{background-position:100% 50%}100%{background-position:0% 50%}
}

/* layout */
.wrap{max-width:1100px;margin:28px auto;padding:20px}
.card{background:linear-gradient(180deg, rgba(255,255,255,0.96), rgba(250,250,252,0.98));border-radius:16px;padding:20px;box-shadow:0 18px 50px rgba(2,6,23,0.18);border:1px solid rgba(0,0,0,0.04);backdrop-filter: blur(4px);}

/* header */
header.hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
.url-left{flex:1;min-width:0}
.url-left h1{margin:0;font-size:20px;word-break:break-all;color:#07223a}
.meta{font-size:13px;color:var(--muted);margin-top:6px}
.score-bubble{min-width:120px;text-align:center;padding:12px;border-radius:12px;color:#fff;font-weight:800;font-size:20px}
.score-safe{background:var(--success)} .score-susp{background:var(--warn)} .score-phish{background:var(--danger)}

/* controls */
.controls{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.btn{padding:8px 12px;border-radius:8px;border:0;background:var(--accent);color:#fff;cursor:pointer;font-weight:700}
.btn.ghost{background:transparent;color:#07223a;border:1px solid rgba(7,34,58,0.06)}

/* report */
.two-col{display:grid;grid-template-columns:1fr 360px;gap:14px}
.panel{padding:0;border-radius:8px}
.vuln{padding:12px;border-left:6px solid rgba(11,61,145,0.06);margin-bottom:8px;background:linear-gradient(180deg,#fff,#fbfdff);border-radius:8px;box-shadow:0 6px 18px rgba(10,20,40,0.03)}
.vuln.high{border-left-color:var(--danger)} .vuln.medium{border-left-color:var(--warn)} .vuln.low{border-left-color:var(--success)}
.vuln b{display:block;margin-bottom:6px}
.small{font-size:13px;color:#445}
.attacks li{margin:8px 0;display:flex;gap:8px;align-items:flex-start}
.attack-dot{width:12px;height:12px;border-radius:50%;margin-top:6px;background:var(--accent);flex:0 0 12px;box-shadow:0 8px 26px rgba(91,140,255,0.16)}
.footer-links{margin-top:12px;display:flex;gap:12px;align-items:center}
.reason{background:#fff8e6;border-left:4px solid var(--warn);padding:10px;border-radius:8px;margin-bottom:8px}
@media (max-width:980px){ .two-col{grid-template-columns:1fr} .score-bubble{margin-top:12px} .attacks li{font-size:14px} }
</style>
</head>
<body>
<div class="wrap">
  <div class="card" role="main" aria-labelledby="reportTitle">
    <header class="hdr">
      <div class="url-left">
        <h1 id="reportTitle"><?= sanitize($report['url'] ?: 'No URL checked yet') ?></h1>
        <div class="meta">
          Host: <?= sanitize($report['host'] ?: '—') ?> |
          IP: <?= sanitize($report['ip'] ?: '—') ?> |
          HTTP: <?= sanitize($report['http_code'] ?: '—') ?> |
          SSL: <?= sanitize($report['ssl']['issuer'] ?? '—') ?>
        </div>
      </div>

      <?php
        $scoreCls = ($classification==='safe'?'score-safe':($classification==='suspicious'?'score-susp':'score-phish'));
      ?>
      <div>
        <div class="score-bubble <?= $scoreCls ?>"><?= $score ?>%</div>
      </div>
    </header>

    <div class="controls">
      <form method="post" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="text" name="url" placeholder="https://example.com/login" value="<?= sanitize($report['url']) ?>" style="padding:8px;border-radius:8px;border:1px solid rgba(2,6,23,.06);width:420px">
        <button class="btn" type="submit">Check</button>
        <a class="btn ghost" href="check.php?export=pdf">📄 Export PDF</a>
        <button id="downloadCsvBtn" class="btn ghost" type="button">⬇ Export CSV</button>
        <a class="btn ghost" href="index.php">↩ Dashboard</a>
      </form>
    </div>

    <div class="two-col">
      <div class="panel">
        <h3 style="margin-top:0">Vulnerability Report</h3>

        <?php if($classification==='safe'): ?>
          <div class="reason"><strong>Safe</strong> — No critical issues detected. The site appears OK based on automated checks.</div>
          <div class="small">Summary: <?= count($vuln_list) ?> findings (none critical)</div>
        <?php elseif($classification==='suspicious'): ?>
          <div class="reason"><strong>Suspicious</strong> — Some indicators suggest this site may be suspicious. Review the items below and exercise caution before interacting or entering credentials.</div>
        <?php else: // phishing ?>
          <div class="reason"><strong>Phishing likely</strong> — High risk detected (<?= $score ?>%). Do NOT enter credentials. Top issues and possible attacks are listed.</div>
        <?php endif; ?>

        <?php foreach($checks as $c): ?>
          <?php $sevClass = strtolower($c['severity']); ?>
          <div class="vuln <?= $c['detected'] ? $sevClass : 'low' ?>">
            <b><?= sanitize($c['title']) ?> — <?= $c['detected'] ? sanitize($c['severity']) : 'None' ?></b>
            <div class="small"><?= sanitize(is_array($c['explanation'])?implode(', ',$c['explanation']):$c['explanation']) ?></div>
            <?php if($c['detected'] && !empty($c['how_attack'])): ?>
              <div style="margin-top:8px"><small><strong>How it may be abused:</strong> <?= is_array($c['how_attack']) ? sanitize(implode(', ', $c['how_attack'])) : sanitize($c['how_attack']) ?></small></div>
            <?php endif; ?>
          </div>
        <?php endforeach; ?>

      </div>

      <aside class="panel">
        <div style="background:#fff;padding:12px;border-radius:8px;box-shadow:0 6px 18px rgba(10,20,40,0.03)">
          <h4 style="margin-top:0">Summary</h4>
          <div class="small">Classification: <strong style="text-transform:capitalize"><?= sanitize($classification) ?></strong></div>
          <div class="small">Risk score: <strong><?= $score ?>%</strong></div>
          <div class="small">Checked at: <?= sanitize($report['timestamp']?:'—') ?></div>

          <hr>

          <h4>Top vulnerabilities</h4>
          <?php if(empty($vuln_list)): ?>
            <div class="small">None detected</div>
          <?php else: ?>
            <ul class="small">
              <?php foreach($vuln_list as $v): ?>
                <li><?= sanitize($v['title']) ?> — <?= sanitize($v['severity']) ?></li>
              <?php endforeach; ?>
            </ul>
          <?php endif; ?>

          <hr>

          <h4>Possible attacks</h4>
          <?php if(empty($possible_attacks)): ?>
            <div class="small">None identified</div>
          <?php else: ?>
            <ul style="padding-left:0;list-style:none;margin:0">
              <?php foreach($possible_attacks as $a): ?>
                <li class="attacks"><span class="attack-dot" aria-hidden="true"></span><div class="small"><?= sanitize($a) ?></div></li>
              <?php endforeach; ?>
            </ul>
          <?php endif; ?>

          <hr>

          <h4>Why this result?</h4>
          <?php if($classification==='safe'): ?>
            <div class="small">Score low — very few or no checks matched. Standard headers present and no password forms detected.</div>
          <?php elseif($classification==='suspicious'): ?>
            <div class="small">Medium-score issues detected (e.g., recently registered domain, suspicious keywords, missing some headers). Investigate manually.</div>
          <?php else: ?>
            <div class="small">High-score issues (missing HTTPS or invalid SSL, password field on page, redirects, risky TLD, etc.) — likely phishing.</div>
          <?php endif; ?>

        </div>
      </aside>
    </div>

    <div class="footer-links" style="margin-top:12px">
      <small class="small">Notes: <?= !empty($report['notes']) ? sanitize(implode('; ',$report['notes'])) : '—' ?></small>
    </div>
  </div>
</div>

<script>
const REPORT = <?= json_encode($js_report) ?>;
const CHECKS = <?= json_encode($js_checks) ?>;
const ATTACKS = <?= json_encode($js_attacks) ?>;

// CSV export
document.getElementById('downloadCsvBtn').addEventListener('click', function(){
  const rows = [];
  rows.push(['Vulnerability Report']);
  rows.push([]);
  rows.push(['URL', REPORT.url || '']);
  rows.push(['Host', REPORT.host || '']);
  rows.push(['IP', REPORT.ip || '']);
  rows.push(['Score', REPORT.score + '%']);
  rows.push([]);
  rows.push(['Check','Detected','Severity','Explanation']);
  for(const c of CHECKS){
    rows.push([c.title, c.detected ? 'Yes' : 'No', c.severity, c.explanation]);
  }
  const csv = rows.map(r => r.map(cell => `"${String(cell).replace(/"/g,'""')}"`).join(',')).join("\r\n");
  const blob = new Blob([csv], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'vulnerability-report.csv';
  a.click();
  URL.revokeObjectURL(a.href);
});
</script>
</body>
</html>
