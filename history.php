<?php
require_once "helpers.php"; ensure_auth(); $conn=db();
$uid = (int)$_SESSION['user_id'];
$q=$conn->prepare("SELECT url,result,checked_at FROM url_checks WHERE user_id=? ORDER BY checked_at DESC LIMIT 200");
$q->bind_param("i",$uid); $q->execute(); $res=$q->get_result();
$rows=$res->fetch_all(MYSQLI_ASSOC);
?>
<!DOCTYPE html><html><head><meta charset="utf-8"><title>History</title>
<style>
  body{font-family:system-ui;margin:0;background:#f5f7fb}
  .wrap{max-width:900px;margin:40px auto;padding:0 16px}
  h2{color:#0b3d91}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 8px 20px rgba(0,0,0,.08)}
  th,td{padding:12px;border-bottom:1px solid #e6e8ef;text-align:left}
  th{background:#eef2f7}
  .btn{padding:10px 12px;border:0;border-radius:8px;background:#0b3d91;color:#fff;cursor:pointer}
</style></head><body>
<div class="wrap">
  <h2>Your Check History</h2>
  <button class="btn" onclick="exportCSV()">Export CSV</button>
  <table id="tbl"><tr><th>URL</th><th>Result</th><th>Checked At</th></tr>
  <?php foreach($rows as $r): ?>
    <tr><td><?=htmlspecialchars($r['url'])?></td><td><?=htmlspecialchars($r['result'])?></td><td><?=htmlspecialchars($r['checked_at'])?></td></tr>
  <?php endforeach; ?>
  </table>
  <p style="margin-top:10px"><a href="index.php">← Back</a></p>
</div>
<script>
function exportCSV(){
  let rows=[...document.querySelectorAll('#tbl tr')].map(r=>[...r.children].map(c=>c.innerText.replaceAll(',',' ')).join(','));
  let blob=new Blob([rows.join('\n')],{type:'text/csv'}); let a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download='history.csv'; a.click();
}
</script>
</body></html>
