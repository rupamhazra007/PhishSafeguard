<?php
// payment.php — PhishSafeguard (Login required + subscription guard + OTP demo)
// Demo ONLY — do not use real card data.

session_start();

/* ===========================================================
    DB bootstrap (best-effort). Should define $pdo (PDO) in init.php
    =========================================================== */
@require_once __DIR__ . '/init.php'; // expected: $pdo = new PDO(...)

/* ----------------- Helpers ----------------- */
function db_get_user_plan($pdo, $userId) {
    if (!$pdo || !$userId) return null;

    // 1) Try users.plan (primary)
    try {
        $q = $pdo->prepare("SELECT plan FROM users WHERE id = :id LIMIT 1");
        $q->execute([':id' => $userId]);
        if ($row = $q->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($row['plan'])) return $row['plan'];
        }
    } catch (Throwable $e) { /* ignore */ }

    // 2) Fallback: users.plan_name (legacy)
    try {
        $q = $pdo->prepare("SELECT plan_name FROM users WHERE id = :id LIMIT 1");
        $q->execute([':id' => $userId]);
        if ($row = $q->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($row['plan_name'])) return $row['plan_name'];
        }
    } catch (Throwable $e) { /* ignore */ }

    // 3) Fallback: user_subscriptions (active, not expired)
    try {
        $q = $pdo->prepare("SELECT plan_name 
                                    FROM user_subscriptions 
                                    WHERE user_id = :id 
                                    AND status = 'active' 
                                    AND (expires_at IS NULL OR expires_at > NOW())
                                    ORDER BY started_at DESC LIMIT 1");
        $q->execute([':id' => $userId]);
        if ($row = $q->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($row['plan_name'])) return $row['plan_name'];
        }
    } catch (Throwable $e) { /* ignore */ }

    return null;
}
function normalize_tier($name) {
    if ($name === null) return null;
    $t = strtolower(trim($name));
    if ($t === 'professional') $t = 'pro';
    if (!in_array($t, ['free','basic','pro','premium','verified premium'], true)) {
        return ucfirst($t);
    }
    if ($t === 'verified premium') return 'Verified Premium';
    return ucfirst($t); // Free | Basic | Pro | Premium
}
/* Map purchase → effective stored plan
    Basic   -> Premium (user becomes Premium user)
    Premium-> Verified Premium (user becomes Verified Premium user)
    Pro/Professional -> Pro (unchanged)
*/
function effective_plan_from_purchase($postedPlanUc) {
    $t = strtolower(trim($postedPlanUc));
    if ($t === 'basic')     return 'Premium';
    if ($t === 'premium') return 'Verified Premium';
    if ($t === 'professional') return 'Pro';
    if ($t === 'pro') return 'Pro';
    return normalize_tier($postedPlanUc);
}
/* user considered "already subscribed" if they have any premium-ish plan */
function has_active_plan($planName) {
    if ($planName === null) return false;
    $t = strtolower(trim($planName));
    return in_array($t, ['basic','pro','premium','verified premium'], true);
}

/* ---------- A) DEMO RESET SWITCH (optional) ---------- */
if (isset($_GET['reset']) && $_GET['reset'] === '1') {
    unset($_SESSION['subscribed_plan'], $_SESSION['user_tier'], $_SESSION['is_premium'], $_SESSION['is_verified']);
    $_SESSION['flash'] = 'Demo subscription reset.';
    $base = strtok($_SERVER['REQUEST_URI'], '?');
    header("Location: {$base}");
    exit;
}

/* ---------- 0) CSRF token for the demo form ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}

/* ---------- 1) LOGIN REQUIRED ---------- */
if (!isset($_SESSION['user_id'])) {
    $_SESSION['flash'] = 'Please log in to complete your purchase.';
    $return = urlencode($_SERVER['REQUEST_URI']);
    header("Location: login.php?next={$return}");
    exit;
}
$userId = (int) $_SESSION['user_id'];

/* ---------- 2) PLAN & AMOUNT (requested) ---------- */
$planParam = strtolower(trim($_GET['plan'] ?? ''));
$planMap = [
    'basic'         => ['name' => 'Basic',   'amount' => 799],
    'pro'           => ['name' => 'Pro',     'amount' => 2574],
    'professional'  => ['name' => 'Pro',     'amount' => 2574],
    'premium'       => ['name' => 'Premium', 'amount' => 2574],
];
$plan       = $planMap[$planParam] ?? $planMap['basic'];
$amount     = $plan['amount'];
$planName = $plan['name'];

/* ===========================================================
    B) Sync session from DB (for header badges etc.)
    =========================================================== */
$currentPlanDB = null;
if (isset($pdo) && $pdo instanceof PDO) {
    $currentPlanDB = db_get_user_plan($pdo, $userId);
}
if (empty($_SESSION['subscribed_plan']) && $currentPlanDB !== null) {
    $norm = normalize_tier($currentPlanDB);
    $_SESSION['subscribed_plan'] = $norm;
    $_SESSION['user_tier']       = $norm;
    $_SESSION['is_premium']      = (int) in_array(strtolower($norm), ['pro','premium','verified premium'], true);
    $_SESSION['is_verified']     = (int) (strtolower($norm) === 'verified premium');
}

/* ---------- ULTRA-EARLY DB GUARD (blocks GET & POST) ---------- */
function fetch_live_plan_for_guard(PDO $pdo, int $userId): ?string {
    // Lock user row first (prevents race during finalize)
    $q = $pdo->prepare("
        SELECT 
            NULLIF(TRIM(LOWER(u.plan)), '')      AS p1,
            NULLIF(TRIM(LOWER(u.plan_name)), '') AS p2
        FROM users u WHERE u.id = :id FOR UPDATE
    ");
    $q->execute([':id'=>$userId]);
    $row = $q->fetch(PDO::FETCH_ASSOC) ?: [];
    $c1 = $row['p1'] ?? null; 
    $c2 = $row['p2'] ?? null;

    if (in_array($c1, ['basic','pro','premium','verified premium'], true)) return normalize_tier($c1);
    if (in_array($c2, ['basic','pro','premium','verified premium'], true)) return normalize_tier($c2);

    // fallback: active subscription
    $s = $pdo->prepare("
        SELECT plan_name 
        FROM user_subscriptions 
        WHERE user_id = :id AND status='active' 
        AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY started_at DESC LIMIT 1
    ");
    $s->execute([':id'=>$userId]);
    $p = $s->fetchColumn();
    return $p ? normalize_tier($p) : null;
}
function show_already_and_exit(string $livePlan, string $requestedPlanParam): void {
    $lp = strtolower($livePlan);
    $rp = strtolower($requestedPlanParam);
    $msg = 'You are already subscribed with <strong>'.htmlspecialchars($livePlan).'</strong> plan.';
    if ($rp === 'basic'   && $lp === 'premium')          $msg = 'You already purchased our Premium plan.';
    if ($rp === 'premium' && $lp === 'verified premium') $msg = 'You already purchased our Verified Premium plan.';

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache'); header('Expires: 0');
    http_response_code(409);
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Already Subscribed • PhishSafeguard</title>
        <style>
        :root{ --bg:#071427; --panel:#0f1e39; --text:#cfe1ff; --muted:#8ea0c7; --accent:#64ffda; --border:rgba(100,255,218,.12); }
        *{box-sizing:border-box}
        body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text)}
        .wrap{max-width:720px;margin:16vh auto 0;padding:24px}
        .card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:28px;box-shadow:0 18px 48px rgba(0,0,0,.45);text-align:center}
        h1{margin:0 0 10px;font-size:1.35rem}
        p{margin:0 0 18px;color:var(--muted)}
        .btn{display:inline-block;margin-top:10px;padding:10px 14px;border-radius:10px;border:1px solid var(--accent);background:var(--accent);color:#001b16;font-weight:700;text-decoration:none}
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="card" role="status" aria-live="polite">
                <h1>Already Subscribed</h1>
                <p><?php echo $msg; ?></p>
                <a class="btn" href="index.php">Go Home</a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

$requestedParam = strtolower(trim($_GET['plan'] ?? ''));
if (isset($pdo) && $pdo instanceof PDO) {
    try {
        $pdo->beginTransaction();
        $livePlan = fetch_live_plan_for_guard($pdo, $userId); // locks user row
        if ($livePlan && has_active_plan($livePlan)) {
            $pdo->commit(); // release lock before rendering
            show_already_and_exit($livePlan, $requestedParam);
        }
        $pdo->commit(); // no active plan → continue to form
    } catch (Throwable $e) {
        try { if ($pdo->inTransaction()) $pdo->rollBack(); } catch (Throwable $_) {}
        // If guard fails for any reason, fall back to safe default (allow form)
    }
}

/* ---------- 3) Soft check (kept false due to hard guard) ---------- */
$already = false;

/* ---------- 4) OTP + SERVER FINALIZE ---------- */
const DEMO_OTP = '123456';

$errors = [];
$successPayload = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF check
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid request (CSRF). Please refresh and try again.';
    }

    if ($already) {
        $errors[] = 'You are already subscribed.';
    } else {
        // NOTE: server expects 'card' to be digits — we keep the same name 'card' as a hidden field updated by JS.
        $cardholder     = trim($_POST['cardholder'] ?? '');
        $card           = preg_replace('/\D+/', '', $_POST['card'] ?? '');
        $expiry         = trim($_POST['expiry'] ?? '');
        $cvv            = trim($_POST['cvv'] ?? '');
        $email          = trim($_POST['email'] ?? '');
        $planPosted     = $_POST['plan'] ?? $planName;
        $amountPosted = (int)($_POST['amount'] ?? $amount);
        $otp_verified = ($_POST['otp_verified'] ?? '') === '1';

        if ($amountPosted !== $amount || strcasecmp($planPosted, $planName) !== 0) $errors[] = 'Plan mismatch. Reload and try again.';
        if ($cardholder === '') $errors[] = 'Cardholder name is required.';
        if (!preg_match('/^\d{13,19}$/', $card)) $errors[] = 'Invalid card number.';
        if (!preg_match('/^\d{2}\/\d{2}$/', $expiry)) $errors[] = 'Invalid expiry (MM/YY).';
        if (!preg_match('/^\d{3,4}$/', $cvv)) $errors[] = 'Invalid CVV.';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Invalid email.';
        if (!$otp_verified) $errors[] = 'OTP not verified.';

        // Luhn
        $luhn = function($num){
            $sum=0; $alt=false;
            for($i=strlen($num)-1;$i>=0;$i--){
                $n=(int)$num[$i];
                if($alt){ $n*=2; if($n>9)$n-=9; }
                $sum+=$n; $alt=!$alt;
            }
            return $sum%10===0;
        };
        if ($card && !$luhn($card)) $errors[] = 'Card failed validation.';

        /* ---------- FINALIZE (transaction + row lock + unique) ---------- */
        if (!$errors && isset($pdo) && $pdo instanceof PDO) {
            try {
                $pdo->beginTransaction();

                // lock user row; re-check active plan
                $lock = $pdo->prepare("SELECT id, plan, plan_name FROM users WHERE id=:id FOR UPDATE");
                $lock->execute([':id'=>$userId]);
                $cur = $lock->fetch(PDO::FETCH_ASSOC) ?: [];
                $curPlan = strtolower(trim($cur['plan'] ?? $cur['plan_name'] ?? ''));

                if (in_array($curPlan, ['basic','pro','premium','verified premium'], true)) {
                    $pdo->rollBack();
                    $errors[] = 'You already have an active plan.';
                } else {
                    // derive effective plan
                    $effectivePlan    = effective_plan_from_purchase($planPosted);
                    $effectiveLower = strtolower($effectivePlan);
                    $isPremiumInt   = (int) in_array($effectiveLower, ['pro','premium','verified premium'], true);
                    $isVerifiedInt  = (int) ($effectiveLower === 'verified premium');

                    // update users (also mirror plan_name for legacy UI)
                    $upd = $pdo->prepare("
                        UPDATE users SET
                            plan = :p,
                            plan_name = :p,
                            is_premium = :ip,
                            is_verified = :iv,
                            plan_purchased_at = NOW(),
                            first_purchase_at = COALESCE(first_purchase_at, NOW())
                        WHERE id = :id
                    ");
                    $upd->execute([
                        ':p'=>$effectivePlan, ':ip'=>$isPremiumInt, ':iv'=>$isVerifiedInt, ':id'=>$userId
                    ]);

                    // insert active subscription (DB UNIQUE on (user_id,status) recommended)
                    try {
                        $ins = $pdo->prepare("
                            INSERT INTO user_subscriptions (user_id, plan_name, status, started_at, expires_at)
                            VALUES (:uid, :plan, 'active', NOW(), NULL)
                        ");
                        $ins->execute([':uid'=>$userId, ':plan'=>$effectivePlan]);
                    } catch (PDOException $ex) {
                        // duplicate active → someone already active (race)
                        $pdo->rollBack();
                        $errors[] = 'You already have an active plan.';
                    }

                    if (!$errors) {
                        $pdo->commit();

                        // session flags (after commit)
                        $_SESSION['subscribed_plan'] = $effectivePlan;
                        $_SESSION['user_tier']       = $effectivePlan;
                        $_SESSION['is_premium']      = $isPremiumInt;
                        $_SESSION['is_verified']     = $isVerifiedInt;

                        // build success payload (for optional on-page receipt)
                        $maskedCard = str_repeat('•', max(0, strlen($card)-4)).substr($card,-4);
                        $txnId = 'PSG'.date('YmdHis').strtoupper(substr(md5($card.$email.random_int(1000,9999)),0,6));
                        $successPayload = [
                            'plan'   => $effectivePlan,
                            'amount' => $amountPosted,
                            'email'  => $email,
                            'masked' => $maskedCard,
                            'txn'    => $txnId,
                            'time'   => date('M d, Y H:i:s'),
                        ];

                        $_SESSION['flash'] = ($isVerifiedInt === 1)
                            ? 'Payment successful. Verified Premium user activated.'
                            : 'Payment successful. Premium user activated.';

                        /* --------- OPTION A (recommended): 303 redirect to stop resubmit --------- */
                        unset($_SESSION['csrf_token']);
                        header('Location: index.php?paid=1', true, 303);
                        exit;

                        /* --------- OPTION B (keep on-page receipt then JS redirect) ----------
                        // comment-out OPTION A (above) if you prefer to show receipt UI below.
                        */
                    }
                }
            } catch (Throwable $e) {
                try { if ($pdo->inTransaction()) $pdo->rollBack(); } catch (Throwable $_) {}
                $errors[] = 'Something went wrong while finalizing payment.';
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pay for <?php echo htmlspecialchars($planName); ?> • PhishSafeguard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
:root{
    --bg:#071427; --panel:#0f1e39; --panel2:#0b1628; --text:#cfe1ff; --muted:#8ea0c7;
    --accent:#64ffda; --border:rgba(100,255,218,.12); --error:#ff6b6b; --overlay:rgba(3,12,27,.55);
    --ease-overshoot:cubic-bezier(.2,.85,.2,1);
}
*{box-sizing:border-box}
html,body{height:100%}
body{
    margin:0; font-family:'Poppins',sans-serif; color:var(--text);
    background:linear-gradient(180deg,var(--bg),#031026);
    -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
}

/* Background image layer (uses your image at images/pay.jpg) */
.bg {
    position:fixed; inset:0; z-index:-2;
    background-image: url('images/pay.jpg');
    background-size: cover; background-position: center center;
    background-repeat:no-repeat;
    transform: scale(1.03);
    filter: brightness(.45) contrast(1.05) saturate(.9);
}

/* Soft radial vignette for depth */
.bg::after{
    content:""; position:absolute; inset:0; background: radial-gradient(60% 60% at 50% 30%, rgba(0,0,0,0) 0%, rgba(0,0,0,.45) 60%, rgba(0,0,0,.75) 100%);
}

/* Slight frosted backdrop behind main content */
.bg-frost {
    position:fixed; inset:0; z-index:-1; pointer-events:none;
    background: linear-gradient(180deg, rgba(3,12,27,.25), rgba(3,12,27,.45));
    backdrop-filter: blur(6px) saturate(.95);
}

/* Entrance */
body:not(.loaded) .wrap{ opacity:0; transform: translateY(14px) scale(.994); filter: blur(8px); }
body.loaded .wrap{ animation: wrapEntrance 900ms var(--ease-overshoot) both; }
@keyframes wrapEntrance{ from{opacity:0;transform:translateY(18px) scale(.992);filter:blur(10px)} to{opacity:1;transform:translateY(0) scale(1);filter:blur(0)} }
.wrap{ max-width:980px; margin:30px auto; padding:26px; }

/* Top */
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.brand{font-weight:800;color:var(--accent);display:flex;gap:12px;align-items:center}
.logo{height:44px;width:44px;border-radius:10px;background:linear-gradient(180deg,#08243f,#0b2a4a);display:flex;align-items:center;justify-content:center;font-weight:900;color:#d8fff0;box-shadow:0 6px 18px rgba(0,0,0,.45)}
.badge{background:rgba(245,166,35,.08);border:1px solid rgba(245,166,35,.18);color:#f5a623;padding:6px 10px;border-radius:999px;font-weight:700; font-size:.86rem}

/* grid layout */
.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:20px}
@media (max-width:900px){.grid{grid-template-columns:1fr}}

/* cards */
.card{ background:linear-gradient(180deg, rgba(255,255,255,.02), transparent); border:1px solid var(--border); border-radius:14px; padding:18px; box-shadow:0 20px 50px rgba(3,9,20,.55); backdrop-filter: blur(4px); }
label{display:block;font-size:.92rem;color:var(--muted);margin-bottom:6px}
input[type="password"],input[type="text"],input[type="email"]{
    width:100%; padding:12px; border-radius:10px; border:1px solid var(--border);
    background:linear-gradient(180deg,var(--panel2), rgba(11,22,40,.85)); color:var(--text); font-size:1rem; outline:none;
    transition: border-color .18s ease, box-shadow .18s ease, transform .08s ease;
}
input:focus{border-color:var(--accent);box-shadow:0 10px 30px rgba(100,255,218,.06);transform:translateY(-1px)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:10px;padding:12px 16px;border-radius:10px;border:1px solid var(--accent);background:var(--accent);color:#001b16;font-weight:700;cursor:pointer;transition:transform .18s,box-shadow .18s}
.btn:hover{transform:translateY(-4px);box-shadow:0 18px 40px rgba(100,255,218,.16)}
.btn.secondary{background:transparent;color:var(--accent);border:1px solid rgba(255,255,255,.04)}
.btn.secondary:hover{background:rgba(100,255,218,.06)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.row3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.small{font-size:.9rem;color:var(--muted)}
.price{font-weight:900;color:var(--accent);font-size:1.6rem}
.err{background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.2);color:#ffd6d6;padding:10px;border-radius:10px;margin-bottom:12px}
.ok{background:rgba(48,209,88,.09);border:1px solid rgba(48,209,88,.18);color:#c8ffd9;padding:10px;border-radius:10px;margin-bottom:12px}
.toast{position:fixed;left:50%;top:18px;transform:translateX(-50%);background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 14px;box-shadow:0 10px 30px rgba(0,0,0,.45);opacity:0;pointer-events:none}
.toast.show{animation:toastIn .28s both}
@keyframes toastIn{from{opacity:0;transform:translateX(-50%) translateY(-6px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}

/* modal & processing */
.modal{position:fixed;inset:0;background:rgba(3,12,27,.75);display:none;align-items:center;justify-content:center;z-index:999}
.modal.show{display:flex}
.box{width:100%;max-width:480px;background:linear-gradient(180deg, rgba(15,30,57,.96), rgba(11,22,40,.96));border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:0 30px 80px rgba(0,0,0,.6);transform-origin:center center;animation:pop .28s cubic-bezier(.2,.95,.2,1)}
@keyframes pop{from{transform:translateY(10px) scale(.98);opacity:0}to{transform:translateY(0) scale(1);opacity:1}}
.processing{position:fixed;inset:0;background:rgba(3,12,27,.75);display:none;align-items:center;justify-content:center;z-index:998}
.processing.show{display:flex}
.spinner{font-size:20px;margin-right:8px}
.checkwrap{display:flex;align-items:center;justify-content:center;margin:8px 0 10px}
.check{width:74px;height:74px;border-radius:50%;border:3px solid var(--accent);position:relative}
.check:after{content:"";position:absolute;left:24px;top:28px;width:10px;height:20px;border-right:4px solid var(--accent);border-bottom:4px solid var(--accent);transform:rotate(40deg) scale(0);transform-origin:left top;animation:tick .35s .2s ease forwards}
@keyframes tick{to{transform:rotate(40deg) scale(1)}}
.note{font-size:.85rem;color:var(--muted);margin-top:12px}
.brandChip { font-weight:700; color:var(--accent); }

/* responsive tweaks */
@media (max-width:520px){
    .row3{grid-template-columns:1fr}
    .brand{gap:8px}
    .logo{height:40px;width:40px}
}
</style>
</head>
<body>
    <!-- Background layers (image + frost) -->
    <div class="bg" aria-hidden="true"></div>
    <div class="bg-frost" aria-hidden="true"></div>

<div class="wrap">
    <div class="top">
        <div class="brand">
            <div class="logo">PS</div>
            <div>
                <div style="font-size:1.05rem">PhishSafeguard</div>
                <div style="font-size:.78rem;color:var(--muted)">Paying to • Secure subscription checkout</div>
            </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center">
            <a class="badge" href="?reset=1" title="Clear demo subscription flag">Reset Demo</a>
            <div class="badge"><i class="fa-solid fa-shield-halved"></i> Payment Checkout</div>
        </div>
    </div>

    <?php if (!empty($_SESSION['flash'])): ?>
        <div class="ok"><?php echo htmlspecialchars($_SESSION['flash']); unset($_SESSION['flash']); ?></div>
    <?php endif; ?>

    <?php if ($successPayload): /* OPTION B path only (if redirect disabled) */ ?>
        <div class="card">
            <div class="ok"><i class="fa-solid fa-circle-check"></i> Payment successful</div>
            <h2>Receipt</h2>
            <div class="row" style="margin-top:10px">
                <div><strong>Plan</strong><div class="small"><?php echo htmlspecialchars($successPayload['plan']); ?></div></div>
                <div><strong>Amount</strong><div class="small">₹<?php echo number_format($successPayload['amount']); ?></div></div>
            </div>
            <div style="margin-top:12px">
                <div class="small">Paid with <strong class="masked"><?php echo htmlspecialchars($successPayload['masked']); ?></strong></div>
                <div class="small" style="margin-top:6px">Email: <strong><?php echo htmlspecialchars($successPayload['email']); ?></strong></div>
                <div class="small" style="margin-top:6px">Transaction ID: <strong><?php echo htmlspecialchars($successPayload['txn']); ?></strong></div>
                <div class="small" style="margin-top:6px">Time: <strong><?php echo htmlspecialchars($successPayload['time']); ?></strong></div>
            </div>
            <div style="margin-top:14px">
                <a class="btn secondary" href="index.php"><i class="fa-solid fa-house"></i> Home</a>
                <a class="btn" href="contact.php"><i class="fa-solid fa-receipt"></i> Need help?</a>
            </div>
        </div>

        <script>
            setTimeout(function(){ window.location.href = 'index.php'; }, 2000);
        </script>

    <?php else: ?>

        <?php if ($errors): ?><div class="err"><?php echo htmlspecialchars(implode(' ', $errors)); ?></div><?php endif; ?>

        <div class="grid">
            <div class="card" aria-live="polite">
                <h2>Pay with Card</h2>
                <p class="small" style="margin-top:6px">Complete purchase for <strong><?php echo htmlspecialchars($planName); ?></strong> — <span class="price">₹<?php echo number_format($amount); ?></span></p>

                <form id="checkoutForm" method="post" novalidate>
                    <input type="hidden" name="plan" value="<?php echo htmlspecialchars($planName); ?>">
                    <input type="hidden" name="amount" value="<?php echo (int)$amount; ?>">
                    <input type="hidden" name="otp_verified" id="otp_verified" value="0">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                    <label>Cardholder name</label>
                    <input id="cardholder" name="cardholder" type="text" autocomplete="cc-name" placeholder="Full name (as on card)" required>

                    <label style="margin-top:12px">Card number</label>

                    <!-- VISIBLE masked input for UX; accepts paste & Ctrl+V -->
                    <input id="card_view" name="card_view" type="text" inputmode="numeric" maxlength="23" placeholder="Enter card number" autocomplete="off" required>

                    <!-- HIDDEN real numeric card field that WILL be submitted as 'card' (server expects $_POST['card']) -->
                    <input id="card_hidden" name="card" type="hidden" value="">

                    <div style="margin-top:8px;display:flex;justify-content:space-between;align-items:center">
                        <div class="small">Digits are masked for privacy.</div>
                        <div id="brandChip" class="small brandChip" style="font-weight:700"></div>
                    </div>

                    <!-- Demo RuPay filler button -->
                    <div style="margin-top:10px; display:flex; gap:10px; align-items:center;">
                        
                    </div>

                    <div style="margin-top:12px" class="row">
                        <div>
                            <label>Expiry (MM/YY)</label>
                            <input id="expiry" name="expiry" type="password" inputmode="numeric" placeholder="MM/YY" maxlength="5" required>
                        </div>
                        <div>
                            <label>CVV</label>
                            <input id="cvv" name="cvv" type="password" inputmode="numeric" placeholder="3 or 4 digits" maxlength="4" required>
                        </div>
                    </div>

                    <div style="margin-top:12px">
                        <label>Email for receipt</label>
                        <input id="email" name="email" type="email" placeholder="you@example.com" required>
                    </div>

                    <div style="margin-top:12px">
                        <label>Card type</label>
                        <div style="display:flex;gap:16px;align-items:center">
                            <label><input id="modeCredit" type="radio" name="cardmode" value="credit"> Credit</label>
                            <label><input id="modeDebit" type="radio" name="cardmode" value="debit" checked> Debit</label>
                        </div>
                    </div>

                    <div style="margin-top:14px" class="row3">
                        <div class="small card"><div class="small">Plan</div><div class="small"><?php echo htmlspecialchars($planName); ?></div></div>
                        <div class="small card"><div class="small">Billing</div><div class="small">One-time</div></div>
                        <div class="small card"><div class="small">Amount</div><div class="price">₹<?php echo number_format($amount); ?></div></div>
                    </div>

                    <div style="margin-top:16px">
                        <button id="payBtn" class="btn" type="button"><i class="fa-solid fa-lock"></i> Pay ₹<?php echo number_format($amount); ?></button>
                    </div>
                </form>
            </div>

            <div class="card">
                <h2 style="margin:0">Order Summary</h2>
                <div class="small" style="margin-top:6px;color:var(--muted)">You're paying <strong>PhishSafeguard</strong> securely.</div>

                <div class="summary-list" style="margin-top:12px;display:grid;gap:10px">
                    <div class="summary-item" style="display:flex;justify-content:space-between;padding:12px;border-radius:10px;background:linear-gradient(180deg,rgba(255,255,255,.01),transparent);border:1px solid rgba(255,255,255,.02)">
                        <div><strong><?php echo htmlspecialchars($planName); ?></strong><div class="small" style="color:var(--muted)">One-time access to features</div></div><div style="font-weight:800">₹<?php echo number_format($amount); ?></div>
                    </div>

                    <div class="summary-item" style="display:flex;justify-content:space-between;padding:12px;border-radius:10px;background:linear-gradient(180deg,rgba(255,255,255,.01),transparent);border:1px solid rgba(255,255,255,.02)">
                        <div class="small" style="color:var(--muted)">Payment method</div>
                        <div class="small" id="summaryBrand">Card</div>
                    </div>

                    <div class="summary-item" style="display:flex;justify-content:space-between;padding:12px;border-radius:10px;background:linear-gradient(180deg,rgba(255,255,255,.01),transparent);border:1px solid rgba(255,255,255,.02)">
                        <div class="small" style="color:var(--muted)">Receipt</div><div class="small">Email after payment</div>
                    </div>
                </div>

                <div style="margin-top:12px;display:flex;justify-content:space-between;align-items:center;padding:12px;border-radius:12px;background:linear-gradient(180deg,rgba(100,255,218,.03),transparent);border:1px solid rgba(100,255,218,.06)">
                    <div style="font-weight:700">Total</div>
                    <div style="font-weight:900;font-size:1.1rem">₹<?php echo number_format($amount); ?></div>
                </div>

               </div>
        </div>
    <?php endif; ?>
</div>

<div id="otpToast" class="toast" role="status" aria-live="polite">OTP has been sent to your registered number.</div>

<div id="otpModal" class="modal" aria-hidden="true" hidden>
    <div class="box" role="dialog" aria-modal="true" aria-labelledby="otpTitle">
        <h3 id="otpTitle">Enter OTP</h3>
        <p class="small" style="margin-top:6px">Please enter the 6-digit OTP.</p>
        <input id="otpInput" type="password" inputmode="numeric" pattern="\d*" maxlength="6" placeholder="••••••" style="width:100%;padding:12px;border-radius:10px;border:1px solid var(--border);background:var(--panel2);color:var(--text);margin-top:10px">
        <div style="display:flex;gap:10px;margin-top:14px;justify-content:flex-end">
            <button id="cancelOtp" class="btn secondary">Cancel</button>
            <button id="verifyOtp" class="btn">Verify</button>
        </div>
        <div id="otpMsg" class="small" style="margin-top:8px;color:#ffd6d6"></div>
    </div>
</div>

<div id="processing" class="processing" aria-hidden="true" hidden>
    <div class="box" style="max-width:360px;display:flex;align-items:center;gap:12px">
        <i class="fa-solid fa-circle-notch fa-spin spinner"></i>
        <div>
            <div style="font-weight:700">Processing your payment…</div>
            <div class="small" style="margin-top:6px;color:var(--muted)">This is a simulation. Please wait.</div>
        </div>
    </div>
</div>

<div id="successModal" class="modal" aria-hidden="true">
    <div class="box" style="text-align:center">
        <div class="checkwrap"><div class="check"></div></div>
        <h3>Plan purchased</h3>
        <p class="small" style="margin-top:6px">Your <?php echo htmlspecialchars($planName); ?> plan is now active.</p>
        <div style="margin-top:12px">
            <a class="btn" href="index.php">Go to Home</a>
        </div>
    </div>
</div>

<script>
(function(){
    // Elements
    const cardView = document.getElementById('card_view');   // visible masked input
    const cardHidden = document.getElementById('card_hidden'); // hidden real card digits (submitted)
    const brandChip = document.getElementById('brandChip');
    const summaryBrand = document.getElementById('summaryBrand');
    const expiryEl = document.getElementById('expiry');
    const cvvEl = document.getElementById('cvv');
    const holderEl = document.getElementById('cardholder');
    const emailEl = document.getElementById('email');
    const payBtn = document.getElementById('payBtn');
    const form = document.getElementById('checkoutForm');
    const otpToast = document.getElementById('otpToast');
    const otpModal = document.getElementById('otpModal');
    const otpInput = document.getElementById('otpInput');
    const otpMsg = document.getElementById('otpMsg');
    const cancelOtp = document.getElementById('cancelOtp');
    const verifyOtp = document.getElementById('verifyOtp');
    const processing = document.getElementById('processing');
    const successModal = document.getElementById('successModal');
    const otpVerifiedField = document.getElementById('otp_verified');
    const fillDemoRuPay = document.getElementById('fillDemoRuPay');
    const modeDebit = document.getElementById('modeDebit');
    const modeCredit = document.getElementById('modeCredit');

    const onlyDigits = (v) => (v||'').replace(/\D+/g,'');

    // BIN/regex-based brand detection (covers main patterns)
    function detectCardBrand(pan) {
        if (!pan || pan.length === 0) return '';
        if (/^4/.test(pan)) return 'Visa';
        if (/^3[47]/.test(pan)) return 'Amex';
        // Mastercard: 51-55 or 2221-2720 range
        if (/^(5[1-5])/.test(pan) || /^(222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(pan)) return 'Mastercard';
        // Discover (common prefixes)
        if (/^(6011|65|64[4-9])/.test(pan)) return 'RuPay';
        // RuPay (approx prefixes used in India: 60, 6521, 6522, 508, 621, 624, 628)
        if (/^(60|6521|6522|508|621|624|628)/.test(pan)) return 'RuPay';
        return '';
    }

    // Masking helper: show bullets for every digit (no revealing last4)
    function formatMaskedAll(pan) {
        if (!pan) return '';
        const bullets = '•'.repeat(pan.length);
        // group into 4-digit chunks for readability (still bullets)
        const groups = [];
        const clean = bullets;
        for (let i = 0; i < clean.length; i += 4) groups.push(clean.slice(i, i+4));
        return groups.join(' ');
    }

    // Update visible mask + hidden actual value + brand displays
    function updateCardUI(rawDigits) {
        // keep hidden numeric value for server
        cardHidden.value = rawDigits;

        // show masked bullets in visible input (all masked)
        cardView.value = formatMaskedAll(rawDigits);

        // detect brand
        const brand = detectCardBrand(rawDigits);

        // Show "Visa" only after user has typed at least 8 digits.
        // For other brands show as soon as detection finds them.
        const brandToShow = (brand === 'Visa' && rawDigits.length < 8) ? '' : brand;

        brandChip.textContent = brandToShow;
        summaryBrand.textContent = brandToShow || 'Card';
    }

    // Keep an internal buffer of digits to allow editing/backspace
    let digitBuffer = '';

    // Handle keydown on the visible field.
    // Allow Ctrl/Cmd+V (paste) and other modifier combos — do NOT block when ctrl/meta pressed.
    cardView.addEventListener('keydown', function(e){
        // allow navigation keys
        const navKeys = ['ArrowLeft','ArrowRight','Backspace','Delete','Tab','Home','End'];
        if (navKeys.includes(e.key)) {
            if (e.key === 'Backspace') {
                e.preventDefault();
                // remove last digit
                digitBuffer = digitBuffer.slice(0, -1);
                updateCardUI(digitBuffer);
            }
            // let Tab/Home/End/Arrows behave (no extra handling)
            return;
        }

        // If user holds Ctrl/Cmd or Alt — allow default (so paste via Ctrl+V works)
        if (e.ctrlKey || e.metaKey || e.altKey) {
            return; // do not prevent default; lets paste / select-all work
        }

        // Only accept digits; prevent default for other keys
        if (!/^\d$/.test(e.key)) {
            e.preventDefault();
            return;
        }

        // digit typed
        if (/^\d$/.test(e.key)) {
            e.preventDefault();
            if (digitBuffer.length < 19) { // max 19 digits
                digitBuffer += e.key;
                updateCardUI(digitBuffer);
            }
        }
    });

    // Handle paste: replace buffer with digits from clipboard (not append)
    cardView.addEventListener('paste', function(e){
        e.preventDefault();
        const txt = (e.clipboardData || window.clipboardData).getData('text') || '';
        const digits = onlyDigits(txt);
        if (!digits) return;
        // Replace buffer with pasted digits (limit to 19)
        digitBuffer = digits.slice(0, 19);
        updateCardUI(digitBuffer);
    });

    // Also allow drop (drag-drop) of card text
    cardView.addEventListener('drop', function(e){
        e.preventDefault();
        const txt = (e.dataTransfer && e.dataTransfer.getData) ? e.dataTransfer.getData('text') : '';
        const digits = onlyDigits(txt);
        if (!digits) return;
        digitBuffer = digits.slice(0, 19);
        updateCardUI(digitBuffer);
    });

    // Fill demo RuPay card on button click
    fillDemoRuPay?.addEventListener('click', function(e){
        // Demo RuPay card (Luhn-valid): 6521 0000 0000 0007
        const demoPan = '6521000000000007';
        const demoExpiry = '12/30';
        const demoCvv = '987';
        const demoEmail = 'demo@phishsafeguard.test';

        digitBuffer = demoPan;
        updateCardUI(digitBuffer);

        // set hidden, expiry, cvv, email, set debit
        cardHidden.value = demoPan;
        expiryEl.value = demoExpiry;
        cvvEl.value = demoCvv;
        emailEl.value = demoEmail;
        if (modeDebit) modeDebit.checked = true;
        if (modeCredit) modeCredit.checked = false;

        // visual feedback: small toast
        otpToast.textContent = 'Demo RuPay card filled (OTP: 123456)';
        otpToast.classList.add('show');
        setTimeout(()=> { otpToast.classList.remove('show'); otpToast.textContent = 'OTP has been sent to your registered number.'; }, 1800);
    });

    // If the form is submitted by script, ensure hidden has digits (already kept updated)
    document.addEventListener('DOMContentLoaded', function(){
        const initial = onlyDigits(cardHidden.value || '');
        if (initial) {
            digitBuffer = initial;
            updateCardUI(digitBuffer);
        } else {
            summaryBrand.textContent = 'Card';
            brandChip.textContent = '';
        }
    });

    // Luhn check for client-side
    function luhn(num){
        let sum=0, alt=false;
        for(let i=num.length-1;i>=0;i--){
            let n=parseInt(num[i],10);
            if(alt){ n*=2; if(n>9)n-=9; }
            sum+=n; alt=!alt;
        }
        return sum%10===0;
    }

    function flashError(btn, message){
        const orig = btn.innerHTML;
        const obg = btn.style.background, oc = btn.style.color, ob = btn.style.borderColor;
        btn.innerHTML = message;
        btn.style.background = 'transparent';
        btn.style.color = 'var(--error)';
        btn.style.borderColor = 'var(--error)';
        btn.disabled = true;
        setTimeout(()=>{ btn.innerHTML = orig; btn.style.background=obg; btn.style.color=oc; btn.style.borderColor=ob; btn.disabled=false; }, 1600);
    }

    payBtn?.addEventListener('click', ()=>{
        if (!form) return;

        const name = (holderEl.value||'').trim();
        const pan  = onlyDigits(cardHidden.value);
        const exp  = (expiryEl.value||'').trim();
        const cvv  = onlyDigits(cvvEl.value);
        const email= (emailEl.value||'').trim();

        let err='';
        if(!name) err='Enter cardholder name';
        else if(!(pan.length>=13 && pan.length<=19) || !luhn(pan)) err='Invalid card number';
        else if(!/^\d{2}\/\d{2}$/.test(exp)) err='Enter expiry as MM/YY';
        else{
            const [mmStr,yyStr]=exp.split('/');
            const mm=parseInt(mmStr,10), yy=parseInt(yyStr,10);
            const now = new Date(), curYY = now.getFullYear()%100, curMM = now.getMonth()+1;
            if(mm<1||mm>12) err='Invalid expiry month';
            else if(yy<curYY || (yy===curYY && mm<curMM)) err='Card expired';
        }
        if(!err && !(cvv.length===3 || cvv.length===4)) err='Invalid CVV';
        if(!err && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) err='Enter valid email';
        if(err) return flashError(payBtn, err);

        payBtn.disabled = true;
        payBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Initiating…';
        setTimeout(()=>{
            payBtn.innerHTML = '<?php echo 'Pay ₹'.number_format($amount); ?>';
            payBtn.disabled = false;
            otpToast.classList.add('show');
            setTimeout(()=>{
                otpToast.classList.remove('show');
                otpModal.hidden = false;
                otpModal.classList.add('show');
                otpModal.setAttribute('aria-hidden','false');
                otpInput.value=''; otpMsg.textContent=''; otpInput.focus();
            }, 900);
        }, 800);
    });

    cancelOtp?.addEventListener('click', ()=>{
        otpModal.classList.remove('show');
        otpModal.setAttribute('aria-hidden','true');
        otpModal.hidden = true;
    });

    verifyOtp?.addEventListener('click', ()=>{
        const v = (otpInput.value||'').trim();
        if(v.length !== 6) { otpMsg.textContent = 'Enter 6 digit code'; return; }
        if(v !== '<?php echo DEMO_OTP; ?>') { otpMsg.textContent = 'Incorrect OTP'; return; }

        otpVerifiedField.value = '1';
        otpModal.classList.remove('show');
        otpModal.setAttribute('aria-hidden','true');
        otpModal.hidden = true;

        processing.classList.add('show');
        processing.hidden = false;

        setTimeout(()=>{
            processing.classList.remove('show');
            processing.hidden = true;
            successModal.classList.add('show');
            successModal.setAttribute('aria-hidden','false');
            setTimeout(()=>{ form.submit(); }, 800);
        }, 1000);
    });

    otpInput?.addEventListener('keydown', (e)=>{
        if(e.key === 'Enter'){ e.preventDefault(); document.getElementById('verifyOtp').click(); }
    });

    // initialize page loaded state
    document.body.classList.add('loaded');
})();
</script>
</body>
</html>
