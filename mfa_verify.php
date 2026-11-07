<?php
session_start();
require_once 'db.php';
require_once 'mfa_helper.php';

if (!isset($_SESSION['pending_user_id'])) {
    header("Location: index.php");
    exit();
}

$pending_user_id = (int) $_SESSION['pending_user_id'];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $entered_code = trim($_POST['mfa_code'] ?? '');
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

    $stmt = $conn->prepare("SELECT mfa_secret, is_active, email FROM users WHERE user_id = ?");
    $stmt->bind_param("i", $pending_user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    // Verify account active status
    if (!$user || (isset($user['is_active']) && (int) $user['is_active'] === 0)) {
        unset($_SESSION['pending_user_id']);
        header("Location: index.php?error=suspended");
        exit();
    }

    if ($user && verifyMfaToken($user['mfa_secret'], $entered_code)) {
        // MFA passed! Promote to full authenticated session
        $_SESSION['user_id'] = $pending_user_id;
        $_SESSION['fresh_login'] = true; // Trigger Animated Cybersecurity Welcome HUD
        unset($_SESSION['pending_user_id']); 
        
        // Audit Log for successful MFA
        $action_type = "MFA_AUTH";
        $action_desc = "User authenticated successfully (MFA Verified)";
        
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $_SESSION['user_id'], $action_type, $action_desc, $ip_address);
        $log_stmt->execute();

        header("Location: dashboard.php");
        exit();
    } else {
        // Audit Log for failed MFA attempt
        $action_type = "MFA_FAIL";
        $action_desc = "Failed MFA challenge attempt for " . ($user['email'] ?? "UID-{$pending_user_id}");
        
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $pending_user_id, $action_type, $action_desc, $ip_address);
        $log_stmt->execute();
        
        $error = "Invalid Authenticator code. Please check your token and try again.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum MFA Challenge - Enterprise Zero-Trust</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay min-h-screen flex items-center justify-center px-4 relative overflow-x-hidden text-slate-300">

    <!-- Top Telemetry Status Ticker -->
    <div class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 py-2.5 bg-slate-950/80 border-b border-cyan-500/20 backdrop-blur-md text-[11px] font-tech text-cyan-400/90">
        <div class="flex items-center space-x-3">
            <span class="inline-flex h-2 w-2 rounded-full bg-amber-400 cyber-beacon"></span>
            <span class="tracking-widest uppercase font-bold text-white">INTERCEPT QUARANTINE // TOTP CHALLENGE</span>
        </div>
        <div class="hidden sm:flex items-center space-x-6 text-slate-400">
            <span>SESSION: <strong class="text-amber-400">PENDING_CHALLENGE</strong></span>
            <span>STANDARD: <strong class="text-cyan-300">RFC 6238 TOTP</strong></span>
            <span>WINDOW: <strong class="text-purple-400">30s TIME-SLICE</strong></span>
        </div>
    </div>

    <!-- Main High-Tech MFA Terminal Card -->
    <div class="relative z-10 w-full max-w-md my-12">
        <div class="cyber-card cyber-brackets rounded-2xl p-7 sm:p-9 shadow-2xl relative overflow-hidden border border-cyan-500/30">
            
            <!-- Laser Scan Line -->
            <div class="cyber-laser-beam"></div>

            <!-- Rotating Holographic Radar Scanner -->
            <div class="text-center mb-8 relative">
                <div class="relative inline-flex items-center justify-center w-24 h-24 mb-3">
                    <div class="absolute inset-0 rounded-full border border-dashed border-cyan-500/40 cyber-radar-spin"></div>
                    <div class="absolute inset-2 rounded-full border border-purple-500/40 cyber-radar-reverse"></div>
                    <div class="absolute inset-4 rounded-full bg-cyan-950/70 border border-cyan-400/60 flex items-center justify-center text-cyan-400 glow-cyan-sm shadow-inner">
                        <i class="fa-solid fa-fingerprint text-3xl text-cyan-300 animate-pulse"></i>
                    </div>
                </div>

                <h1 class="font-orbitron text-lg sm:text-xl font-extrabold text-white tracking-wider glow-text-cyan mb-1">
                    IDENTITY <span class="text-cyan-400">CHALLENGE</span>
                </h1>
                <p class="font-tech text-xs text-slate-400 tracking-wider">
                    Enter dynamic 6-digit TOTP cryptographic token
                </p>

                <!-- Quarantined Identity Badge -->
                <div class="mt-3 inline-flex items-center space-x-2 px-3 py-1 rounded-full text-[11px] font-tech text-amber-300 bg-amber-950/40 border border-amber-500/40 shadow-sm">
                    <i class="fa-solid fa-user-shield text-[10px] text-amber-400"></i>
                    <span class="font-bold"><?php echo htmlspecialchars($user['email'] ?? 'Authenticated Identity'); ?></span>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-950/40 border border-red-500/60 text-red-300 p-3.5 rounded-xl mb-6 text-xs font-tech flex items-start glow-red shadow-lg animate-pulse">
                    <i class="fa-solid fa-triangle-exclamation mr-2.5 mt-0.5 text-base text-red-400 flex-shrink-0"></i>
                    <div>
                        <strong class="text-red-400 uppercase font-bold tracking-wider">Challenge Failed:</strong>
                        <p class="mt-0.5"><?php echo htmlspecialchars($error); ?></p>
                    </div>
                </div>
                <script>
                    window.addEventListener('DOMContentLoaded', () => {
                        if (typeof CyberAudio !== 'undefined') CyberAudio.accessDenied();
                    });
                </script>
            <?php endif; ?>

            <!-- TOTP Input Form -->
            <form method="POST" action="" class="space-y-6">
                <div>
                    <label class="block font-tech text-xs text-cyan-300 uppercase tracking-widest text-center mb-3">
                        6-Digit Micro-Challenge Code
                    </label>
                    <div class="relative">
                        <input type="text" name="mfa_code" maxlength="6" autofocus 
                               class="cyber-input w-full px-4 py-4 rounded-xl text-center tracking-[0.55em] font-orbitron font-bold text-2xl text-cyan-300 placeholder:text-slate-700 glow-cyan-sm focus:ring-0 focus:border-cyan-400" 
                               placeholder="••••••" required autocomplete="one-time-code" inputmode="numeric">
                    </div>
                    
                    <!-- 30-Second TOTP Time Remaining Bar -->
                    <div class="mt-3 flex items-center justify-between text-[10px] font-tech text-slate-500">
                        <span id="totpSecLabel">Dynamic Token Active</span>
                        <div class="w-32 bg-slate-900 rounded-full h-1.5 overflow-hidden border border-slate-800">
                            <div id="totpProgressBar" class="bg-gradient-to-r from-cyan-400 to-indigo-500 h-full transition-all duration-1000 ease-linear" style="width: 100%;"></div>
                        </div>
                    </div>
                </div>

                <button type="submit" class="cyber-btn w-full py-3.5 px-4 bg-gradient-to-r from-cyan-600 via-blue-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 text-white font-bold text-xs tracking-widest rounded-xl transition shadow-lg glow-cyan flex items-center justify-center space-x-2 group">
                    <i class="fa-solid fa-shield-halved text-sm group-hover:scale-110 transition"></i>
                    <span>CONFIRM CRYPTOGRAPHIC CHALLENGE</span>
                </button>
            </form>
            
            <div class="mt-8 pt-4 border-t border-slate-800/80 text-center font-tech text-xs text-slate-500">
                <a href="logout.php" class="text-slate-400 hover:text-cyan-400 transition flex items-center justify-center space-x-1.5">
                    <i class="fa-solid fa-arrow-left text-[11px]"></i>
                    <span>Abort Quarantine & Return to Gateway</span>
                </a>
            </div>
        </div>
    </div>

    <!-- Live TOTP 30-second slice sync script -->
    <script>
        function updateTotpProgress() {
            const now = Math.floor(Date.now() / 1000);
            const remaining = 30 - (now % 30);
            const pct = (remaining / 30) * 100;
            const bar = document.getElementById('totpProgressBar');
            const lbl = document.getElementById('totpSecLabel');
            if (bar) bar.style.width = pct + '%';
            if (lbl) lbl.textContent = `Token Refresh in ${remaining}s`;
        }
        setInterval(updateTotpProgress, 1000);
        updateTotpProgress();
    </script>

</body>
</html>
