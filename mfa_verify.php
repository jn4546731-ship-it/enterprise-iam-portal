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
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Quantum MFA Challenge - Enterprise Zero-Trust</title>
    <!-- Immediate Theme Application to Prevent Flash of Wrong Theme -->
    <script>
        (function() {
            const savedTheme = localStorage.getItem('iam_theme') || 'dark';
            if (savedTheme === 'light') {
                document.documentElement.classList.remove('dark');
                document.documentElement.classList.add('light');
            } else {
                document.documentElement.classList.add('dark');
                document.documentElement.classList.remove('light');
            }
        })();
    </script>
    <script src="assets/js/tailwind.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        "surface": "#0f131c",
                        "surface-dim": "#0f131c",
                        "surface-bright": "#353942",
                        "surface-container-lowest": "#0a0e16",
                        "surface-container-low": "#181c24",
                        "surface-container": "#1c2028",
                        "surface-container-high": "#262a33",
                        "surface-container-highest": "#31353e",
                        "on-surface": "#dfe2ee",
                        "on-surface-variant": "#bdc8d1",
                        "outline": "#87929a",
                        "outline-variant": "#3e484f",
                        "primary": "#8ed5ff",
                        "primary-container": "#38bdf8",
                        "on-primary": "#00354a",
                        "on-primary-container": "#004965",
                        "secondary": "#4edea3",
                        "secondary-container": "#00a572",
                        "tertiary": "#ffc174",
                        "tertiary-container": "#f59e0b",
                        "error": "#ffb4ab",
                        "error-container": "#93000a",
                        "on-error": "#690005"
                    },
                    fontFamily: {
                        sans: ["Geist", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
                        mono: ["JetBrains Mono", "Share Tech Mono", "monospace"]
                    }
                }
            }
        };
    </script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css?v=<?php echo time(); ?>" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="bg-[#090d16] min-h-screen flex flex-col items-center justify-center px-4 py-8 relative text-slate-300">

    <!-- Top Telemetry Status Header -->
    <header class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 py-2.5 bg-[#0c101a]/90 border-b border-[#1c2233] backdrop-blur-md text-xs font-sans text-slate-400">
        <div class="flex items-center space-x-2.5">
            <div class="w-6 h-6 rounded-md bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <i class="fa-solid fa-shield-halved text-xs"></i>
            </div>
            <span class="font-bold text-white tracking-tight">SECURE·DEFENSE</span>
            <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">MFA INTERCEPT</span>
        </div>
        <div class="hidden sm:flex items-center space-x-4 text-xs font-mono">
            <span>Session: <strong class="text-amber-400">QUARANTINE_PENDING</strong></span>
            <span class="text-slate-600">|</span>
            <span>Standard: <strong class="text-sky-300">RFC 6238 TOTP</strong></span>
            <span class="text-slate-600">|</span>
            <span>Window: <strong class="text-slate-300">30s Rolling</strong></span>
        </div>
    </header>

    <!-- Main Okta-Grade MFA Card -->
    <div class="relative z-10 w-full max-w-md my-auto pt-8">
        <div class="bg-[#10141f] rounded-xl p-8 sm:p-9 shadow-2xl border border-[#1c2233]">
            
            <div class="text-center mb-6">
                <div class="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 mb-3 shadow-inner">
                    <i class="fa-solid fa-mobile-screen-button text-2xl"></i>
                </div>
                <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight font-sans">
                    Two-Step Verification
                </h1>
                <p class="text-xs text-slate-400 mt-1 font-sans">
                    Enter the 6-digit code from your authenticator app
                </p>
                <div class="mt-2.5 inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono text-amber-300 bg-amber-500/10 border border-amber-500/20">
                    <i class="fa-solid fa-user-check text-[10px]"></i>
                    <span class="truncate max-w-[220px]"><?php echo htmlspecialchars($user['email'] ?? 'Authenticated Identity'); ?></span>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-500/10 border border-red-500/30 text-red-300 p-3.5 rounded-lg mb-6 text-xs flex items-start">
                    <i class="fa-solid fa-circle-exclamation mr-2.5 mt-0.5 text-base text-red-400 flex-shrink-0"></i>
                    <div>
                        <strong class="text-red-400 font-semibold">Verification Failed:</strong>
                        <p class="mt-0.5 text-slate-300"><?php echo htmlspecialchars($error); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <!-- TOTP Input Form -->
            <form method="POST" action="" class="space-y-5">
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 text-center">
                        6-Digit Security Code
                    </label>
                    <input type="text" name="mfa_code" maxlength="6" autofocus 
                           class="w-full px-4 py-3.5 rounded-lg text-center tracking-[0.45em] font-mono font-bold text-2xl bg-[#090d16] border border-[#1c2233] text-sky-400 placeholder:text-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-500/30 focus:border-sky-500 transition" 
                           placeholder="000000" required autocomplete="one-time-code" inputmode="numeric">
                    
                    <!-- 30-Second Rolling Code Progress Bar -->
                    <div class="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-500">
                        <span id="totpSecLabel">Rolling Code Active</span>
                        <div class="w-28 bg-[#090d16] rounded-full h-1.5 overflow-hidden border border-[#1c2233]">
                            <div id="totpProgressBar" class="bg-sky-400 h-full transition-all duration-1000 ease-linear" style="width: 100%;"></div>
                        </div>
                    </div>
                </div>

                <button type="submit" class="w-full py-2.5 px-4 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm rounded-md transition shadow-md flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-shield-check text-sm"></i>
                    <span>Verify Identity</span>
                </button>
            </form>
            
            <div class="mt-6 pt-4 border-t border-[#1c2233] text-center text-xs">
                <a href="logout.php" class="text-slate-400 hover:text-white transition flex items-center justify-center space-x-1.5 font-sans">
                    <i class="fa-solid fa-arrow-left text-xs"></i>
                    <span>Cancel and return to sign in</span>
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
