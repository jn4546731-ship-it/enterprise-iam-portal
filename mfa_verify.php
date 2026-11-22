<?php
/**
 * Enterprise IAM Portal - Multi-Factor Authentication Verification Gate
 * Challenge intercept requiring RFC 6238 TOTP passcode before granting full session.
 */

session_start();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/mfa_helper.php';

if (!isset($_SESSION['pending_user_id'])) {
    header("Location: index.php");
    exit();
}

$pending_user_id = (int) $_SESSION['pending_user_id'];
$error = '';

$stmt = $conn->prepare("SELECT mfa_secret, is_active, email FROM users WHERE user_id = ?");
$stmt->bind_param("i", $pending_user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user || (isset($user['is_active']) && (int) $user['is_active'] === 0)) {
    unset($_SESSION['pending_user_id']);
    header("Location: index.php?error=suspended");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $entered_code = trim($_POST['mfa_code'] ?? '');
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

    if (verifyMfaToken($user['mfa_secret'], $entered_code)) {
        // MFA passed! Promote to full authenticated session
        $_SESSION['user_id'] = $pending_user_id;
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
        
        $error = "Invalid verification code. Please check your authenticator token and try again.";
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Two-Step Verification &mdash; Enterprise IAM</title>
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
    <script id="tailwind-config">
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            colors: {
              "surface": "#0d1117",
              "surface-container-lowest": "#090d13",
              "surface-container-low": "#161b22",
              "surface-container": "#1c2128",
              "surface-container-high": "#21262d",
              "surface-container-highest": "#30363d",
              "on-surface": "#e6edf3",
              "on-surface-variant": "#8b949e",
              "primary": "#2f81f7",
              "primary-container": "#1f6feb",
              "on-primary": "#ffffff"
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
<body class="bg-[#0d1117] min-h-screen flex flex-col items-center justify-center px-4 py-8 relative text-[#e6edf3] font-sans antialiased selection:bg-[#2f81f7] selection:text-white">

    <!-- Top Telemetry Header -->
    <header class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 h-16 bg-[#161b22] border-b border-[#30363d] backdrop-blur-md text-xs font-sans">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-md bg-[#2f81f7]/15 border border-[#2f81f7]/30 flex items-center justify-center text-[#2f81f7] shrink-0">
                <i class="fa-solid fa-shield-halved text-sm"></i>
            </div>
            <div class="flex flex-col">
                <span class="font-semibold text-white tracking-tight">Enterprise IAM</span>
                <span class="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Identity Governance</span>
            </div>
        </div>

        <div class="flex items-center gap-4">
            <div class="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0d1117] border border-[#30363d] text-xs font-mono text-slate-300">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                <span>Environment: Production</span>
            </div>

            <!-- Theme Switcher -->
            <button id="themeToggleBtn" onclick="toggleTheme()" class="p-2 rounded-md bg-[#0d1117] border border-[#30363d] text-slate-300 hover:text-white hover:bg-[#21262d] transition text-xs" title="Toggle Light / Dark mode">
                <i id="themeToggleIcon" class="fa-solid fa-sun text-amber-400"></i>
            </button>

            <a href="logout.php" class="text-xs text-slate-400 hover:text-white transition flex items-center gap-1.5 font-sans pl-2 border-l border-[#30363d]">
                <i class="fa-solid fa-arrow-left text-xs"></i>
                <span>Cancel Sign In</span>
            </a>
        </div>
    </header>

    <!-- Main Verification Card -->
    <div class="relative z-10 w-full max-w-md my-auto pt-16">
        <div class="bg-[#161b22] rounded-xl p-8 sm:p-9 shadow-2xl border border-[#30363d]">
            
            <div class="text-center mb-6">
                <div class="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-[#2f81f7]/15 border border-[#2f81f7]/30 text-[#2f81f7] mb-3 shadow-xs">
                    <i class="fa-solid fa-fingerprint text-xl"></i>
                </div>
                <h1 class="text-xl font-bold text-white tracking-tight">
                    Two-Step Verification
                </h1>
                <p class="text-xs text-slate-400 mt-1">
                    Enter the 6-digit passcode generated by your authenticator app
                </p>
                <div class="mt-3 inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono text-slate-300 bg-[#0d1117] border border-[#30363d]">
                    <i class="fa-solid fa-user-shield text-[#2f81f7] text-[11px]"></i>
                    <span class="truncate max-w-[220px]"><?php echo htmlspecialchars($user['email'] ?? 'Authenticated Identity'); ?></span>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-500/10 border border-red-500/30 text-red-400 p-3.5 rounded-lg mb-6 text-xs flex items-start gap-2.5 font-mono">
                    <i class="fa-solid fa-circle-exclamation mt-0.5 text-sm shrink-0"></i>
                    <div>
                        <strong class="text-white">Verification Failed:</strong>
                        <p class="mt-0.5 text-red-300"><?php echo htmlspecialchars($error); ?></p>
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
                           class="w-full px-4 py-3 rounded-md text-center tracking-[0.45em] font-mono font-bold text-2xl bg-[#0d1117] border border-[#30363d] text-[#2f81f7] placeholder:text-slate-700 focus:outline-none focus:border-[#2f81f7] transition" 
                           placeholder="000000" required autocomplete="one-time-code" inputmode="numeric">
                    
                    <!-- 30-Second Rolling Code Progress Bar -->
                    <div class="mt-3 flex items-center justify-between text-[11px] font-mono text-slate-500">
                        <span id="totpSecLabel">Rolling Code Active</span>
                        <div class="w-28 bg-[#0d1117] rounded-full h-1.5 overflow-hidden border border-[#30363d]">
                            <div id="totpProgressBar" class="bg-[#2f81f7] h-full transition-all duration-1000 ease-linear" style="width: 100%;"></div>
                        </div>
                    </div>
                </div>

                <button type="submit" class="w-full py-2.5 px-4 bg-[#2f81f7] hover:bg-blue-600 text-white font-semibold text-xs rounded-md transition shadow-xs flex items-center justify-center gap-2">
                    <i class="fa-solid fa-shield-check text-xs"></i>
                    <span>Verify Identity</span>
                </button>
            </form>
            
            <div class="mt-6 pt-4 border-t border-[#30363d] text-center text-xs">
                <a href="logout.php" class="text-slate-400 hover:text-white transition flex items-center justify-center gap-1.5 font-sans">
                    <i class="fa-solid fa-arrow-left text-xs"></i>
                    <span>Cancel and return to sign in</span>
                </a>
            </div>
        </div>

        <!-- Footer Compliance Readout -->
        <div class="mt-4 text-center text-[10px] text-slate-500 font-mono uppercase tracking-wider">
            RFC 6238 TOTP Standard &bull; Zero-Trust Session Intercept
        </div>
    </div>

    <!-- Rolling 30-Second TOTP Window Sync -->
    <script>
        function updateTotpProgress() {
            var now = new Date();
            var seconds = now.getSeconds();
            var remaining = 30 - (seconds % 30);
            var percentage = (remaining / 30) * 100;
            
            var bar = document.getElementById('totpProgressBar');
            var label = document.getElementById('totpSecLabel');
            if (bar) bar.style.width = percentage + '%';
            if (label) label.innerText = remaining + 's window';
        }
        setInterval(updateTotpProgress, 1000);
        updateTotpProgress();
    </script>
</body>
</html>
