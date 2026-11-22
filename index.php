<?php
session_start();
require_once 'db.php';

if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

$error = '';
if (isset($_GET['error']) && $_GET['error'] === 'suspended') {
    $error = "Session Terminated: Your account has been suspended by the Security Operations Center.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user && password_verify($password, $user['password_hash'])) {
        // Check if account has been suspended (RBAC Zero-Trust Enforcement)
        if (isset($user['is_active']) && (int) $user['is_active'] === 0) {
            $error = "Access Denied: Account UID-" . str_pad($user['user_id'], 4, '0', STR_PAD_LEFT) . " has been SUSPENDED by the SOC Administrator due to policy violation or detected anomaly.";
            
            // Log suspended access attempt for AI Sentinel telemetry
            $action_type = "SUSPENDED_LOGIN_ATTEMPT";
            $action_desc = "Blocked authentication attempt on suspended account: " . $email;
            $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
            $log_stmt->bind_param("isss", $user['user_id'], $action_type, $action_desc, $ip_address);
            $log_stmt->execute();
        } else {
            // Account is active; evaluate MFA requirement
            if (!empty($user['mfa_secret'])) {
                // User has MFA enabled, hold in pending state (Session Intercept)
                $_SESSION['pending_user_id'] = $user['user_id'];
                header("Location: mfa_verify.php");
                exit();
            } else {
                // No MFA configured, grant session and record audit
                $_SESSION['user_id'] = $user['user_id'];
                $_SESSION['fresh_login'] = true; // Trigger Animated Cybersecurity Welcome HUD
                
                $action_type = "LOGIN";
                $action_desc = "User authenticated successfully (Standard)";
                
                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $_SESSION['user_id'], $action_type, $action_desc, $ip_address);
                $log_stmt->execute();
                
                header("Location: dashboard.php");
                exit();
            }
        }
    } else {
        $error = "Invalid enterprise credentials.";
        
        // Log failed login attempt for AI Sentinel Brute-Force & Spray analysis
        $action_type = "LOGIN_FAIL";
        $target_uid = $user ? (int) $user['user_id'] : null;
        $action_desc = $user 
            ? "Failed password attempt for user: {$email}" 
            : "Failed password attempt for non-existent identity: {$email}";
        
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $target_uid, $action_type, $action_desc, $ip_address);
        $log_stmt->execute();
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark">
    <title>Enterprise Zero-Trust IAM - Cyber Access Terminal</title>
    <script src="assets/js/tailwind.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        surface: {
                            DEFAULT: '#0f131c',
                            dim: '#0f131c',
                            bright: '#353942',
                            lowest: '#0a0e16',
                            low: '#181c24',
                            container: '#1c2029',
                            high: '#262a34',
                            highest: '#31353f',
                        },
                        primary: {
                            DEFAULT: '#38bdf8',
                            dim: '#0284c7',
                            container: '#004d69',
                        },
                        cyber: {
                            neon: '#00f0ff',
                            success: '#10b981',
                            warning: '#f59e0b',
                            critical: '#ef4444',
                        }
                    },
                    fontFamily: {
                        sans: ['Geist', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
                        mono: ['JetBrains Mono', 'Share Tech Mono', 'monospace'],
                    },
                    borderRadius: {
                        DEFAULT: '4px',
                        md: '6px',
                        lg: '8px',
                        xl: '12px',
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
            <div class="w-6 h-6 rounded-md bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-400">
                <i class="fa-solid fa-shield-halved text-xs"></i>
            </div>
            <span class="font-bold text-white tracking-tight">SECURE·DEFENSE</span>
            <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold">ZERO-TRUST</span>
        </div>
        <div class="hidden sm:flex items-center space-x-4 text-xs font-mono">
            <span class="flex items-center"><span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> AI Sentinel: <strong class="text-emerald-400 ml-1">ONLINE</strong></span>
            <span class="text-slate-600">|</span>
            <span>Cipher: <strong class="text-sky-300">TLS 1.3 / AES-256</strong></span>
            <span class="text-slate-600">|</span>
            <span class="text-slate-400">Host: <strong class="text-white">iam.secure-defense.internal</strong></span>
        </div>
    </header>

    <!-- Main Okta-Grade Sign-In Card -->
    <div class="relative z-10 w-full max-w-md my-auto pt-8">
        <div class="bg-[#10141f] rounded-xl p-8 sm:p-9 shadow-2xl border border-[#1c2233]">
            
            <!-- Company / Tenant Header -->
            <div class="text-center mb-7">
                <div class="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-sky-500/10 border border-sky-500/30 text-sky-400 mb-3 shadow-inner">
                    <i class="fa-solid fa-shield-halved text-2xl"></i>
                </div>
                <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight font-sans">
                    Sign in to SecureDefense
                </h1>
                <p class="text-xs text-slate-400 mt-1 font-sans">
                    Single Sign-On &bull; Zero-Trust Identity Gateway
                </p>
                <div class="mt-2.5 inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
                    <i class="fa-solid fa-lock text-[10px]"></i>
                    <span>iam.secure-defense.internal</span>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-500/10 border border-red-500/30 text-red-300 p-3.5 rounded-lg mb-6 text-xs flex items-start">
                    <i class="fa-solid fa-circle-exclamation mr-2.5 mt-0.5 text-base text-red-400 flex-shrink-0"></i>
                    <div>
                        <strong class="text-red-400 font-semibold">Authentication Alert:</strong>
                        <p class="mt-0.5 text-slate-300"><?php echo htmlspecialchars($error); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Sign In Form -->
            <form method="POST" action="" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                        <span>Email or Username</span>
                        <span class="text-[10px] text-slate-500 font-mono">PRINCIPAL</span>
                    </label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                            <i class="fa-regular fa-envelope text-sm"></i>
                        </div>
                        <input type="email" id="loginEmail" name="email" class="w-full pl-10 pr-4 py-2.5 rounded-md text-sm bg-[#090d16] border border-[#1c2233] text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-sky-500/30 focus:border-sky-500 transition" placeholder="admin@organization.com" required autocomplete="username">
                    </div>
                </div>
                
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                        <span>Password</span>
                        <span class="text-[10px] text-slate-500 font-mono">CREDENTIAL</span>
                    </label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                            <i class="fa-solid fa-lock text-sm"></i>
                        </div>
                        <input type="password" id="loginPass" name="password" class="w-full pl-10 pr-4 py-2.5 rounded-md text-sm bg-[#090d16] border border-[#1c2233] text-white placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-sky-500/30 focus:border-sky-500 transition" placeholder="••••••••••••" required autocomplete="current-password">
                    </div>
                </div>

                <!-- Submit Button -->
                <button type="submit" class="w-full py-2.5 px-4 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-sm rounded-md transition shadow-md flex items-center justify-center space-x-2 mt-2">
                    <span>Sign In</span>
                    <i class="fa-solid fa-arrow-right text-xs"></i>
                </button>
            </form>
            
            <!-- Quick Demo Credentials Selector for Presentation / Defense -->
            <div class="mt-6 pt-4 border-t border-[#1c2233]">
                <p class="text-[11px] font-semibold text-slate-400 mb-2 flex items-center justify-between">
                    <span>Pre-Configured Identities:</span>
                    <span class="text-[10px] font-mono text-sky-400">DEMO READY</span>
                </p>
                <div class="grid grid-cols-3 gap-1.5 text-[11px] font-mono">
                    <button type="button" onclick="setDemo('admin@organization.com', 'admin123')" class="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-[#1c2233] text-center transition truncate" title="Super Admin UID-1 (Tier 3)">
                        <span class="text-purple-400 font-bold">Tier 3</span> Admin
                    </button>
                    <button type="button" onclick="setDemo('auditor@organization.com', 'auditor123')" class="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-[#1c2233] text-center transition truncate" title="Auditor UID-2 (Tier 2)">
                        <span class="text-sky-400 font-bold">Tier 2</span> Audit
                    </button>
                    <button type="button" onclick="setDemo('staff@organization.com', 'staff123')" class="p-1.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-[#1c2233] text-center transition truncate" title="Staff UID-3 (Tier 1)">
                        <span class="text-amber-400 font-bold">Tier 1</span> Staff
                    </button>
                </div>
            </div>

            <!-- Footer Compliance Readout -->
            <div class="mt-5 text-center text-[10px] text-slate-500 font-mono">
                NIST SP 800-207 ZERO-TRUST &bull; PROTECTED BY AI SENTINEL
            </div>
        </div>
    </div>

    <script>
        function setDemo(email, pass) {
            document.getElementById('loginEmail').value = email;
            document.getElementById('loginPass').value = pass;
        }
    </script>

</body>
</html>
