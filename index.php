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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Zero-Trust IAM - Cyber Access Terminal</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay min-h-screen flex items-center justify-center px-4 relative overflow-x-hidden text-slate-300">

    <!-- Top Telemetry Status Ticker -->
    <div class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 py-2.5 bg-slate-950/80 border-b border-cyan-500/20 backdrop-blur-md text-[11px] font-tech text-cyan-400/90">
        <div class="flex items-center space-x-3">
            <span class="inline-flex h-2 w-2 rounded-full bg-cyan-400 cyber-beacon"></span>
            <span class="tracking-widest uppercase font-bold text-white">ZERO-TRUST ACCESS GATEWAY // NODE-01</span>
        </div>
        <div class="hidden sm:flex items-center space-x-6 text-slate-400">
            <span>DEFENSE: <strong class="text-emerald-400">AI SENTINEL ONLINE</strong></span>
            <span>CIPHER: <strong class="text-cyan-300">TLS 1.3 / AES-256</strong></span>
            <span>INGRESS: <strong class="text-purple-400"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'); ?></strong></span>
        </div>
    </div>

    <!-- Main High-Tech Cyber Terminal Card -->
    <div class="relative z-10 w-full max-w-md my-12">
        <div class="cyber-card cyber-brackets rounded-2xl p-7 sm:p-9 shadow-2xl relative overflow-hidden border border-cyan-500/30">
            
            <!-- Laser Scan Line -->
            <div class="cyber-laser-beam"></div>

            <!-- Terminal Header & Holographic Biometric Emblem -->
            <div class="text-center mb-8 relative">
                <div class="relative inline-flex items-center justify-center w-20 h-20 mb-3">
                    <!-- Rotating Sci-Fi Cyber Rings -->
                    <div class="absolute inset-0 rounded-full border border-dashed border-cyan-500/50 cyber-radar-spin"></div>
                    <div class="absolute inset-1.5 rounded-full border border-purple-500/40 cyber-radar-reverse"></div>
                    <div class="w-14 h-14 rounded-full bg-cyan-950/70 border border-cyan-400/60 flex items-center justify-center text-cyan-400 glow-cyan-sm shadow-inner">
                        <i class="fa-solid fa-shield-halved text-2xl text-cyan-300"></i>
                    </div>
                </div>

                <h1 class="font-orbitron text-xl sm:text-2xl font-extrabold text-white tracking-wider glow-text-cyan mb-1">
                    ENTERPRISE <span class="text-cyan-400">SOC IAM</span>
                </h1>
                <p class="font-tech text-xs text-cyan-300/80 tracking-widest uppercase">
                    Zero-Trust Perimeter &bull; Multi-Factor Intercept
                </p>

                <!-- Domain Security Badge -->
                <div class="mt-3 inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-[11px] font-tech text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 shadow-sm">
                    <i class="fa-solid fa-lock text-[10px] text-emerald-400"></i>
                    <span class="tracking-wide font-bold">iam.secure-defense.internal</span>
                </div>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-950/40 border border-red-500/60 text-red-300 p-3.5 rounded-xl mb-6 text-xs font-tech flex items-start glow-red shadow-lg animate-pulse">
                    <i class="fa-solid fa-triangle-exclamation mr-2.5 mt-0.5 text-base text-red-400 flex-shrink-0"></i>
                    <div>
                        <strong class="text-red-400 uppercase font-bold tracking-wider">Access Violation:</strong>
                        <p class="mt-0.5"><?php echo htmlspecialchars($error); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Login Credentials Form -->
            <form method="POST" action="" class="space-y-5">
                <div>
                    <label class="block font-tech text-xs text-cyan-300 uppercase tracking-wider mb-2 flex items-center justify-between">
                        <span>Identity Identifier (Email)</span>
                        <span class="text-[10px] text-slate-500 font-mono">// PRINCIPAL</span>
                    </label>
                    <div class="relative group">
                        <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500 group-focus-within:text-cyan-400 transition">
                            <i class="fa-solid fa-fingerprint text-base"></i>
                        </div>
                        <input type="email" name="email" class="cyber-input w-full pl-11 pr-4 py-3 rounded-xl text-sm placeholder:text-slate-600 focus:ring-0" placeholder="admin@organization.com" required autocomplete="username">
                    </div>
                </div>
                
                <div>
                    <label class="block font-tech text-xs text-cyan-300 uppercase tracking-wider mb-2 flex items-center justify-between">
                        <span>Cryptographic Passphrase</span>
                        <span class="text-[10px] text-slate-500 font-mono">// SECRET KEY</span>
                    </label>
                    <div class="relative group">
                        <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500 group-focus-within:text-cyan-400 transition">
                            <i class="fa-solid fa-key text-base"></i>
                        </div>
                        <input type="password" name="password" class="cyber-input w-full pl-11 pr-4 py-3 rounded-xl text-sm placeholder:text-slate-600 focus:ring-0" placeholder="••••••••••••" required autocomplete="current-password">
                    </div>
                </div>

                <!-- Submit Button -->
                <button type="submit" class="cyber-btn w-full py-3.5 px-4 bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs tracking-widest rounded-xl transition shadow-lg glow-cyan flex items-center justify-center space-x-2 group mt-2">
                    <span>AUTHENTICATE IDENTITY</span>
                    <i class="fa-solid fa-arrow-right-to-bracket text-sm group-hover:translate-x-1 transition"></i>
                </button>
            </form>
            
            <!-- Terminal Diagnostic Readout Footer -->
            <div class="mt-8 pt-4 border-t border-slate-800/80 text-center font-tech text-[11px] text-slate-500 space-y-1">
                <p class="flex items-center justify-center space-x-2">
                    <span class="text-cyan-400">&gt;</span>
                    <span>Protected by AI Sentinel Behavioral Telemetry</span>
                </p>
                <p class="text-[10px] text-slate-600">UNAUTHORIZED ACCESS STRICTLY MONITORED &bull; NIST SP 800-207</p>
            </div>
        </div>
    </div>

</body>
</html>
