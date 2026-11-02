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
    <title>IAM Portal - Secure Login</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-900 flex items-center justify-center min-h-screen px-4">

    <div class="bg-slate-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-slate-700">
        <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 mb-3">
                <i class="fa-solid fa-shield-halved text-3xl text-blue-500"></i>
            </div>
            <h2 class="text-2xl font-bold text-white tracking-wide">IAM Secure Portal</h2>
            <p class="text-slate-400 mt-1 text-sm">Enterprise Zero-Trust Authentication Gateway</p>
            <div class="mt-2 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
                <i class="fa-solid fa-lock mr-1 text-[9px]"></i> TLS 1.3 ENCRYPTED &bull; iam.secure-defense.internal
            </div>
        </div>

        <?php if ($error): ?>
            <div class="bg-red-500/10 border border-red-500/50 text-red-400 p-3.5 rounded-lg mb-6 text-sm flex items-start">
                <i class="fa-solid fa-triangle-exclamation mr-2.5 mt-0.5 flex-shrink-0 text-red-500"></i>
                <div><?php echo htmlspecialchars($error); ?></div>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <div class="mb-5">
                <label class="block text-sm font-medium text-slate-300 mb-2">Corporate Email Address</label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                        <i class="fa-solid fa-envelope text-slate-500"></i>
                    </div>
                    <input type="email" name="email" class="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none text-white transition-colors placeholder:text-slate-500" placeholder="admin@organization.com" required>
                </div>
            </div>
            
            <div class="mb-6">
                <label class="block text-sm font-medium text-slate-300 mb-2">Password</label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                        <i class="fa-solid fa-lock text-slate-500"></i>
                    </div>
                    <input type="password" name="password" class="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none text-white transition-colors placeholder:text-slate-500" placeholder="••••••••" required>
                </div>
            </div>

            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 rounded-lg focus:ring-4 focus:ring-blue-500/50 transition duration-200 flex justify-center items-center shadow-lg shadow-blue-900/30">
                <span>Authenticate Identity</span>
                <i class="fa-solid fa-arrow-right-to-bracket ml-2"></i>
            </button>
        </form>
        
        <div class="mt-6 text-center border-t border-slate-700/60 pt-4">
            <p class="text-xs text-slate-500">Protected by Zero-Trust IAM & AI Sentinel Anomaly Engine</p>
        </div>
    </div>

</body>
</html>
