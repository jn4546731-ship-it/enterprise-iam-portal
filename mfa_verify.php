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
    <title>Two-Factor Authentication - IAM Portal</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-slate-900 flex items-center justify-center min-h-screen px-4">
    <div class="bg-slate-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-slate-700">
        <div class="text-center mb-8">
            <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 mb-3">
                <i class="fa-solid fa-shield-halved text-3xl text-blue-500"></i>
            </div>
            <h2 class="text-2xl font-bold text-white tracking-wide">Two-Factor Authentication</h2>
            <p class="text-slate-400 mt-2 text-sm">Enter the dynamic 6-digit TOTP code from your Google Authenticator app.</p>
            <div class="mt-2 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20">
                <i class="fa-solid fa-lock mr-1 text-[9px]"></i> TLS 1.3 SECURED &bull; iam.secure-defense.internal
            </div>
        </div>

        <?php if ($error): ?>
            <div class="bg-red-500/10 border border-red-500/50 text-red-400 p-3.5 rounded-lg mb-6 text-sm flex items-start">
                <i class="fa-solid fa-triangle-exclamation mr-2.5 mt-0.5 flex-shrink-0 text-red-500"></i>
                <div><?php echo htmlspecialchars($error); ?></div>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <div class="mb-6">
                <input type="text" name="mfa_code" maxlength="6" autofocus 
                       class="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none text-white text-center tracking-[0.5em] font-mono text-2xl" 
                       placeholder="••••••" required autocomplete="off">
            </div>
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 rounded-lg transition duration-200 shadow-lg shadow-blue-900/30 flex justify-center items-center">
                <i class="fa-solid fa-fingerprint mr-2"></i>
                <span>Verify Identity Challenge</span>
            </button>
        </form>
        
        <div class="mt-6 text-center border-t border-slate-700/60 pt-4">
            <a href="logout.php" class="text-sm text-slate-500 hover:text-white transition">
                <i class="fa-solid fa-arrow-left mr-1"></i> Cancel and Return to Login
            </a>
        </div>
    </div>
</body>
</html>
