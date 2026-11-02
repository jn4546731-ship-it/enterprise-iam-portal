<?php
session_start();
require_once 'db.php';
require_once 'mfa_helper.php';

// Ensure the user is authenticated before configuring MFA
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$user_id = (int) $_SESSION['user_id'];
$message = '';

// Fetch user email for authentic TOTP issuer naming
$user_stmt = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
$user_stmt->bind_param("i", $user_id);
$user_stmt->execute();
$user_data = $user_stmt->get_result()->fetch_assoc();
$user_email = $user_data['email'] ?? 'user@organization.com';

// Handle code verification submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $entered_code = trim($_POST['mfa_code'] ?? '');
    $secret_to_test = trim($_POST['mfa_secret_hidden'] ?? '');

    if (verifyMfaToken($secret_to_test, $entered_code)) {
        // Save secret permanently
        $stmt = $conn->prepare("UPDATE users SET mfa_secret = ? WHERE user_id = ?");
        $stmt->bind_param("si", $secret_to_test, $user_id);
        $stmt->execute();

        // Audit Trail entry
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, 'MFA_ENROLLED', 'User enrolled in Google Authenticator TOTP Multi-Factor Authentication', ?)");
        $log_stmt->bind_param("is", $user_id, $ip_address);
        $log_stmt->execute();

        $message = '<div class="bg-emerald-500/10 border border-emerald-500/40 text-emerald-400 p-3.5 rounded-lg mb-5 text-center text-sm font-semibold flex items-center justify-center"><i class="fa-solid fa-circle-check mr-2"></i> MFA Successfully Enforced! Your account is now protected.</div>';
    } else {
        $message = '<div class="bg-red-500/10 border border-red-500/40 text-red-400 p-3.5 rounded-lg mb-5 text-center text-sm font-semibold flex items-center justify-center"><i class="fa-solid fa-triangle-exclamation mr-2"></i> Verification code invalid. Ensure system clock is synced and retry.</div>';
    }
}

// Generate secret and TOTP URI for offline QR code generation
$current_secret = $_POST['mfa_secret_hidden'] ?? generateMfaSecret();
$issuer = "Enterprise IAM";
$account = $user_email;
$otpauth_uri = "otpauth://totp/" . rawurlencode($issuer) . ":" . rawurlencode($account) . "?secret=" . $current_secret . "&issuer=" . rawurlencode($issuer);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MFA Enrollment - Enterprise SOC Portal</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <script src="assets/js/qrcode.min.js"></script>
</head>
<body class="bg-slate-900 text-slate-300 flex items-center justify-center min-h-screen px-4 py-8">

    <div class="bg-slate-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-slate-700">
        <div class="text-center mb-6">
            <div class="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-500/10 border border-blue-500/20 mb-3">
                <i class="fa-solid fa-mobile-screen-button text-3xl text-blue-500"></i>
            </div>
            <h2 class="text-2xl font-bold text-white tracking-wide">MFA Configuration</h2>
            <p class="text-slate-400 text-xs mt-1">Google Authenticator TOTP Zero-Trust Enrollment (100% Offline)</p>
        </div>
        
        <?php echo $message; ?>

        <div class="text-center mb-6 bg-slate-900/60 p-5 rounded-xl border border-slate-700/60">
            <p class="text-xs text-slate-300 mb-3 font-medium">1. Scan this QR code using Google Authenticator:</p>
            <div class="inline-block bg-white p-2.5 rounded-lg shadow-md">
                <div id="qrcode" class="w-44 h-44 mx-auto flex items-center justify-center"></div>
            </div>
            <p class="text-[11px] text-slate-400 mt-3">Manual Key: <span class="font-mono text-emerald-400 font-bold bg-slate-800 px-2 py-0.5 rounded border border-slate-700 select-all"><?php echo $current_secret; ?></span></p>
        </div>

        <script>
            // 100% Air-Gapped Local QR Code Generation
            window.addEventListener('DOMContentLoaded', function() {
                var qrContainer = document.getElementById("qrcode");
                if (qrContainer && typeof QRCode !== 'undefined') {
                    new QRCode(qrContainer, {
                        text: <?php echo json_encode($otpauth_uri); ?>,
                        width: 176,
                        height: 176,
                        colorDark: "#0f172a",
                        colorLight: "#ffffff",
                        correctLevel: QRCode.CorrectLevel.M
                    });
                }
            });
        </script>

        <form method="POST" action="">
            <input type="hidden" name="mfa_secret_hidden" value="<?php echo $current_secret; ?>">
            <div class="mb-5">
                <label class="block text-xs font-medium text-slate-300 mb-1.5">2. Enter 6-digit confirmation code</label>
                <input type="text" name="mfa_code" maxlength="6" 
                       class="w-full px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none text-center tracking-[0.3em] font-mono text-xl text-white placeholder:text-slate-600" 
                       placeholder="000000" required autocomplete="off">
            </div>
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2.5 rounded-lg transition duration-200 shadow-lg shadow-blue-900/40 flex justify-center items-center">
                <i class="fa-solid fa-shield-check mr-2"></i> Verify & Enable MFA
            </button>
        </form>

        <div class="mt-5 text-center border-t border-slate-700/60 pt-4">
            <a href="dashboard.php" class="text-xs text-slate-400 hover:text-white transition flex items-center justify-center">
                <i class="fa-solid fa-arrow-left mr-1.5"></i> Return to Command Center
            </a>
        </div>
    </div>

</body>
</html>
