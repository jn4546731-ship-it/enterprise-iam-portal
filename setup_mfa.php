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
    <title>MFA Zero-Trust Enrollment - Enterprise SOC</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <script src="assets/js/qrcode.min.js"></script>
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay min-h-screen flex items-center justify-center px-4 py-12 relative overflow-x-hidden text-slate-300">

    <!-- Top Telemetry Status Ticker -->
    <div class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 py-2.5 bg-slate-950/80 border-b border-cyan-500/20 backdrop-blur-md text-[11px] font-tech text-cyan-400/90">
        <div class="flex items-center space-x-3">
            <span class="inline-flex h-2 w-2 rounded-full bg-cyan-400 cyber-beacon"></span>
            <span class="tracking-widest uppercase font-bold text-white">IDENTITY ENCLAVE // TOTP REGISTRATION</span>
        </div>
        <div class="hidden sm:flex items-center space-x-6 text-slate-400">
            <span>ALGORITHM: <strong class="text-cyan-300">HMAC-SHA1 / RFC 6238</strong></span>
            <span>STORAGE: <strong class="text-emerald-400">ENCRYPTED BASE32</strong></span>
            <span>AIR-GAP: <strong class="text-purple-400">100% OFFLINE</strong></span>
        </div>
    </div>

    <!-- Main High-Tech MFA Enrollment Card -->
    <div class="relative z-10 w-full max-w-lg my-8">
        <div class="cyber-card cyber-brackets rounded-2xl p-7 sm:p-9 shadow-2xl relative overflow-hidden border border-cyan-500/30">
            
            <!-- Laser Scan Line -->
            <div class="cyber-laser-beam"></div>

            <div class="text-center mb-6 relative">
                <div class="relative inline-flex items-center justify-center w-20 h-20 mb-3">
                    <div class="absolute inset-0 rounded-full border border-dashed border-cyan-500/40 cyber-radar-spin"></div>
                    <div class="absolute inset-1.5 rounded-full border border-emerald-500/40 cyber-radar-reverse"></div>
                    <div class="w-14 h-14 rounded-full bg-cyan-950/70 border border-cyan-400/60 flex items-center justify-center text-cyan-400 glow-cyan-sm shadow-inner">
                        <i class="fa-solid fa-mobile-screen-button text-2xl text-cyan-300"></i>
                    </div>
                </div>

                <h1 class="font-orbitron text-xl sm:text-2xl font-extrabold text-white tracking-wider glow-text-cyan mb-1">
                    MFA <span class="text-cyan-400">ENROLLMENT</span>
                </h1>
                <p class="font-tech text-xs text-slate-400 uppercase tracking-wider">
                    Google Authenticator Zero-Trust Provisioning
                </p>
            </div>
            
            <?php echo $message; ?>

            <!-- Step 1: Holographic QR Code Box -->
            <div class="text-center mb-6 bg-slate-950/70 p-5 rounded-2xl border border-cyan-500/20 relative">
                <div class="flex items-center justify-between mb-3 text-xs font-tech">
                    <span class="text-cyan-300 font-bold flex items-center">
                        <span class="w-5 h-5 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center mr-2 text-[10px]">1</span>
                        SCAN QR MATRIX
                    </span>
                    <span class="text-emerald-400 text-[10px] font-mono"><i class="fa-solid fa-microchip mr-1"></i> CLIENT-SIDE SVG</span>
                </div>

                <!-- QR Code Mount with Glowing Corner Brackets -->
                <div class="inline-block p-3.5 bg-white rounded-xl shadow-2xl relative cyber-brackets border border-cyan-400/60 glow-cyan-sm">
                    <div id="qrcode" class="w-44 h-44 mx-auto flex items-center justify-center"></div>
                </div>

                <!-- Secret Key Display with Copy Trigger -->
                <div class="mt-4 pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-2 font-tech text-xs">
                    <span class="text-slate-400">Manual Key:</span>
                    <div class="flex items-center space-x-2">
                        <span id="secretKeyText" class="text-emerald-400 font-bold bg-slate-900 px-3 py-1 rounded-lg border border-slate-700 select-all tracking-widest text-xs font-mono">
                            <?php echo $current_secret; ?>
                        </span>
                        <button type="button" onclick="copySecretKey()" class="text-xs bg-slate-800 hover:bg-slate-700 text-cyan-300 px-2.5 py-1 rounded-lg border border-slate-700 hover:border-cyan-400 transition" title="Copy to Clipboard">
                            <i class="fa-solid fa-copy"></i>
                        </button>
                    </div>
                </div>
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
                            colorDark: "#050811",
                            colorLight: "#ffffff",
                            correctLevel: QRCode.CorrectLevel.M
                        });
                    }
                });

                function copySecretKey() {
                    const key = document.getElementById('secretKeyText').innerText.trim();
                    navigator.clipboard.writeText(key).then(() => {
                        if (typeof CyberAudio !== 'undefined') CyberAudio.click();
                        alert('Base32 Secret Key copied to clipboard!');
                    });
                }
            </script>

            <!-- Step 2: Verification Form -->
            <form method="POST" action="" class="space-y-5">
                <input type="hidden" name="mfa_secret_hidden" value="<?php echo $current_secret; ?>">
                
                <div>
                    <label class="block font-tech text-xs text-cyan-300 uppercase tracking-widest mb-2 flex items-center">
                        <span class="w-5 h-5 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center mr-2 text-[10px]">2</span>
                        CONFIRM 6-DIGIT CODE
                    </label>
                    <input type="text" name="mfa_code" maxlength="6" 
                           class="cyber-input w-full px-4 py-3 rounded-xl text-center tracking-[0.45em] font-orbitron font-bold text-xl text-cyan-300 placeholder:text-slate-700 focus:ring-0 focus:border-cyan-400" 
                           placeholder="000000" required autocomplete="off" inputmode="numeric">
                </div>

                <button type="submit" class="cyber-btn w-full py-3.5 px-4 bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-bold text-xs tracking-widest rounded-xl transition shadow-lg glow-emerald flex items-center justify-center space-x-2 group">
                    <i class="fa-solid fa-shield-check text-sm group-hover:scale-110 transition"></i>
                    <span>VERIFY & ENFORCE ZERO-TRUST MFA</span>
                </button>
            </form>

            <div class="mt-6 pt-4 border-t border-slate-800/80 text-center font-tech text-xs">
                <a href="dashboard.php" class="text-slate-400 hover:text-cyan-400 transition flex items-center justify-center space-x-1.5">
                    <i class="fa-solid fa-arrow-left text-[11px]"></i>
                    <span>Return to SOC Command Center</span>
                </a>
            </div>
        </div>
    </div>

</body>
</html>
