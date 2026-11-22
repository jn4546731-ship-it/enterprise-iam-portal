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
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>MFA Zero-Trust Enrollment - Enterprise SOC</title>
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
    <script src="assets/js/qrcode.min.js"></script>
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="bg-[#090d16] min-h-screen flex flex-col items-center justify-center px-4 py-12 relative text-slate-300">

    <!-- Top Telemetry Status Header -->
    <header class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 py-2.5 bg-[#0c101a]/90 border-b border-[#1c2233] backdrop-blur-md text-xs font-sans text-slate-400">
        <div class="flex items-center space-x-2.5">
            <div class="w-6 h-6 rounded-md bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <i class="fa-solid fa-shield-halved text-xs"></i>
            </div>
            <span class="font-bold text-white tracking-tight">SECURE·DEFENSE</span>
            <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">MFA ENROLLMENT</span>
        </div>
        <div class="hidden sm:flex items-center space-x-4 text-xs font-mono">
            <span>Algorithm: <strong class="text-sky-300">HMAC-SHA1 / RFC 6238</strong></span>
            <span class="text-slate-600">|</span>
            <span>Storage: <strong class="text-emerald-400">ENCRYPTED BASE32</strong></span>
            <span class="text-slate-600">|</span>
            <span>Air-Gap: <strong class="text-slate-300">100% OFFLINE</strong></span>
        </div>
    </header>

    <!-- Main Okta-Grade MFA Setup Card -->
    <div class="relative z-10 w-full max-w-lg my-auto pt-8">
        <div class="bg-[#10141f] rounded-xl p-8 sm:p-9 shadow-2xl border border-[#1c2233]">
            
            <div class="text-center mb-6">
                <div class="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 mb-3 shadow-inner">
                    <i class="fa-solid fa-mobile-screen-button text-2xl"></i>
                </div>
                <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight font-sans">
                    Configure Authenticator App
                </h1>
                <p class="text-xs text-slate-400 mt-1 font-sans">
                    Pair Google Authenticator or Okta Verify to enforce Multi-Factor Authentication
                </p>
            </div>
            
            <?php echo $message; ?>

            <!-- Step 1: QR Code Scan -->
            <div class="text-center mb-6 bg-[#090d16] p-5 rounded-lg border border-[#1c2233]">
                <div class="flex items-center justify-between mb-3 text-xs font-sans">
                    <span class="text-sky-400 font-semibold flex items-center">
                        <span class="w-5 h-5 rounded-full bg-sky-500/20 border border-sky-500/40 flex items-center justify-center mr-2 text-[10px] text-sky-300 font-bold">1</span>
                        Scan QR Code with Authenticator
                    </span>
                    <span class="text-emerald-400 text-[10px] font-mono"><i class="fa-solid fa-check mr-1"></i> Client-Side SVG</span>
                </div>

                <div class="inline-block p-3.5 bg-white rounded-lg shadow-xl border border-slate-300">
                    <div id="qrcode" class="w-44 h-44 mx-auto flex items-center justify-center"></div>
                </div>

                <!-- Secret Key Display with Copy Trigger -->
                <div class="mt-4 pt-3 border-t border-[#1c2233] flex flex-col sm:flex-row items-center justify-between gap-2 text-xs">
                    <span class="text-slate-400 font-sans">Manual Entry Key:</span>
                    <div class="flex items-center space-x-2">
                        <span id="secretKeyText" class="text-emerald-400 font-bold bg-[#10141f] px-3 py-1 rounded border border-[#1c2233] select-all tracking-widest text-xs font-mono">
                            <?php echo $current_secret; ?>
                        </span>
                        <button type="button" onclick="copySecretKey()" class="text-xs bg-slate-800 hover:bg-slate-700 text-sky-400 px-2.5 py-1 rounded border border-[#1c2233] transition" title="Copy to Clipboard">
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
                        alert('Secret Key copied to clipboard: ' + key);
                    });
                }
            </script>

            <!-- Step 2: Verification Form -->
            <form method="POST" action="" class="space-y-4">
                <input type="hidden" name="mfa_secret_hidden" value="<?php echo $current_secret; ?>">
                
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center">
                        <span class="w-5 h-5 rounded-full bg-sky-500/20 border border-sky-500/40 flex items-center justify-center mr-2 text-[10px] text-sky-300 font-bold">2</span>
                        Enter 6-digit confirmation code
                    </label>
                    <input type="text" name="mfa_code" maxlength="6" 
                           class="w-full px-4 py-3 rounded-md text-center tracking-[0.45em] font-mono font-bold text-xl bg-[#090d16] border border-[#1c2233] text-sky-400 placeholder:text-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-500/30 focus:border-sky-500 transition" 
                           placeholder="000000" required autocomplete="off" inputmode="numeric">
                </div>

                <button type="submit" class="w-full py-2.5 px-4 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm rounded-md transition shadow-md flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-shield-check text-sm"></i>
                    <span>Confirm & Activate 2FA</span>
                </button>
            </form>

            <div class="mt-6 pt-4 border-t border-[#1c2233] text-center text-xs">
                <a href="dashboard.php" class="text-slate-400 hover:text-white transition flex items-center justify-center space-x-1.5 font-sans">
                    <i class="fa-solid fa-arrow-left text-xs"></i>
                    <span>Return to User Directory</span>
                </a>
            </div>
        </div>
    </div>

</body>
</html>
