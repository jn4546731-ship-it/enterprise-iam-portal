<?php
/**
 * Enterprise IAM Portal - Authentication & Multi-Factor (MFA) Configuration
 * Standard RFC 6238 TOTP Authenticator Enrollment (Google Authenticator, Okta Verify, etc.)
 * 100% Air-Gapped client-side QR generation and server-side cryptographic verification.
 */

session_start();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/mfa_helper.php';

// Ensure the user is authenticated before configuring MFA
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$current_user_id = (int) $_SESSION['user_id'];
$message = '';

// Fetch current user details with clearance and role
$stmt = $conn->prepare("
    SELECT u.user_id, u.first_name, u.last_name, u.email, u.department, u.job_title, 
           u.role, u.security_clearance, u.is_active, u.role_id, u.mfa_secret,
           COALESCE(r.role_name, 'Employee') AS role_table_name
    FROM users u
    LEFT JOIN roles r ON u.role_id = r.role_id
    WHERE u.user_id = ?
");
$stmt->bind_param("i", $current_user_id);
$stmt->execute();
$user_res = $stmt->get_result();
$user = $user_res->fetch_assoc();

if (!$user || (isset($user['is_active']) && (int) $user['is_active'] === 0)) {
    session_unset();
    session_destroy();
    header("Location: index.php?error=suspended");
    exit();
}

// User attributes
$user_email = $user['email'];
$user_name = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? ''));
if (empty($user_name)) {
    $user_name = explode('@', $user_email)[0];
}

$user_dept = !empty($user['department']) ? $user['department'] : 'General Operations';
$user_title = !empty($user['job_title']) ? $user['job_title'] : 'Staff Analyst';
$user_role = !empty($user['role']) ? $user['role'] : ($user['role_table_name'] ?? 'Staff');
$user_clearance = !empty($user['security_clearance']) ? $user['security_clearance'] : 'Tier 1';
$has_mfa = !empty($user['mfa_secret']);

// Handle code verification submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mfa_code'])) {
    $entered_code = trim($_POST['mfa_code'] ?? '');
    $secret_to_test = trim($_POST['mfa_secret_hidden'] ?? '');

    if (verifyMfaToken($secret_to_test, $entered_code)) {
        // Save secret permanently
        $upd_stmt = $conn->prepare("UPDATE users SET mfa_secret = ? WHERE user_id = ?");
        $upd_stmt->bind_param("si", $secret_to_test, $current_user_id);
        $upd_stmt->execute();

        // Audit Trail entry
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, 'MFA_ENROLLED', 'User enrolled in Google Authenticator TOTP Multi-Factor Authentication', ?)");
        $log_stmt->bind_param("is", $current_user_id, $ip_address);
        $log_stmt->execute();

        $user['mfa_secret'] = $secret_to_test;
        $has_mfa = true;

        $message = '<div class="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono mb-6 flex items-center gap-3"><i class="fa-solid fa-circle-check text-base text-emerald-400 shrink-0"></i> <div><strong class="text-white">MFA SUCCESSFULLY ACTIVATED:</strong> Your identity is now enrolled in RFC 6238 TOTP two-step verification.</div></div>';
    } else {
        $message = '<div class="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6 flex items-center gap-3"><i class="fa-solid fa-triangle-exclamation text-base text-red-400 shrink-0"></i> <div><strong class="text-white">VERIFICATION FAILED:</strong> Invalid 6-digit confirmation code. Check your device clock and retry.</div></div>';
    }
}

// Generate secret and TOTP URI for offline QR code generation
$current_secret = $_POST['mfa_secret_hidden'] ?? ($user['mfa_secret'] ?: generateMfaSecret());
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
    <title>Authentication &amp; MFA Configuration &mdash; Enterprise IAM</title>
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
    <script src="assets/js/qrcode.min.js"></script>
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="bg-[#0d1117] font-sans text-[#e6edf3] antialiased selection:bg-[#2f81f7] selection:text-white min-h-screen">

    <!-- ========================================================================= -->
    <!-- LEFT FIXED NAVIGATION SIDEBAR                                             -->
    <!-- ========================================================================= -->
    <aside id="appSidebar" class="fixed left-0 top-0 h-screen w-64 bg-[#161b22] border-r border-[#30363d] z-50 flex flex-col justify-between shadow-xl transition-transform duration-300">
        <div class="flex flex-col h-full overflow-y-auto custom-scrollbar">
            <!-- Brand Header -->
            <div class="h-16 flex items-center gap-3 px-5 bg-[#0d1117] border-b border-[#30363d]">
                <div class="w-8 h-8 rounded-md bg-[#2f81f7]/15 border border-[#2f81f7]/30 flex items-center justify-center text-[#2f81f7] shrink-0">
                    <i class="fa-solid fa-shield-halved text-base"></i>
                </div>
                <div class="flex flex-col min-w-0">
                    <span class="text-sm text-white font-semibold tracking-tight truncate">Enterprise IAM</span>
                    <span class="text-[10px] font-mono text-slate-400 tracking-wider uppercase font-medium">Identity Governance</span>
                </div>
            </div>

            <!-- Directory Sync Status Chip -->
            <div class="px-4 py-3">
                <div class="flex items-center gap-2 px-3 py-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span class="font-mono text-[10px] text-slate-300 uppercase font-medium truncate">Directory Sync: Connected</span>
                </div>
            </div>

            <!-- Categorized Navigation -->
            <nav class="flex-1 px-3 py-2 space-y-1 text-xs font-sans">
                <a href="dashboard.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-table-cells-large text-sm w-4 text-center"></i>
                    <span>Overview</span>
                </a>

                <!-- Authentication & MFA (Active Page) -->
                <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#21262d] border border-[#30363d] text-white shadow-xs font-medium">
                    <i class="fa-solid fa-fingerprint text-sm text-[#2f81f7] w-4 text-center"></i>
                    <span>Authentication &amp; MFA</span>
                </a>

                <a href="dashboard.php#usersDirectory" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-users text-sm w-4 text-center"></i>
                    <span>Users &amp; Directory</span>
                </a>

                <a href="dashboard.php#usersDirectory" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-user-shield text-sm w-4 text-center"></i>
                    <span>Roles &amp; Permissions (RBAC)</span>
                </a>

                <a href="vault.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-lock text-sm w-4 text-center"></i>
                    <span>Access Policies</span>
                </a>

                <a href="audit_report.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-list-check text-sm w-4 text-center"></i>
                    <span>Audit Logs</span>
                </a>

                <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-key text-sm w-4 text-center"></i>
                    <span>Active Sessions</span>
                </a>

                <a href="dashboard.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-gear text-sm w-4 text-center"></i>
                    <span>System Settings</span>
                </a>
            </nav>

            <!-- Sidebar User Card in Footer -->
            <div class="p-3 border-t border-[#30363d] bg-[#0d1117]">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded-full bg-[#2f81f7]/15 text-[#2f81f7] flex items-center justify-center font-bold text-xs shrink-0 border border-[#2f81f7]/30">
                        <?php echo strtoupper(substr($user_email ?? 'A', 0, 1)); ?>
                    </div>
                    <div class="min-w-0">
                        <p class="text-xs font-semibold text-white truncate"><?php echo htmlspecialchars($user_name); ?></p>
                        <p class="text-[10px] font-mono text-emerald-400 truncate flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            <span><?php echo htmlspecialchars($user_role); ?> (<?php echo htmlspecialchars($user_clearance); ?>)</span>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </aside>

    <!-- ========================================================================= -->
    <!-- MAIN WORKSPACE CONTAINER                                                  -->
    <!-- ========================================================================= -->
    <div class="pl-64 flex flex-col min-h-screen">

        <!-- Top Fixed Header -->
        <header class="fixed top-0 right-0 left-64 h-16 bg-[#161b22] border-b border-[#30363d] z-40 flex items-center justify-between px-6 shadow-xs backdrop-blur-md">
            <!-- Search Bar -->
            <div class="relative w-96 max-w-md">
                <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs pointer-events-none"></i>
                <input type="text" placeholder="Search users, authenticators, policies... (Ctrl+K)" class="w-full bg-[#0d1117] border border-[#30363d] rounded-md pl-10 pr-14 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#2f81f7] transition font-sans">
                <kbd class="absolute right-2.5 top-1/2 -translate-y-1/2 font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#161b22] border border-[#30363d] text-slate-400 uppercase">Ctrl+K</kbd>
            </div>

            <!-- Top Header Right Controls -->
            <div class="flex items-center gap-3">
                <div class="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0d1117] border border-[#30363d] text-xs font-mono text-slate-300">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    <span>Environment: Production</span>
                </div>

                <!-- Theme Switcher -->
                <button id="themeToggleBtn" onclick="toggleTheme()" class="p-2 rounded-md bg-[#0d1117] border border-[#30363d] text-slate-300 hover:text-white hover:bg-[#21262d] transition text-xs" title="Toggle Light / Dark mode">
                    <i id="themeToggleIcon" class="fa-solid fa-sun text-amber-400"></i>
                </button>

                <!-- User Profile -->
                <div class="flex items-center gap-3 pl-3 border-l border-[#30363d]">
                    <div class="w-8 h-8 rounded-full bg-[#2f81f7]/20 border border-[#2f81f7]/40 flex items-center justify-center font-bold text-xs text-[#2f81f7] shrink-0">
                        <?php echo strtoupper(substr($user_email ?? 'A', 0, 1)); ?>
                    </div>
                    <div class="hidden md:flex flex-col text-left">
                        <span class="text-xs font-semibold text-white leading-tight whitespace-nowrap"><?php echo htmlspecialchars($user_name); ?></span>
                        <span class="text-[11px] font-mono text-slate-400 whitespace-nowrap"><?php echo htmlspecialchars($user_title); ?></span>
                    </div>
                    <a href="logout.php" class="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-md transition ml-1" title="Sign out of enterprise session">
                        <i class="fa-solid fa-arrow-right-from-bracket text-xs"></i>
                    </a>
                </div>
            </div>
        </header>

        <!-- Main Content Area -->
        <main class="relative pt-20 w-full min-h-screen bg-[#0d1117] px-6 py-6 text-[#e6edf3]">

            <?php if (!empty($message)) echo $message; ?>

            <!-- 1. BREADCRUMB, MAIN HEADING & ACTION BUTTONS -->
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#30363d]">
                <div>
                    <!-- Clean Breadcrumb & Environment Status -->
                    <div class="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1.5">
                        <span>Administration</span>
                        <span class="text-slate-600">/</span>
                        <span class="text-slate-200 font-semibold">Authentication &amp; MFA</span>
                        <span class="text-slate-600 ml-1">&bull;</span>
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Environment: Production
                        </span>
                    </div>
                    <!-- Main Heading & Subtitle -->
                    <h1 class="text-2xl font-bold text-white tracking-tight">Authentication &amp; MFA Configuration</h1>
                    <p class="text-xs text-slate-400 mt-1 max-w-2xl">Configure RFC 6238 TOTP two-step verification using Google Authenticator, Okta Verify, or hardware security keys.</p>
                </div>

                <!-- Practical Action Buttons -->
                <div class="flex flex-wrap items-center gap-2.5 shrink-0">
                    <a href="dashboard.php" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-table-cells-large text-xs text-slate-400"></i>
                        <span>Back to Overview</span>
                    </a>
                    <a href="audit_report.php" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-list-check text-xs text-slate-400"></i>
                        <span>View Audit Logs</span>
                    </a>
                </div>
            </div>

            <!-- 2. KPI / STATUS STRIP -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 my-6">
                <!-- Status Card 1 -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-xs mb-2">
                        <span class="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Enrollment State</span>
                        <?php if ($has_mfa): ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">Enforced</span>
                        <?php else: ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">Pending Setup</span>
                        <?php endif; ?>
                    </div>
                    <div class="text-xl font-bold text-white flex items-center gap-2">
                        <i class="fa-solid <?php echo $has_mfa ? 'fa-shield-check text-emerald-400' : 'fa-clock text-amber-400'; ?> text-base"></i>
                        <span><?php echo $has_mfa ? 'Active & Protected' : 'MFA Not Enrolled'; ?></span>
                    </div>
                    <p class="text-xs text-slate-400 mt-1"><?php echo htmlspecialchars($user_email); ?></p>
                </div>

                <!-- Status Card 2 -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-xs mb-2">
                        <span class="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Authentication Standard</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20 font-bold">RFC 6238</span>
                    </div>
                    <div class="text-xl font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-stopwatch text-sky-400 text-base"></i>
                        <span>TOTP (30s Window)</span>
                    </div>
                    <p class="text-xs text-slate-400 mt-1">HMAC-SHA1 &bull; 6-Digit Time-Based Passcode</p>
                </div>

                <!-- Status Card 3 -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-xs mb-2">
                        <span class="font-semibold text-slate-400 uppercase tracking-wider text-[11px]">Security Clearance</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20 font-bold"><?php echo htmlspecialchars($user_clearance); ?></span>
                    </div>
                    <div class="text-xl font-bold text-white flex items-center gap-2">
                        <i class="fa-solid fa-building-shield text-purple-400 text-base"></i>
                        <span><?php echo htmlspecialchars($user_role); ?></span>
                    </div>
                    <p class="text-xs text-slate-400 mt-1"><?php echo htmlspecialchars($user_dept); ?></p>
                </div>
            </div>

            <!-- 3. MAIN CONFIGURATION CONTAINER -->
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 mb-8">

                <!-- Left Column: Step 1 (QR Code) & Step 2 (Verification Form) (8 cols) -->
                <div class="lg:col-span-8 space-y-6">
                    <div class="rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs p-6">
                        <div class="border-b border-[#30363d] pb-4 mb-6">
                            <h2 class="text-base font-semibold text-white flex items-center gap-2">
                                <i class="fa-solid fa-mobile-screen-button text-[#2f81f7]"></i>
                                <span>Pair Authenticator Device</span>
                            </h2>
                            <p class="text-xs text-slate-400 mt-1">Use Google Authenticator, Okta Verify, Microsoft Authenticator, or 1Password on your mobile device.</p>
                        </div>

                        <?php if ($has_mfa): ?>
                            <div class="p-3.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-300 text-xs mb-6 flex items-center gap-2.5">
                                <i class="fa-solid fa-info-circle text-sky-400 text-sm"></i>
                                <span>MFA is currently configured on this account. Scanning the QR code below will re-bind or rotate your authenticator credential.</span>
                            </div>
                        <?php endif; ?>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
                            <!-- QR Code Preview Box -->
                            <div class="flex flex-col items-center justify-center p-6 rounded-lg bg-[#0d1117] border border-[#30363d]">
                                <div class="p-3 bg-white rounded-lg shadow-md border border-slate-300">
                                    <div id="qrcode" class="w-44 h-44 flex items-center justify-center"></div>
                                </div>
                                <span class="text-[10px] font-mono text-emerald-400 mt-3 flex items-center gap-1.5">
                                    <i class="fa-solid fa-check"></i>
                                    Air-Gapped Local SVG Render
                                </span>
                            </div>

                            <!-- Secret Key & Instructions -->
                            <div class="space-y-4">
                                <div>
                                    <span class="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-1">Step 1 &mdash; Scan or Enter Secret</span>
                                    <p class="text-xs text-slate-400 leading-relaxed">
                                        Scan the QR code with your authenticator camera, or manually input the secret seed below if your camera is unavailable:
                                    </p>
                                </div>

                                <div>
                                    <label class="block text-[11px] font-mono text-slate-400 mb-1">Manual Base32 Seed:</label>
                                    <div class="flex items-center gap-2">
                                        <span id="secretKeyText" class="font-mono text-xs font-bold text-emerald-400 bg-[#0d1117] px-3 py-2 rounded-md border border-[#30363d] select-all tracking-wider flex-1 truncate">
                                            <?php echo htmlspecialchars($current_secret); ?>
                                        </span>
                                        <button type="button" onclick="copySecretKey()" class="px-3 py-2 rounded-md bg-[#21262d] hover:bg-[#30363d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-1.5" title="Copy to clipboard">
                                            <i class="fa-solid fa-copy text-xs"></i>
                                            <span>Copy</span>
                                        </button>
                                    </div>
                                </div>

                                <div class="text-[11px] font-mono text-slate-400 space-y-1 pt-2 border-t border-[#30363d]">
                                    <div>Account: <strong class="text-slate-200"><?php echo htmlspecialchars($user_email); ?></strong></div>
                                    <div>Issuer: <strong class="text-slate-200">Enterprise IAM</strong></div>
                                </div>
                            </div>
                        </div>

                        <!-- Step 2 Verification Form -->
                        <div class="mt-8 pt-6 border-t border-[#30363d]">
                            <form method="POST" action="" class="space-y-4">
                                <input type="hidden" name="mfa_secret_hidden" value="<?php echo htmlspecialchars($current_secret); ?>">

                                <div>
                                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                                        Step 2 &mdash; Enter 6-digit verification code from your device
                                    </label>
                                    <div class="flex items-center gap-3">
                                        <input type="text" name="mfa_code" maxlength="6" 
                                               class="w-48 px-4 py-2.5 rounded-md text-center tracking-[0.35em] font-mono font-bold text-xl bg-[#0d1117] border border-[#30363d] text-[#2f81f7] placeholder:text-slate-700 focus:outline-none focus:border-[#2f81f7] transition" 
                                               placeholder="000000" required autocomplete="off" inputmode="numeric">
                                        <button type="submit" class="px-6 py-2.5 rounded-md bg-[#2f81f7] hover:bg-blue-600 text-white font-semibold text-xs transition shadow-xs flex items-center gap-2">
                                            <i class="fa-solid fa-shield-check text-xs"></i>
                                            <span>Confirm &amp; Enforce MFA</span>
                                        </button>
                                    </div>
                                    <p class="text-[11px] text-slate-500 mt-2">Enter the rolling numeric token shown in your authenticator app to verify proper clock synchronization.</p>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- Right Column: Security Guidance & Policy Checklist (4 cols) -->
                <div class="lg:col-span-4 space-y-6">
                    <!-- Policy Card -->
                    <div class="rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs p-5">
                        <h3 class="text-xs font-semibold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                            <i class="fa-solid fa-clipboard-check text-emerald-400"></i>
                            <span>Access Policy Standards</span>
                        </h3>
                        <ul class="text-xs text-slate-400 space-y-2.5 leading-relaxed font-sans">
                            <li class="flex items-start gap-2">
                                <i class="fa-solid fa-check text-emerald-400 text-xs mt-0.5 shrink-0"></i>
                                <span><strong>NIST SP 800-63B Compliant:</strong> Satisfies Authentication Assurance Level 2 (AAL2).</span>
                            </li>
                            <li class="flex items-start gap-2">
                                <i class="fa-solid fa-check text-emerald-400 text-xs mt-0.5 shrink-0"></i>
                                <span><strong>Zero-Trust Gate:</strong> Mandatory step intercept during login for all sensitive enterprise roles.</span>
                            </li>
                            <li class="flex items-start gap-2">
                                <i class="fa-solid fa-check text-emerald-400 text-xs mt-0.5 shrink-0"></i>
                                <span><strong>Immutable Audit Logging:</strong> Every enrollment and verification is committed with client IP and timestamp.</span>
                            </li>
                        </ul>
                    </div>

                    <!-- Supported Authenticator Apps -->
                    <div class="rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs p-5">
                        <h3 class="text-xs font-semibold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                            <i class="fa-solid fa-shield-halved text-[#2f81f7]"></i>
                            <span>Supported Authenticators</span>
                        </h3>
                        <div class="space-y-2 text-xs text-slate-300">
                            <div class="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#30363d]">
                                <span class="flex items-center gap-2">
                                    <i class="fa-brands fa-google text-slate-400"></i>
                                    Google Authenticator
                                </span>
                                <span class="text-[10px] font-mono text-emerald-400">Verified</span>
                            </div>
                            <div class="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#30363d]">
                                <span class="flex items-center gap-2">
                                    <i class="fa-solid fa-lock text-slate-400"></i>
                                    Okta Verify
                                </span>
                                <span class="text-[10px] font-mono text-emerald-400">Verified</span>
                            </div>
                            <div class="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#30363d]">
                                <span class="flex items-center gap-2">
                                    <i class="fa-brands fa-microsoft text-slate-400"></i>
                                    Microsoft Authenticator
                                </span>
                                <span class="text-[10px] font-mono text-emerald-400">Verified</span>
                            </div>
                            <div class="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#30363d]">
                                <span class="flex items-center gap-2">
                                    <i class="fa-solid fa-key text-slate-400"></i>
                                    Bitwarden / 1Password
                                </span>
                                <span class="text-[10px] font-mono text-emerald-400">Verified</span>
                            </div>
                        </div>
                    </div>
                </div>

            </div>

        </main>
    </div>

    <!-- Client-Side Air-Gapped QR Code Render Script -->
    <script>
        window.addEventListener('DOMContentLoaded', function() {
            var qrContainer = document.getElementById("qrcode");
            if (qrContainer && typeof QRCode !== 'undefined') {
                new QRCode(qrContainer, {
                    text: <?php echo json_encode($otpauth_uri); ?>,
                    width: 176,
                    height: 176,
                    colorDark: "#0d1117",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
            }
        });

        function copySecretKey() {
            const key = document.getElementById('secretKeyText').innerText.trim();
            navigator.clipboard.writeText(key).then(() => {
                alert('Secret Seed copied to clipboard:\n' + key);
            });
        }
    </script>
</body>
</html>
