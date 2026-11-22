<?php
/**
 * Enterprise IAM Portal - Access Policies & Protected Resources (The Vault)
 * Implements Role-Based Access Control (RBAC) & Clearance Tiers (Tier 1, Tier 2, Tier 3)
 * Full audit logging of all authorized and unauthorized access attempts.
 */

session_start();
require_once __DIR__ . '/db.php';

// Enforce Session Authentication
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$current_user_id = (int) $_SESSION['user_id'];

// Fetch current user details with clearance and role
$stmt = $conn->prepare("
    SELECT u.user_id, u.first_name, u.last_name, u.email, u.department, u.job_title, 
           u.role, u.security_clearance, u.is_active, u.role_id,
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

// Calculate numeric clearance tier (Tier 1 = 1, Tier 2 = 2, Tier 3 = 3)
$tier_numeric = 1;
if (stripos($user_clearance, 'Tier 3') !== false || strcasecmp($user_role, 'Admin') === 0 || (int)$user['role_id'] === 1) {
    $tier_numeric = 3;
} elseif (stripos($user_clearance, 'Tier 2') !== false || strcasecmp($user_role, 'Auditor') === 0 || (int)$user['role_id'] === 3) {
    $tier_numeric = 2;
} else {
    $tier_numeric = 1;
}

// Ensure CSRF Token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

$feedback_msg = '';
$client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

// -------------------------------------------------------------
// HANDLE INTERACTIVE VAULT ACTIONS & SIMULATED AUDIT LOGGING
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['vault_action'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 text-base'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $resource_id = $_POST['resource_id'] ?? '';
        $action_requested = $_POST['vault_action']; // 'inspect' or 'download'

        // RBAC Enforcement Rules:
        // PII: Tier 2+
        // Financials: Tier 2+
        // SSH Keys: Tier 3 Only
        $allowed = false;
        $required_tier = 1;
        $res_label = 'Unknown Resource';

        switch ($resource_id) {
            case 'res_pii':
                $res_label = 'Customer PII Database';
                $required_tier = 2;
                $allowed = ($tier_numeric >= 2);
                break;
            case 'res_fin':
                $res_label = 'Q3 Corporate Financials';
                $required_tier = 2;
                $allowed = ($tier_numeric >= 2);
                break;
            case 'res_ssh':
                $res_label = 'Production Server SSH Keys';
                $required_tier = 3;
                $allowed = ($tier_numeric >= 3);
                break;
        }

        if ($allowed) {
            // Authorized Access Event
            $action_type = "VAULT_ACCESS_GRANTED";
            $action_desc = "User {$user_email} ({$user_role} / {$user_clearance}) AUTHORIZED to access '{$res_label}' [Action: {$action_requested}]";
            $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
            $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
            $log->execute();

            if ($action_requested === 'download_ssh') {
                // Serve mock Ed25519 key file
                header('Content-Type: application/x-pem-file');
                header('Content-Disposition: attachment; filename="id_ed25519_prod_cluster.pem"');
                echo "-----BEGIN OPENSSH PRIVATE KEY-----\n";
                echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n";
                echo "QyNTUxOQAAACCE0K/X92Z/lWjRjFj3Jq9N7o01ZLkLm0123456789ABCDEFGHAAAJsAoW\n";
                echo "K2Cg123456789ABCDEFGHAAAAAtzc2gtZWQyNTUxOQAAACCE0K/X92Z/lWjRjFj3Jq9N7o\n";
                echo "01ZLkLm0123456789ABCDEFGHAAAEC6JvG1/mock/production/cluster/admin/key==\n";
                echo "-----END OPENSSH PRIVATE KEY-----\n";
                exit();
            }

            if ($action_requested === 'download_fin_csv') {
                header('Content-Type: text/csv');
                header('Content-Disposition: attachment; filename="Q3_Corporate_Financial_Audit_Report.csv"');
                echo "Account Code,Ledger Category,Q3 Budget,Actual Outlay,Variance,Audit Approval\n";
                echo "ACC-10901,Core Infrastructure Cloud Services,$4500000,$4210900,-$289100,APPROVED_CISO\n";
                echo "ACC-10904,Zero-Trust IAM & Security Tooling,$1200000,$1185000,-$15000,APPROVED_CISO\n";
                echo "ACC-20311,EBITDA Operating Reserve,$14200000,$14200000,$0,VERIFIED_AUDIT\n";
                echo "ACC-30401,Cryptographic HSM Hardware Vaults,$850000,$849200,-$800,APPROVED_AUDIT\n";
                exit();
            }

            $feedback_msg = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-circle-check mr-2 text-base text-emerald-400'></i> <div><strong class='text-white'>ACCESS AUTHORIZED:</strong> Clearance {$user_clearance} validated. Operation logged to immutable audit ledger.</div></div>";
        } else {
            // Unauthorized Access Attempt
            $action_type = "ACCESS_DENIED_UNAUTHORIZED_RESOURCE";
            $action_desc = "UNAUTHORIZED ACCESS ATTEMPT: User {$user_email} ({$user_clearance}) tried to access '{$res_label}' (Requires Tier {$required_tier}+). Action BLOCKED by Zero-Trust RBAC Policy.";
            $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
            $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
            $log->execute();

            $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-ban mr-2 text-base text-red-400'></i> <div><strong class='text-white'>ACCESS DENIED:</strong> Access blocked for <span class='text-red-300 font-bold'>{$res_label}</span>. Current clearance level (<span class='text-amber-400 font-bold'>{$user_clearance}</span>) is insufficient. Security incident recorded.</div></div>";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Access Policies &amp; Protected Resources &mdash; Enterprise IAM</title>
    <!-- Immediate Theme Application -->
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

                <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-fingerprint text-sm w-4 text-center"></i>
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

                <!-- Access Policies (Active Page) -->
                <a href="vault.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#21262d] border border-[#30363d] text-white shadow-xs font-medium">
                    <i class="fa-solid fa-lock text-sm text-[#2f81f7] w-4 text-center"></i>
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
                <i class="fa-solid fa-magnifying-glass absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-xs"></i>
                <input type="text" placeholder="Search access policies, resources, audit logs... (Ctrl+K)" class="w-full bg-[#0d1117] border border-[#30363d] rounded-md pl-9 pr-14 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#2f81f7] transition font-sans">
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

            <?php if (!empty($feedback_msg)) echo $feedback_msg; ?>

            <!-- 1. BREADCRUMB, MAIN HEADING & ACTION BUTTONS -->
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#30363d]">
                <div>
                    <!-- Clean Breadcrumb & Environment Status -->
                    <div class="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1.5">
                        <span>Administration</span>
                        <span class="text-slate-600">/</span>
                        <span class="text-slate-200 font-semibold">Access Policies</span>
                        <span class="text-slate-600 ml-1">&bull;</span>
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Environment: Production
                        </span>
                    </div>
                    <!-- Main Heading & Subtitle -->
                    <h1 class="text-2xl font-bold text-white tracking-tight">Access Policies &amp; Protected Resources</h1>
                    <p class="text-xs text-slate-400 mt-1 max-w-2xl">Manage Role-Based Access Control (RBAC) tiers and evaluate access authorization for sensitive databases, financials, and credentials.</p>
                </div>

                <!-- Practical Action Buttons -->
                <div class="flex flex-wrap items-center gap-2.5 shrink-0">
                    <div class="px-3.5 py-1.5 rounded-md bg-[#161b22] border border-[#30363d] text-xs font-mono flex items-center gap-2">
                        <span class="text-slate-400">Your Clearance:</span>
                        <strong class="text-[#2f81f7]"><?php echo htmlspecialchars($user_role); ?> (<?php echo htmlspecialchars($user_clearance); ?>)</strong>
                    </div>

                    <a href="dashboard.php#usersDirectory" class="px-3.5 py-2 rounded-md bg-[#2f81f7] hover:bg-blue-600 text-white text-xs font-semibold shadow-xs transition flex items-center gap-2">
                        <i class="fa-solid fa-sliders text-xs"></i>
                        <span>Manage Roles</span>
                    </a>

                    <a href="dashboard.php?export=csv" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-download text-xs text-slate-400"></i>
                        <span>Export Audit CSV</span>
                    </a>
                </div>
            </div>

            <!-- 2. CLEARANCE TIER MATRIX (3 Cards in Dark Slate Aesthetic) -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 my-6">
                <!-- Tier 1 Overview -->
                <div class="p-5 rounded-lg bg-[#161b22] border <?php echo ($tier_numeric === 1) ? 'border-[#2f81f7] ring-1 ring-[#2f81f7]/30' : 'border-[#30363d]'; ?> shadow-xs">
                    <div class="flex items-center justify-between text-xs mb-2">
                        <span class="font-semibold text-slate-300 flex items-center gap-1.5">
                            <i class="fa-solid fa-id-badge text-amber-400"></i> Tier 1 &mdash; Restricted
                        </span>
                        <?php if ($tier_numeric === 1): ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold uppercase">Your Level</span>
                        <?php endif; ?>
                    </div>
                    <div class="text-sm font-semibold text-white">Staff / General Employees</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Standard enterprise workspace access. Read privileges for sensitive PII databases, financial ledgers, and SSH root key pairs are strictly locked.</p>
                </div>

                <!-- Tier 2 Overview -->
                <div class="p-5 rounded-lg bg-[#161b22] border <?php echo ($tier_numeric === 2) ? 'border-[#2f81f7] ring-1 ring-[#2f81f7]/30' : 'border-[#30363d]'; ?> shadow-xs">
                    <div class="flex items-center justify-between text-xs mb-2">
                        <span class="font-semibold text-slate-300 flex items-center gap-1.5">
                            <i class="fa-solid fa-file-shield text-sky-400"></i> Tier 2 &mdash; Confidential
                        </span>
                        <?php if ($tier_numeric === 2): ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20 font-bold uppercase">Your Level</span>
                        <?php endif; ?>
                    </div>
                    <div class="text-sm font-semibold text-white">Auditors &amp; Compliance Officers</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Inspection privileges for Customer PII records and Corporate Financial statements. Production infrastructure SSH root access remains locked.</p>
                </div>

                <!-- Tier 3 Overview -->
                <div class="p-5 rounded-lg bg-[#161b22] border <?php echo ($tier_numeric === 3) ? 'border-[#2f81f7] ring-1 ring-[#2f81f7]/30' : 'border-[#30363d]'; ?> shadow-xs">
                    <div class="flex items-center justify-between text-xs mb-2">
                        <span class="font-semibold text-slate-300 flex items-center gap-1.5">
                            <i class="fa-solid fa-gem text-purple-400"></i> Tier 3 &mdash; Top Secret
                        </span>
                        <?php if ($tier_numeric === 3): ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20 font-bold uppercase">Your Level</span>
                        <?php endif; ?>
                    </div>
                    <div class="text-sm font-semibold text-white">SOC Administrators &amp; CISOs</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Full unrestricted authorization across all enterprise protected resources, cryptographic key enclaves, and cloud infrastructure bastions.</p>
                </div>
            </div>

            <!-- 3. PROTECTED RESOURCES GRID (3 Cards) -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">

                <!-- RESOURCE 1: CUSTOMER PII DATABASE (Requires Tier 2+) -->
                <?php $can_access_pii = ($tier_numeric >= 2); ?>
                <div class="rounded-lg bg-[#161b22] border <?php echo $can_access_pii ? 'border-[#30363d]' : 'border-red-500/30 bg-red-950/5'; ?> shadow-xs flex flex-col justify-between overflow-hidden">
                    <div class="p-5 border-b border-[#30363d] flex justify-between items-center bg-[#0d1117]">
                        <div class="flex items-center space-x-3">
                            <div class="h-9 w-9 rounded-md <?php echo $can_access_pii ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30' : 'bg-red-500/15 text-red-400 border border-red-500/30'; ?> flex items-center justify-center text-sm font-bold">
                                <i class="fa-solid <?php echo $can_access_pii ? 'fa-id-card' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="text-sm font-semibold text-white">Customer PII Database</h3>
                                <p class="text-[10px] font-mono text-slate-400 uppercase">Class: Confidential &bull; Tier 2+</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-mono font-medium px-2 py-0.5 rounded <?php echo $can_access_pii ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'; ?>">
                            <?php echo $can_access_pii ? 'Cleared' : 'Locked'; ?>
                        </span>
                    </div>

                    <div class="p-5 flex-1 space-y-4 text-xs font-sans">
                        <p class="text-slate-400 leading-relaxed">
                            Encrypted database storing 45,820 customer identity records, government ID numbers, session tokens, and billing information.
                        </p>

                        <!-- Data Preview Container -->
                        <div class="bg-[#0d1117] rounded-md p-3 border border-[#30363d] text-xs font-mono relative overflow-hidden">
                            <?php if (!$can_access_pii): ?>
                                <div class="absolute inset-0 bg-[#0d1117]/95 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/30">
                                    <i class="fa-solid fa-ban text-red-400 text-lg mb-1"></i>
                                    <span class="text-xs font-bold text-red-300">Access Restricted</span>
                                    <span class="text-[10px] text-slate-400 mt-0.5">Requires Tier 2+ clearance</span>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_pii ? 'filter blur-sm select-none opacity-30' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-[#30363d] pb-1 text-[10px] uppercase font-bold">
                                    <span>Record UUID</span>
                                    <span>Identity</span>
                                    <span>Cipher</span>
                                </div>
                                <div class="flex justify-between text-slate-300 text-[11px]">
                                    <span class="text-sky-400">UID-9481-C</span>
                                    <span>Sophia Vance (ID: ***-8192)</span>
                                    <span class="text-emerald-400">AES-256</span>
                                </div>
                                <div class="flex justify-between text-slate-300 text-[11px]">
                                    <span class="text-sky-400">UID-9482-D</span>
                                    <span>Marcus Chen (ID: ***-3341)</span>
                                    <span class="text-emerald-400">AES-256</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-[#30363d] font-mono">
                            <span>Compliance: <strong class="text-slate-300">GDPR &bull; ISO 27001</strong></span>
                            <span>Records: <strong class="text-slate-200">45,820</strong></span>
                        </div>
                    </div>

                    <!-- Actions Footer -->
                    <div class="p-4 bg-[#0d1117] border-t border-[#30363d]">
                        <?php if ($can_access_pii): ?>
                            <div class="grid grid-cols-2 gap-2">
                                <button onclick="openModal('piiModal')" class="w-full bg-[#2f81f7] hover:bg-blue-600 text-white py-2 px-3 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 shadow-xs">
                                    <i class="fa-solid fa-eye text-xs"></i> Inspect PII
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="inspect">
                                    <input type="hidden" name="resource_id" value="res_pii">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="w-full bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] py-2 px-3 rounded-md text-xs font-medium transition flex items-center justify-center gap-1.5">
                                        <i class="fa-solid fa-fingerprint text-emerald-400"></i> Audit Query
                                    </button>
                                </form>
                            </div>
                        <?php else: ?>
                            <form method="POST" action="" onsubmit="return confirm('WARNING: Attempting to access an unauthorized resource will log a security policy alert. Proceed?');">
                                <input type="hidden" name="vault_action" value="inspect">
                                <input type="hidden" name="resource_id" value="res_pii">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 py-2 px-3 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5">
                                    <i class="fa-solid fa-lock text-xs"></i> Access Locked (Evaluate Policy)
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- RESOURCE 2: Q3 CORPORATE FINANCIALS (Requires Tier 2+) -->
                <?php $can_access_fin = ($tier_numeric >= 2); ?>
                <div class="rounded-lg bg-[#161b22] border <?php echo $can_access_fin ? 'border-[#30363d]' : 'border-red-500/30 bg-red-950/5'; ?> shadow-xs flex flex-col justify-between overflow-hidden">
                    <div class="p-5 border-b border-[#30363d] flex justify-between items-center bg-[#0d1117]">
                        <div class="flex items-center space-x-3">
                            <div class="h-9 w-9 rounded-md <?php echo $can_access_fin ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/15 text-red-400 border border-red-500/30'; ?> flex items-center justify-center text-sm font-bold">
                                <i class="fa-solid <?php echo $can_access_fin ? 'fa-chart-pie' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="text-sm font-semibold text-white">Q3 Corporate Financials</h3>
                                <p class="text-[10px] font-mono text-slate-400 uppercase">Class: Financial &bull; Tier 2+</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-mono font-medium px-2 py-0.5 rounded <?php echo $can_access_fin ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'; ?>">
                            <?php echo $can_access_fin ? 'Cleared' : 'Locked'; ?>
                        </span>
                    </div>

                    <div class="p-5 flex-1 space-y-4 text-xs font-sans">
                        <p class="text-slate-400 leading-relaxed">
                            Corporate treasury ledgers, Q3 net operating revenue ($14.2M), EBITDA projections, and executive compensation schedules.
                        </p>

                        <!-- Data Preview Container -->
                        <div class="bg-[#0d1117] rounded-md p-3 border border-[#30363d] text-xs font-mono relative overflow-hidden">
                            <?php if (!$can_access_fin): ?>
                                <div class="absolute inset-0 bg-[#0d1117]/95 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/30">
                                    <i class="fa-solid fa-ban text-red-400 text-lg mb-1"></i>
                                    <span class="text-xs font-bold text-red-300">Access Restricted</span>
                                    <span class="text-[10px] text-slate-400 mt-0.5">Requires Tier 2+ clearance</span>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_fin ? 'filter blur-sm select-none opacity-30' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-[#30363d] pb-1 text-[10px] uppercase font-bold">
                                    <span>Fiscal Category</span>
                                    <span>Realized</span>
                                    <span>Status</span>
                                </div>
                                <div class="flex justify-between text-slate-300 text-[11px]">
                                    <span class="text-emerald-400">Enterprise ARR</span>
                                    <span class="font-bold">$14,210,000</span>
                                    <span class="text-emerald-400">+28.4%</span>
                                </div>
                                <div class="flex justify-between text-slate-300 text-[11px]">
                                    <span class="text-emerald-400">Security &amp; IAM</span>
                                    <span class="font-bold">$3,190,000</span>
                                    <span class="text-sky-400">Audited</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-[#30363d] font-mono">
                            <span>Standard: <strong class="text-slate-300">SOX-404 &bull; GAAP</strong></span>
                            <span>Ledger: <strong class="text-emerald-400">Balanced</strong></span>
                        </div>
                    </div>

                    <!-- Actions Footer -->
                    <div class="p-4 bg-[#0d1117] border-t border-[#30363d]">
                        <?php if ($can_access_fin): ?>
                            <div class="grid grid-cols-2 gap-2">
                                <button onclick="openModal('finModal')" class="w-full bg-[#2f81f7] hover:bg-blue-600 text-white py-2 px-3 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 shadow-xs">
                                    <i class="fa-solid fa-chart-line text-xs"></i> View Ledger
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="download_fin_csv">
                                    <input type="hidden" name="resource_id" value="res_fin">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="w-full bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] py-2 px-3 rounded-md text-xs font-medium transition flex items-center justify-center gap-1.5">
                                        <i class="fa-solid fa-download text-xs text-slate-400"></i> Export CSV
                                    </button>
                                </form>
                            </div>
                        <?php else: ?>
                            <form method="POST" action="" onsubmit="return confirm('WARNING: Attempting to access an unauthorized resource will log a security policy alert. Proceed?');">
                                <input type="hidden" name="vault_action" value="inspect">
                                <input type="hidden" name="resource_id" value="res_fin">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 py-2 px-3 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5">
                                    <i class="fa-solid fa-lock text-xs"></i> Access Locked (Evaluate Policy)
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- RESOURCE 3: PRODUCTION SERVER SSH KEYS (Requires Tier 3) -->
                <?php $can_access_ssh = ($tier_numeric >= 3); ?>
                <div class="rounded-lg bg-[#161b22] border <?php echo $can_access_ssh ? 'border-[#30363d]' : 'border-red-500/30 bg-red-950/5'; ?> shadow-xs flex flex-col justify-between overflow-hidden">
                    <div class="p-5 border-b border-[#30363d] flex justify-between items-center bg-[#0d1117]">
                        <div class="flex items-center space-x-3">
                            <div class="h-9 w-9 rounded-md <?php echo $can_access_ssh ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30' : 'bg-red-500/15 text-red-400 border border-red-500/30'; ?> flex items-center justify-center text-sm font-bold">
                                <i class="fa-solid <?php echo $can_access_ssh ? 'fa-key' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="text-sm font-semibold text-white">Production Server SSH Keys</h3>
                                <p class="text-[10px] font-mono text-slate-400 uppercase">Class: Top Secret &bull; Tier 3 Admin</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-mono font-medium px-2 py-0.5 rounded <?php echo $can_access_ssh ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'; ?>">
                            <?php echo $can_access_ssh ? 'Cleared' : 'Locked'; ?>
                        </span>
                    </div>

                    <div class="p-5 flex-1 space-y-4 text-xs font-sans">
                        <p class="text-slate-400 leading-relaxed">
                            Root Ed25519 private key pairs granting root shell privileges across Kubernetes core control planes and database infrastructure.
                        </p>

                        <!-- Data Preview Container -->
                        <div class="bg-[#0d1117] rounded-md p-3 border border-[#30363d] text-xs font-mono relative overflow-hidden">
                            <?php if (!$can_access_ssh): ?>
                                <div class="absolute inset-0 bg-[#0d1117]/95 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/30">
                                    <i class="fa-solid fa-ban text-red-400 text-lg mb-1"></i>
                                    <span class="text-xs font-bold text-red-300">Access Restricted</span>
                                    <span class="text-[10px] text-slate-400 mt-0.5">Requires Tier 3 (Super Admin)</span>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_ssh ? 'filter blur-sm select-none opacity-30' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-[#30363d] pb-1 text-[10px] uppercase font-bold">
                                    <span>Target Host</span>
                                    <span>Fingerprint</span>
                                </div>
                                <div class="flex justify-between text-slate-300 text-[11px]">
                                    <span class="text-purple-400">k8s-prod-master-01</span>
                                    <span>SHA256:4X7mQ...</span>
                                </div>
                                <div class="flex justify-between text-slate-300 text-[11px]">
                                    <span class="text-purple-400">bastion-prod.net</span>
                                    <span>SHA256:1v98K...</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-[#30363d] font-mono">
                            <span>Algorithm: <strong class="text-slate-300">Ed25519</strong></span>
                            <span>Key Length: <strong class="text-purple-400">256-Bit</strong></span>
                        </div>
                    </div>

                    <!-- Actions Footer -->
                    <div class="p-4 bg-[#0d1117] border-t border-[#30363d]">
                        <?php if ($can_access_ssh): ?>
                            <div class="grid grid-cols-2 gap-2">
                                <button onclick="openModal('sshModal')" class="w-full bg-[#2f81f7] hover:bg-blue-600 text-white py-2 px-3 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 shadow-xs">
                                    <i class="fa-solid fa-terminal text-xs"></i> View Key
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="download_ssh">
                                    <input type="hidden" name="resource_id" value="res_ssh">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="w-full bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] py-2 px-3 rounded-md text-xs font-medium transition flex items-center justify-center gap-1.5">
                                        <i class="fa-solid fa-download text-xs text-slate-400"></i> Download .pem
                                    </button>
                                </form>
                            </div>
                        <?php else: ?>
                            <form method="POST" action="" onsubmit="return confirm('CRITICAL WARNING: Attempting to access Root Infrastructure Keys without Tier 3 clearance will trigger an immediate Incident Response alert. Proceed?');">
                                <input type="hidden" name="vault_action" value="inspect">
                                <input type="hidden" name="resource_id" value="res_ssh">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 py-2 px-3 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5">
                                    <i class="fa-solid fa-lock text-xs"></i> Access Locked (Evaluate Policy)
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

            </div>

            <!-- 4. RECENT ACCESS & AUDIT LOGS TABLE -->
            <div class="p-6 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs mb-8">
                <div class="flex items-center justify-between pb-4 border-b border-[#30363d] mb-4">
                    <div>
                        <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                            <i class="fa-solid fa-list-check text-[#2f81f7]"></i>
                            <span>Protected Resources Audit Ledger</span>
                        </h3>
                        <p class="text-xs text-slate-400 mt-0.5">Real-time record of all authorized and unauthorized access attempts to protected resources.</p>
                    </div>
                    <span class="text-xs font-mono text-slate-300 bg-[#0d1117] px-2.5 py-1 rounded border border-[#30363d]">
                        Immutable Policy Log
                    </span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs font-sans">
                        <thead class="bg-[#0d1117] text-slate-400 font-mono text-[11px] uppercase tracking-wider border-b border-[#30363d]">
                            <tr>
                                <th class="px-3.5 py-2.5">Timestamp</th>
                                <th class="px-3.5 py-2.5">Event Type</th>
                                <th class="px-3.5 py-2.5">User</th>
                                <th class="px-3.5 py-2.5">Description</th>
                                <th class="px-3.5 py-2.5 text-right">IP Address</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-[#30363d]">
                            <?php 
                            $v_logs = $conn->query("
                                SELECT a.*, u.email 
                                FROM audit_logs a 
                                LEFT JOIN users u ON a.user_id = u.user_id 
                                WHERE a.action_type LIKE '%VAULT%' OR a.action_type LIKE '%ACCESS_DENIED%'
                                ORDER BY a.log_id DESC 
                                LIMIT 6
                            ");
                            if ($v_logs && $v_logs->num_rows > 0):
                                while ($vl = $v_logs->fetch_assoc()):
                                    $is_denied = (stripos($vl['action_type'], 'DENIED') !== false);
                            ?>
                            <tr class="hover:bg-[#21262d]/60 transition">
                                <td class="px-3.5 py-3 font-mono text-[11px] text-slate-400 whitespace-nowrap"><?php echo htmlspecialchars($vl['created_at']); ?></td>
                                <td class="px-3.5 py-3 whitespace-nowrap">
                                    <span class="px-2 py-0.5 rounded text-[11px] font-medium <?php echo $is_denied ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'; ?>">
                                        <?php echo htmlspecialchars($vl['action_type']); ?>
                                    </span>
                                </td>
                                <td class="px-3.5 py-3 text-slate-200 font-medium whitespace-nowrap"><?php echo htmlspecialchars($vl['email'] ?? 'UID-' . $vl['user_id']); ?></td>
                                <td class="px-3.5 py-3 text-slate-300"><?php echo htmlspecialchars($vl['action_description']); ?></td>
                                <td class="px-3.5 py-3 text-right whitespace-nowrap font-mono text-slate-400"><code><?php echo htmlspecialchars($vl['ip_address']); ?></code></td>
                            </tr>
                            <?php 
                                endwhile;
                            else:
                            ?>
                            <tr>
                                <td colspan="5" class="px-4 py-8 text-center text-slate-500 font-mono text-xs">No resource access events logged yet. Interact with a protected asset above to test RBAC policies.</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Footer -->
            <div class="mt-8 text-center border-t border-[#30363d] pt-6 text-xs text-slate-500 font-mono">
                <i class="fa-solid fa-shield-halved text-[#2f81f7] mr-1"></i>
                ENTERPRISE IDENTITY &amp; ACCESS MANAGEMENT &bull; AIR-GAPPED DEPLOYMENT &bull; iam.secure-defense.internal
            </div>
        </main>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 1: INSPECT DECRYPTED CUSTOMER PII                       -->
    <!-- ============================================================== -->
    <div id="piiModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4 relative">
            <div class="flex justify-between items-center border-b border-[#30363d] pb-3">
                <div class="flex items-center space-x-2 text-[#2f81f7]">
                    <i class="fa-solid fa-id-card text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Customer PII Database &mdash; Decrypted View</h3>
                </div>
                <button onclick="closeModal('piiModal')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <p class="text-xs text-slate-400">
                Identity records decrypted for authorized session. Clearance Level: 
                <strong class="text-emerald-400"><?php echo htmlspecialchars($user_clearance); ?></strong>.
            </p>
            <div class="overflow-x-auto border border-[#30363d] rounded-md">
                <table class="w-full text-left text-xs font-sans">
                    <thead class="bg-[#0d1117] text-slate-400 font-mono text-[10px] uppercase tracking-wider">
                        <tr>
                            <th class="p-3">Customer ID</th>
                            <th class="p-3">Full Name</th>
                            <th class="p-3">National ID</th>
                            <th class="p-3">Country</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-[#30363d] text-slate-300">
                        <tr>
                            <td class="p-3 text-sky-400 font-bold font-mono">CUST-8491</td>
                            <td class="p-3 font-medium text-white">Sophia Vance</td>
                            <td class="p-3 text-emerald-400 font-mono">928-44-8192</td>
                            <td class="p-3">United Kingdom</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-sky-400 font-bold font-mono">CUST-8492</td>
                            <td class="p-3 font-medium text-white">Marcus Chen</td>
                            <td class="p-3 text-emerald-400 font-mono">419-82-3341</td>
                            <td class="p-3">Canada</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-sky-400 font-bold font-mono">CUST-8493</td>
                            <td class="p-3 font-medium text-white">Elena Rostova</td>
                            <td class="p-3 text-emerald-400 font-mono">810-19-5109</td>
                            <td class="p-3">Germany</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="flex justify-end pt-2">
                <button onclick="closeModal('piiModal')" class="px-4 py-2 rounded-md bg-[#21262d] hover:bg-[#30363d] text-slate-200 text-xs font-semibold border border-[#30363d] transition">
                    Close Inspection
                </button>
            </div>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 2: VIEW Q3 CORPORATE FINANCIAL LEDGER                   -->
    <!-- ============================================================== -->
    <div id="finModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4 relative">
            <div class="flex justify-between items-center border-b border-[#30363d] pb-3">
                <div class="flex items-center space-x-2 text-emerald-400">
                    <i class="fa-solid fa-chart-pie text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Q3 Financial Statement &mdash; Executive Ledger</h3>
                </div>
                <button onclick="closeModal('finModal')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <div class="grid grid-cols-2 gap-3 text-xs font-sans">
                <div class="bg-[#0d1117] p-3 rounded-md border border-[#30363d]">
                    <span class="text-slate-400 uppercase text-[10px] font-mono">Gross ARR:</span>
                    <p class="text-lg font-bold text-emerald-400 mt-0.5">$14,210,000</p>
                </div>
                <div class="bg-[#0d1117] p-3 rounded-md border border-[#30363d]">
                    <span class="text-slate-400 uppercase text-[10px] font-mono">EBITDA Margin:</span>
                    <p class="text-lg font-bold text-sky-400 mt-0.5">$4,850,000 (+34.1%)</p>
                </div>
            </div>
            <div class="overflow-x-auto border border-[#30363d] rounded-md">
                <table class="w-full text-left text-xs font-sans">
                    <thead class="bg-[#0d1117] text-slate-400 font-mono text-[10px] uppercase tracking-wider">
                        <tr>
                            <th class="p-3">Department</th>
                            <th class="p-3">Allocated Outlay</th>
                            <th class="p-3">Auditor Verification</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-[#30363d] text-slate-300">
                        <tr>
                            <td class="p-3 font-medium text-white">Security Operations &amp; IAM</td>
                            <td class="p-3 text-emerald-400 font-mono font-bold">$1,850,000</td>
                            <td class="p-3 text-slate-400 font-mono">VERIFIED // SOX-2026</td>
                        </tr>
                        <tr>
                            <td class="p-3 font-medium text-white">Cloud Compute Infrastructure</td>
                            <td class="p-3 text-emerald-400 font-mono font-bold">$2,400,000</td>
                            <td class="p-3 text-slate-400 font-mono">VERIFIED // SOX-2026</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="flex justify-end pt-2">
                <button onclick="closeModal('finModal')" class="px-4 py-2 rounded-md bg-[#21262d] hover:bg-[#30363d] text-slate-200 text-xs font-semibold border border-[#30363d] transition">
                    Close Ledger
                </button>
            </div>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 3: VIEW PRODUCTION SSH PRIVATE KEY                      -->
    <!-- ============================================================== -->
    <div id="sshModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4 relative">
            <div class="flex justify-between items-center border-b border-[#30363d] pb-3">
                <div class="flex items-center space-x-2 text-purple-400">
                    <i class="fa-solid fa-terminal text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Production Root Key Enclave (Ed25519)</h3>
                </div>
                <button onclick="closeModal('sshModal')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <div class="bg-purple-500/10 border border-purple-500/20 p-3 rounded-md text-xs text-purple-300 font-mono">
                <i class="fa-solid fa-shield-halved mr-1.5 text-purple-400"></i> Top Secret Asset: Decrypted for UID-<?php echo $current_user_id; ?> (<?php echo htmlspecialchars($user_role); ?>).
            </div>
            <div class="relative">
                <pre id="sshKeyContent" class="bg-[#0d1117] p-4 rounded-md border border-[#30363d] text-[11px] font-mono text-emerald-400 overflow-x-auto leading-relaxed select-all">-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCE0K/X92Z/lWjRjFj3Jq9N7o01ZLkLm0123456789ABCDEFGHAAAJsAoW
K2Cg123456789ABCDEFGHAAAAAtzc2gtZWQyNTUxOQAAACCE0K/X92Z/lWjRjFj3Jq9N7o
01ZLkLm0123456789ABCDEFGHAAAEC6JvG1/mock/production/cluster/admin/key==
-----END OPENSSH PRIVATE KEY-----</pre>
            </div>
            <div class="flex justify-between items-center pt-2">
                <button onclick="copySSHKey()" id="copyKeyBtn" class="px-3.5 py-2 rounded-md bg-[#2f81f7] hover:bg-blue-600 text-white text-xs font-semibold shadow-xs transition flex items-center gap-1.5">
                    <i class="fa-solid fa-copy text-xs"></i> Copy Private Key
                </button>
                <button onclick="closeModal('sshModal')" class="px-4 py-2 rounded-md bg-[#21262d] hover:bg-[#30363d] text-slate-200 text-xs font-semibold border border-[#30363d] transition">
                    Close Window
                </button>
            </div>
        </div>
    </div>

    <!-- JavaScript Handlers -->
    <script>
        function openModal(id) {
            document.getElementById(id).classList.remove('hidden');
        }

        function closeModal(id) {
            document.getElementById(id).classList.add('hidden');
        }

        function copySSHKey() {
            const keyText = document.getElementById('sshKeyContent').innerText;
            navigator.clipboard.writeText(keyText).then(() => {
                const btn = document.getElementById('copyKeyBtn');
                btn.innerHTML = '<i class="fa-solid fa-check text-xs"></i> Copied!';
                btn.classList.remove('bg-[#2f81f7]');
                btn.classList.add('bg-emerald-600');
                setTimeout(() => {
                    btn.innerHTML = '<i class="fa-solid fa-copy text-xs"></i> Copy Private Key';
                    btn.classList.remove('bg-emerald-600');
                    btn.classList.add('bg-[#2f81f7]');
                }, 2000);
            });
        }

        // Theme Switcher (Light / Dark Mode)
        function toggleTheme() {
            const isDark = document.documentElement.classList.contains('dark');
            if (isDark) {
                document.documentElement.classList.remove('dark');
                document.documentElement.classList.add('light');
                localStorage.setItem('iam_theme', 'light');
                updateThemeIcon('light');
            } else {
                document.documentElement.classList.add('dark');
                document.documentElement.classList.remove('light');
                localStorage.setItem('iam_theme', 'dark');
                updateThemeIcon('dark');
            }
        }

        function updateThemeIcon(theme) {
            const icon = document.getElementById('themeToggleIcon');
            if (!icon) return;
            if (theme === 'light') {
                icon.className = 'fa-solid fa-moon text-xs text-indigo-400';
            } else {
                icon.className = 'fa-solid fa-sun text-xs text-amber-400';
            }
        }

        window.addEventListener('DOMContentLoaded', () => {
            const currentTheme = localStorage.getItem('iam_theme') || 'dark';
            updateThemeIcon(currentTheme);
        });
    </script>
</body>
</html>
