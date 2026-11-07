<?php
/**
 * Enterprise Zero-Trust IAM Portal - Protected Resources (The Crown Jewels Vault)
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
        $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/60 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 text-xs font-tech flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 text-lg text-red-500'></i> CSRF validation failed. Action aborted.</div>";
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

            $feedback_msg = "<div class='cyber-card cyber-brackets bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 p-4 rounded-xl mb-6 text-xs font-tech flex items-center shadow-lg glow-emerald'><i class='fa-solid fa-circle-check mr-3 text-lg text-emerald-400'></i> <div><strong class='font-orbitron font-bold text-white'>ACCESS AUTHORIZED:</strong> Identity clearance {$user_clearance} validated. Operation logged to cryptographic immutable ledger.</div></div>";
        } else {
            // Unauthorized Breach / Access Attempt
            $action_type = "ACCESS_DENIED_UNAUTHORIZED_RESOURCE";
            $action_desc = "UNAUTHORIZED ACCESS ATTEMPT: User {$user_email} ({$user_clearance}) tried to access '{$res_label}' (Requires Tier {$required_tier}+). Action BLOCKED by Zero-Trust RBAC Policy.";
            $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
            $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
            $log->execute();

            $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/80 border border-red-500/60 text-red-300 p-4 rounded-xl mb-6 text-xs font-tech flex items-center shadow-2xl glow-red animate-pulse'><i class='fa-solid fa-triangle-exclamation mr-3 text-xl text-red-400'></i> <div><strong class='font-orbitron font-bold text-white'>SECURITY ACCESS VIOLATION LOGGED:</strong> Access Denied for <span class='text-red-400 font-bold'>{$res_label}</span>. Current clearance level (<span class='text-amber-400 font-bold'>{$user_clearance}</span>) is insufficient. Security incident permanently written to SOC Audit Ledger and flagged by AI Sentinel.</div></div>";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Crown Jewels Vault - Zero-Trust RBAC Protection</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay text-slate-300 font-sans min-h-screen flex flex-col antialiased relative selection:bg-purple-500 selection:text-black">

    <!-- Top High-Tech Cyber Navigation Bar -->
    <nav class="bg-slate-950/85 backdrop-blur-md border-b border-purple-500/25 py-3 px-4 sm:px-6 flex justify-between items-center shadow-2xl sticky top-0 z-30 relative overflow-hidden">
        <!-- Sub-laser accent -->
        <div class="cyber-laser-beam opacity-40"></div>

        <div class="flex items-center space-x-3">
            <button id="mobileSidebarToggle" onclick="toggleSidebar()" class="lg:hidden p-2 text-slate-400 hover:text-purple-400 rounded-lg hover:bg-slate-900 border border-transparent hover:border-purple-500/30 transition">
                <i class="fa-solid fa-bars text-lg"></i>
            </button>
            <div class="relative w-9 h-9 rounded-xl bg-purple-950/60 border border-purple-400/50 flex items-center justify-center text-purple-400 glow-purple">
                <i class="fa-solid fa-vault text-lg"></i>
            </div>
            <div>
                <h1 class="font-orbitron text-sm sm:text-base font-extrabold text-white tracking-wider flex items-center space-x-2">
                    <span>ENTERPRISE VAULT</span>
                    <span class="text-purple-400 glow-text-purple">CROWN JEWELS</span>
                </h1>
                <p class="font-tech text-[10px] text-slate-400 tracking-wider">MANDATORY ACCESS CONTROL (MAC) &bull; ROLE-BASED ACCESS CONTROL (RBAC)</p>
            </div>
        </div>

        <div class="flex items-center space-x-3 text-xs font-tech">
            <!-- Audio SFX Mute/Unmute Toggle -->
            <button onclick="toggleGlobalAudio()" id="navMuteBtn" class="p-2 rounded-lg bg-slate-900/80 border border-slate-700 text-slate-400 hover:text-purple-400 hover:border-purple-400/50 transition" title="Toggle Cyber Audio Synthesizer">
                <i id="navMuteIcon" class="fa-solid fa-volume-high text-xs"></i>
            </button>

            <!-- Clearance Pill -->
            <div class="flex items-center space-x-2 bg-slate-900/90 px-3 py-1.5 rounded-lg border border-purple-500/30 font-tech">
                <span class="text-slate-500">Clearance:</span>
                <?php if ($tier_numeric === 3): ?>
                    <span class="text-purple-300 font-bold flex items-center font-orbitron text-[11px]"><i class="fa-solid fa-gem mr-1.5 text-[10px] text-purple-400"></i> TIER 3 (TOP SECRET)</span>
                <?php elseif ($tier_numeric === 2): ?>
                    <span class="text-cyan-300 font-bold flex items-center font-orbitron text-[11px]"><i class="fa-solid fa-file-shield mr-1.5 text-[10px] text-cyan-400"></i> TIER 2 (CONFIDENTIAL)</span>
                <?php else: ?>
                    <span class="text-amber-300 font-bold flex items-center font-orbitron text-[11px]"><i class="fa-solid fa-id-badge mr-1.5 text-[10px] text-amber-400"></i> TIER 1 (RESTRICTED)</span>
                <?php endif; ?>
            </div>

            <!-- Identity Pill -->
            <div class="hidden md:flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-700 font-tech text-slate-400">
                <i class="fa-solid fa-user-shield text-purple-400"></i>
                <span class="text-white font-medium"><?php echo htmlspecialchars($user_name); ?></span>
                <span class="text-slate-600">|</span>
                <span class="text-cyan-400 font-bold">UID-<?php echo str_pad($current_user_id, 4, '0', STR_PAD_LEFT); ?></span>
            </div>

            <a href="logout.php" class="font-orbitron text-[11px] font-bold text-red-400 hover:text-red-300 transition flex items-center bg-red-950/30 hover:bg-red-950/60 border border-red-500/40 px-3 py-1.5 rounded-lg glow-red shadow-sm">
                <i class="fa-solid fa-arrow-right-from-bracket mr-1.5"></i> LOGOUT
            </a>
        </div>
    </nav>

    <!-- Main Container With Unified Responsive Sidebar -->
    <div class="flex-1 flex overflow-hidden">

        <!-- Sidebar Navigation Drawer -->
        <aside id="appSidebar" class="fixed inset-y-0 left-0 z-40 w-64 bg-slate-950/95 backdrop-blur-md border-r border-purple-500/20 flex flex-col transition-transform duration-300 -translate-x-full lg:translate-x-0 lg:static lg:z-auto">
            
            <!-- Sidebar Header / Current Profile Card -->
            <div class="p-4 border-b border-slate-800">
                <div class="cyber-card cyber-brackets p-3.5 rounded-xl border border-purple-500/25">
                    <div class="flex items-center space-x-3 mb-2">
                        <div class="relative w-10 h-10 rounded-lg bg-purple-950/60 border border-purple-400/50 flex items-center justify-center text-purple-300 font-orbitron font-bold text-sm glow-purple">
                            <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                        </div>
                        <div class="overflow-hidden">
                            <h4 class="font-orbitron text-xs font-bold text-white truncate"><?php echo htmlspecialchars($user_name); ?></h4>
                            <p class="font-tech text-[11px] text-slate-400 truncate"><?php echo htmlspecialchars($user_title); ?></p>
                        </div>
                    </div>
                    <div class="flex items-center justify-between text-[10px] font-tech pt-2 border-t border-slate-800/80">
                        <span class="text-slate-500">Dept:</span>
                        <span class="text-slate-300 truncate max-w-[130px]"><?php echo htmlspecialchars($user_dept); ?></span>
                    </div>
                    <div class="flex items-center justify-between text-[10px] font-tech pt-1">
                        <span class="text-slate-500">Role:</span>
                        <span class="text-purple-400 font-bold"><?php echo htmlspecialchars($user_role); ?></span>
                    </div>
                </div>
            </div>

            <!-- Navigation Links -->
            <nav class="flex-1 p-3 space-y-1.5 overflow-y-auto custom-scrollbar text-xs">
                <div class="px-3 py-1 text-[10px] font-tech uppercase tracking-widest text-slate-500 font-bold">
                    // Core Operations
                </div>

                <a href="dashboard.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-cyan-500/30 transition group font-tech">
                    <i class="fa-solid fa-gauge-high w-4 text-center text-slate-500 group-hover:text-cyan-400 transition"></i>
                    <span class="font-medium">SOC Command Center</span>
                </a>

                <a href="vault.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl bg-purple-950/40 text-purple-300 border border-purple-500/40 font-orbitron text-xs font-bold shadow-md glow-purple">
                    <i class="fa-solid fa-vault w-4 text-center text-purple-400"></i>
                    <span>Secure Vault (Crown Jewels)</span>
                    <span class="ml-auto text-[9px] font-mono bg-purple-500/30 text-purple-200 px-1.5 py-0.5 rounded border border-purple-500/40 uppercase font-bold">RBAC</span>
                </a>

                <a href="api_management.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-amber-500/30 transition group font-tech">
                    <i class="fa-solid fa-key w-4 text-center text-slate-500 group-hover:text-amber-400 transition"></i>
                    <span class="font-medium">API Management</span>
                </a>

                <div class="pt-4 px-3 py-1 text-[10px] font-tech uppercase tracking-widest text-slate-500 font-bold">
                    // Identity & Security
                </div>

                <a href="setup_mfa.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-emerald-500/30 transition group font-tech">
                    <i class="fa-solid fa-mobile-screen-button w-4 text-center text-slate-500 group-hover:text-emerald-400 transition"></i>
                    <span class="font-medium">Multi-Factor Auth (MFA)</span>
                </a>

                <a href="dashboard.php?export=csv" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-cyan-500/30 transition group font-tech">
                    <i class="fa-solid fa-file-csv w-4 text-center text-slate-500 group-hover:text-cyan-400 transition"></i>
                    <span class="font-medium">Export Audit Ledger</span>
                </a>
            </nav>

            <!-- Sidebar Footer Security Status -->
            <div class="p-3 border-t border-slate-800 text-[11px] font-tech text-slate-500">
                <div class="flex items-center space-x-2 text-purple-400 mb-1">
                    <span class="h-2 w-2 rounded-full bg-purple-500 cyber-beacon"></span>
                    <span class="font-bold">Zero-Trust MAC Enforced</span>
                </div>
                <div class="truncate text-[10px] text-slate-500">ED25519 &bull; AES-256 ENCLAVE</div>
            </div>
        </aside>

        <!-- Sidebar Backdrop for Mobile -->
        <div id="sidebarBackdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 hidden lg:hidden"></div>

        <!-- Main Workspace Area -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">

            <?php if (!empty($feedback_msg)) echo $feedback_msg; ?>

            <!-- Page Header -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-8 gap-4 border-b border-purple-500/20 pb-6">
                <div>
                    <div class="flex items-center space-x-2 mb-2">
                        <span class="px-2.5 py-0.5 text-[10px] font-tech font-bold uppercase rounded-md bg-purple-500/20 text-purple-300 border border-purple-500/40">
                            ENTERPRISE ASSET PROTECTION LAYER // RBAC GATEWAY
                        </span>
                        <span class="text-xs text-slate-500 font-tech">&bull; Mandatory Access Control</span>
                    </div>
                    <h2 class="font-orbitron text-2xl sm:text-3xl font-extrabold text-white tracking-tight glow-text-purple mb-1">
                        Protected Resources: "The Crown Jewels"
                    </h2>
                    <p class="font-tech text-slate-400 text-xs sm:text-sm max-w-2xl">
                        Simulating the mission-critical core assets of the enterprise under dynamic Role-Based Access Control (RBAC) and Security Clearance Tiers. Every access attempt, authorized or prohibited, commits a cryptographically hashed event to the audit ledger.
                    </p>
                </div>

                <!-- Fast Identity State Switcher -->
                <div class="cyber-card cyber-brackets p-3.5 rounded-xl border border-purple-500/30 flex items-center space-x-4 shadow-lg">
                    <div class="text-right font-tech">
                        <p class="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Active Identity State</p>
                        <p class="text-xs font-bold text-white font-orbitron"><?php echo htmlspecialchars($user_role); ?> <span class="text-purple-400">(<?php echo htmlspecialchars($user_clearance); ?>)</span></p>
                    </div>
                    <div class="h-8 w-[1px] bg-slate-800"></div>
                    <a href="dashboard.php" class="cyber-btn text-xs font-tech font-bold text-purple-300 hover:text-white flex items-center bg-purple-950/60 hover:bg-purple-900/60 border border-purple-500/40 px-3 py-1.5 rounded-lg transition shadow glow-purple" title="Modify Clearance or User Roles in Command Center">
                        <i class="fa-solid fa-sliders mr-1.5 text-purple-400"></i> Change Role
                    </a>
                </div>
            </div>

            <!-- Clearance Tier Matrix Card (Defense Visualizer) -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
                <!-- Tier 1 Overview -->
                <div class="cyber-card cyber-brackets p-5 rounded-2xl border <?php echo ($tier_numeric === 1) ? 'border-amber-500/60 glow-amber' : 'border-slate-800/80'; ?> transition">
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-orbitron text-xs font-bold text-amber-400 flex items-center">
                            <i class="fa-solid fa-id-badge mr-1.5"></i> TIER 1 // RESTRICTED
                        </span>
                        <?php if ($tier_numeric === 1): ?>
                            <span class="text-[9px] font-tech bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded font-bold uppercase">YOUR CLEARANCE</span>
                        <?php endif; ?>
                    </div>
                    <p class="font-tech text-xs font-bold text-white">Staff / General Employees</p>
                    <p class="font-tech text-[11px] text-slate-400 mt-1 leading-relaxed">Standard enterprise workspace access. Read privileges for sensitive PII databases, financial ledgers, and SSH root key pairs are strictly locked.</p>
                </div>

                <!-- Tier 2 Overview -->
                <div class="cyber-card cyber-brackets p-5 rounded-2xl border <?php echo ($tier_numeric === 2) ? 'border-cyan-500/60 glow-cyan' : 'border-slate-800/80'; ?> transition">
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-orbitron text-xs font-bold text-cyan-400 flex items-center">
                            <i class="fa-solid fa-file-shield mr-1.5"></i> TIER 2 // CONFIDENTIAL
                        </span>
                        <?php if ($tier_numeric === 2): ?>
                            <span class="text-[9px] font-tech bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded font-bold uppercase">YOUR CLEARANCE</span>
                        <?php endif; ?>
                    </div>
                    <p class="font-tech text-xs font-bold text-white">Auditors & Compliance Officers</p>
                    <p class="font-tech text-[11px] text-slate-400 mt-1 leading-relaxed">Read & inspection privileges for Customer PII records and Corporate Financial statements. Production infrastructure SSH root access remains locked.</p>
                </div>

                <!-- Tier 3 Overview -->
                <div class="cyber-card cyber-brackets p-5 rounded-2xl border <?php echo ($tier_numeric === 3) ? 'border-purple-500/60 glow-purple' : 'border-slate-800/80'; ?> transition">
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-orbitron text-xs font-bold text-purple-400 flex items-center">
                            <i class="fa-solid fa-gem mr-1.5"></i> TIER 3 // TOP SECRET
                        </span>
                        <?php if ($tier_numeric === 3): ?>
                            <span class="text-[9px] font-tech bg-purple-500/20 text-purple-300 border border-purple-500/40 px-2 py-0.5 rounded font-bold uppercase">YOUR CLEARANCE</span>
                        <?php endif; ?>
                    </div>
                    <p class="font-tech text-xs font-bold text-white">SOC Administrators & CISOs</p>
                    <p class="font-tech text-[11px] text-slate-400 mt-1 leading-relaxed">Full unrestricted authorization across all enterprise crown jewels, cryptographic key enclaves, cloud infrastructure bastions, and telemetry streams.</p>
                </div>
            </div>

            <!-- CROWN JEWELS GRID (THE 3 PROTECTED DATABASES) -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-10">

                <!-- ============================================================== -->
                <!-- CROWN JEWEL 1: CUSTOMER PII DATABASE (Requires Tier 2+)       -->
                <!-- ============================================================== -->
                <?php 
                $can_access_pii = ($tier_numeric >= 2);
                ?>
                <div class="cyber-card cyber-brackets rounded-2xl border <?php echo $can_access_pii ? 'border-cyan-500/40 shadow-2xl' : 'border-red-500/40 bg-red-950/10'; ?> flex flex-col justify-between overflow-hidden relative group">
                    <div class="cyber-laser-beam opacity-30"></div>
                    
                    <!-- Top Ribbon -->
                    <div class="p-5 border-b <?php echo $can_access_pii ? 'border-cyan-500/20 bg-slate-950/80' : 'border-red-500/20 bg-red-950/30'; ?> flex justify-between items-center">
                        <div class="flex items-center space-x-3">
                            <div class="h-10 w-10 rounded-xl <?php echo $can_access_pii ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-500/50 glow-cyan-sm' : 'bg-red-950/70 text-red-400 border border-red-500/50 glow-red'; ?> flex items-center justify-center text-lg">
                                <i class="fa-solid <?php echo $can_access_pii ? 'fa-id-card' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="font-orbitron text-sm font-bold text-white">Customer PII Database</h3>
                                <p class="text-[10px] font-tech text-slate-400 uppercase tracking-wider">CLASS: CONFIDENTIAL // TIER 2+</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-tech font-bold px-2.5 py-1 rounded-md <?php echo $can_access_pii ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'; ?>">
                            <?php echo $can_access_pii ? 'CLEARED' : 'LOCKED'; ?>
                        </span>
                    </div>

                    <!-- Body Content -->
                    <div class="p-5 flex-1 space-y-4 font-tech">
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Encrypted relational cluster storing 45,820 customer identity records, Social Security & National ID tokens, session hashes, and PCI-DSS billing information.
                        </p>

                        <!-- Mock Data Preview / Lock Overlay -->
                        <div class="bg-slate-950/90 rounded-xl p-3 border border-slate-800 text-[11px] font-tech relative overflow-hidden">
                            <?php if (!$can_access_pii): ?>
                                <!-- Red Denied Overlay -->
                                <div class="absolute inset-0 bg-red-950/90 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/50">
                                    <div class="h-10 w-10 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center text-red-400 mb-2">
                                        <i class="fa-solid fa-ban text-lg"></i>
                                    </div>
                                    <h4 class="font-orbitron text-xs font-bold text-red-300 tracking-wider">ACCESS DENIED: INSUFFICIENT CLEARANCE</h4>
                                    <p class="text-[10px] text-red-300/80 mt-1 max-w-[220px]">Requires Tier 2 (Auditor) or Tier 3 (Admin). Your clearance: <strong class="text-amber-400"><?php echo htmlspecialchars($user_clearance); ?></strong>.</p>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_pii ? 'filter blur-sm select-none opacity-40' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-slate-800 pb-1 text-[10px] uppercase font-bold">
                                    <span>Record UUID</span>
                                    <span>Identity Token</span>
                                    <span>Encryption</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-cyan-400 font-bold">UID-9481-C</span>
                                    <span>Sophia Vance (SSN: ***-**-8192)</span>
                                    <span class="text-emerald-400 font-bold">AES-256</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-cyan-400 font-bold">UID-9482-D</span>
                                    <span>Marcus Chen (SSN: ***-**-3341)</span>
                                    <span class="text-emerald-400 font-bold">AES-256</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-cyan-400 font-bold">UID-9483-E</span>
                                    <span>Elena Rostova (SSN: ***-**-5109)</span>
                                    <span class="text-emerald-400 font-bold">AES-256</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                            <span>Compliance: <span class="text-slate-300">GDPR &bull; ISO-27001</span></span>
                            <span>Records: <span class="text-cyan-400 font-bold">45,820</span></span>
                        </div>
                    </div>

                    <!-- Footer Action Buttons -->
                    <div class="p-5 bg-slate-950/70 border-t border-slate-800/80 font-tech">
                        <?php if ($can_access_pii): ?>
                            <div class="grid grid-cols-2 gap-2.5">
                                <button onclick="openModal('piiModal')" class="cyber-btn w-full bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-500/40 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center glow-cyan-sm">
                                    <i class="fa-solid fa-eye mr-1.5 text-cyan-400"></i> Inspect PII
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="inspect">
                                    <input type="hidden" name="resource_id" value="res_pii">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="cyber-btn w-full bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center">
                                        <i class="fa-solid fa-fingerprint mr-1.5 text-emerald-400"></i> Audit Query
                                    </button>
                                </form>
                            </div>
                        <?php else: ?>
                            <!-- Staff Blocked Button with Simulated Breach Logging -->
                            <form method="POST" action="" onsubmit="return confirm('WARNING: Attempting to access an unauthorized resource will log a security alert under your user ID. Proceed?');">
                                <input type="hidden" name="vault_action" value="inspect">
                                <input type="hidden" name="resource_id" value="res_pii">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="cyber-btn w-full bg-red-950/40 hover:bg-red-900/50 text-red-400 border border-red-500/40 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center group glow-red">
                                    <i class="fa-solid fa-lock mr-2 text-red-500 group-hover:scale-110 transition"></i>
                                    <span>Access Locked (Trigger Violation)</span>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- CROWN JEWEL 2: Q3 CORPORATE FINANCIALS (Requires Tier 2+)     -->
                <!-- ============================================================== -->
                <?php 
                $can_access_fin = ($tier_numeric >= 2);
                ?>
                <div class="cyber-card cyber-brackets rounded-2xl border <?php echo $can_access_fin ? 'border-emerald-500/40 shadow-2xl' : 'border-red-500/40 bg-red-950/10'; ?> flex flex-col justify-between overflow-hidden relative group">
                    <div class="cyber-laser-beam opacity-30"></div>
                    
                    <!-- Top Ribbon -->
                    <div class="p-5 border-b <?php echo $can_access_fin ? 'border-emerald-500/20 bg-slate-950/80' : 'border-red-500/20 bg-red-950/30'; ?> flex justify-between items-center">
                        <div class="flex items-center space-x-3">
                            <div class="h-10 w-10 rounded-xl <?php echo $can_access_fin ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-500/50 glow-emerald' : 'bg-red-950/70 text-red-400 border border-red-500/50 glow-red'; ?> flex items-center justify-center text-lg">
                                <i class="fa-solid <?php echo $can_access_fin ? 'fa-chart-pie' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="font-orbitron text-sm font-bold text-white">Q3 Corporate Financials</h3>
                                <p class="text-[10px] font-tech text-slate-400 uppercase tracking-wider">CLASS: RESTRICTED FINANCIAL // TIER 2+</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-tech font-bold px-2.5 py-1 rounded-md <?php echo $can_access_fin ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'; ?>">
                            <?php echo $can_access_fin ? 'CLEARED' : 'LOCKED'; ?>
                        </span>
                    </div>

                    <!-- Body Content -->
                    <div class="p-5 flex-1 space-y-4 font-tech">
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Consolidated corporate treasury ledgers, Q3 net revenue performance ($14.2M), EBITDA projections, executive compensation schedules, and SWIFT authorizations.
                        </p>

                        <!-- Mock Data Preview / Lock Overlay -->
                        <div class="bg-slate-950/90 rounded-xl p-3 border border-slate-800 text-[11px] font-tech relative overflow-hidden">
                            <?php if (!$can_access_fin): ?>
                                <!-- Red Denied Overlay -->
                                <div class="absolute inset-0 bg-red-950/90 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/50">
                                    <div class="h-10 w-10 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center text-red-400 mb-2">
                                        <i class="fa-solid fa-ban text-lg"></i>
                                    </div>
                                    <h4 class="font-orbitron text-xs font-bold text-red-300 tracking-wider">ACCESS DENIED: INSUFFICIENT CLEARANCE</h4>
                                    <p class="text-[10px] text-red-300/80 mt-1 max-w-[220px]">Requires Tier 2 (Auditor) or Tier 3 (Admin). Your clearance: <strong class="text-amber-400"><?php echo htmlspecialchars($user_clearance); ?></strong>.</p>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_fin ? 'filter blur-sm select-none opacity-40' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-slate-800 pb-1 text-[10px] uppercase font-bold">
                                    <span>Fiscal Category</span>
                                    <span>Q3 Realized</span>
                                    <span>EBITDA Margin</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-emerald-400 font-bold">Gross Enterprise ARR</span>
                                    <span class="font-bold">$14,210,000</span>
                                    <span class="text-emerald-400 font-bold">+28.4%</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-emerald-400 font-bold">R&D / SOC Security</span>
                                    <span>$3,190,000</span>
                                    <span class="text-cyan-400 font-bold">Allocated</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-emerald-400 font-bold">Corporate Treasury Cash</span>
                                    <span>$8,450,000</span>
                                    <span class="text-emerald-400 font-bold">Audited</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                            <span>Audit Standard: <span class="text-slate-300">SOX-404 &bull; GAAP</span></span>
                            <span>Ledger Status: <span class="text-emerald-400 font-bold">BALANCED</span></span>
                        </div>
                    </div>

                    <!-- Footer Action Buttons -->
                    <div class="p-5 bg-slate-950/70 border-t border-slate-800/80 font-tech">
                        <?php if ($can_access_fin): ?>
                            <div class="grid grid-cols-2 gap-2.5">
                                <button onclick="openModal('finModal')" class="cyber-btn w-full bg-emerald-950/50 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-500/40 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center glow-emerald">
                                    <i class="fa-solid fa-chart-line mr-1.5 text-emerald-400"></i> View Ledger
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="download_fin_csv">
                                    <input type="hidden" name="resource_id" value="res_fin">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="cyber-btn w-full bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center">
                                        <i class="fa-solid fa-download mr-1.5 text-cyan-400"></i> Export CSV
                                    </button>
                                </form>
                            </div>
                        <?php else: ?>
                            <!-- Staff Blocked Button with Simulated Breach Logging -->
                            <form method="POST" action="" onsubmit="return confirm('WARNING: Attempting to access an unauthorized resource will log a security alert under your user ID. Proceed?');">
                                <input type="hidden" name="vault_action" value="inspect">
                                <input type="hidden" name="resource_id" value="res_fin">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="cyber-btn w-full bg-red-950/40 hover:bg-red-900/50 text-red-400 border border-red-500/40 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center group glow-red">
                                    <i class="fa-solid fa-lock mr-2 text-red-500 group-hover:scale-110 transition"></i>
                                    <span>Access Locked (Trigger Violation)</span>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- ============================================================== -->
                <!-- CROWN JEWEL 3: PRODUCTION SERVER SSH KEYS (Requires Tier 3)   -->
                <!-- ============================================================== -->
                <?php 
                $can_access_ssh = ($tier_numeric >= 3);
                ?>
                <div class="cyber-card cyber-brackets rounded-2xl border <?php echo $can_access_ssh ? 'border-purple-500/40 shadow-2xl' : 'border-red-500/40 bg-red-950/10'; ?> flex flex-col justify-between overflow-hidden relative group">
                    <div class="cyber-laser-beam opacity-30"></div>
                    
                    <!-- Top Ribbon -->
                    <div class="p-5 border-b <?php echo $can_access_ssh ? 'border-purple-500/20 bg-slate-950/80' : 'border-red-500/20 bg-red-950/30'; ?> flex justify-between items-center">
                        <div class="flex items-center space-x-3">
                            <div class="h-10 w-10 rounded-xl <?php echo $can_access_ssh ? 'bg-purple-950/70 text-purple-400 border border-purple-500/50 glow-purple' : 'bg-red-950/70 text-red-400 border border-red-500/50 glow-red'; ?> flex items-center justify-center text-lg">
                                <i class="fa-solid <?php echo $can_access_ssh ? 'fa-key' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="font-orbitron text-sm font-bold text-white">Production Server SSH Keys</h3>
                                <p class="text-[10px] font-tech text-slate-400 uppercase tracking-wider">CLASS: TOP SECRET // TIER 3 ADMIN ONLY</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-tech font-bold px-2.5 py-1 rounded-md <?php echo $can_access_ssh ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'; ?>">
                            <?php echo $can_access_ssh ? 'CLEARED' : 'LOCKED'; ?>
                        </span>
                    </div>

                    <!-- Body Content -->
                    <div class="p-5 flex-1 space-y-4 font-tech">
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Root Ed25519 cryptographic private key pairs granting root shell privileges across Kubernetes core control clusters, AWS production VPC bastions, and database infrastructure.
                        </p>

                        <!-- Mock Data Preview / Lock Overlay -->
                        <div class="bg-slate-950/90 rounded-xl p-3 border border-slate-800 text-[11px] font-tech relative overflow-hidden">
                            <?php if (!$can_access_ssh): ?>
                                <!-- Red Denied Overlay -->
                                <div class="absolute inset-0 bg-red-950/90 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/50">
                                    <div class="h-10 w-10 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center text-red-400 mb-2">
                                        <i class="fa-solid fa-shield-halved text-lg"></i>
                                    </div>
                                    <h4 class="font-orbitron text-xs font-bold text-red-300 tracking-wider">ACCESS DENIED: INSUFFICIENT CLEARANCE</h4>
                                    <p class="text-[10px] text-red-300/80 mt-1 max-w-[220px]">Requires Tier 3 (Super Admin / CISO). Even Tier 2 Auditors are blocked from raw root infrastructure keys.</p>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_ssh ? 'filter blur-sm select-none opacity-40' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-slate-800 pb-1 text-[10px] uppercase font-bold">
                                    <span>Target Host</span>
                                    <span>Cipher / Fingerprint</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-purple-400 font-bold">k8s-prod-master-01</span>
                                    <span>SHA256:4X7mQ9p...</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-purple-400 font-bold">bastion-east.defense.net</span>
                                    <span>SHA256:1v98Kll...</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-purple-400 font-bold">mariadb-cluster-node-01</span>
                                    <span>SHA256:9a32Zxc...</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/80">
                            <span>Cipher: <span class="text-slate-300">Ed25519 (OpenSSH)</span></span>
                            <span>Key Strength: <span class="text-purple-400 font-bold">MIL-SPEC 256-BIT</span></span>
                        </div>
                    </div>

                    <!-- Footer Action Buttons -->
                    <div class="p-5 bg-slate-950/70 border-t border-slate-800/80 font-tech">
                        <?php if ($can_access_ssh): ?>
                            <div class="grid grid-cols-2 gap-2.5">
                                <button onclick="openModal('sshModal')" class="cyber-btn w-full bg-purple-950/50 hover:bg-purple-900/60 text-purple-300 border border-purple-500/40 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center glow-purple">
                                    <i class="fa-solid fa-terminal mr-1.5 text-purple-400"></i> View Key Pair
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="download_ssh">
                                    <input type="hidden" name="resource_id" value="res_ssh">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="cyber-btn w-full bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center">
                                        <i class="fa-solid fa-download mr-1.5 text-cyan-400"></i> Download .pem
                                    </button>
                                </form>
                            </div>
                        <?php else: ?>
                            <!-- Staff / Auditor Blocked Button with Simulated Breach Logging -->
                            <form method="POST" action="" onsubmit="return confirm('CRITICAL SECURITY WARNING: Attempting to access Root Infrastructure Keys without Tier 3 clearance will trigger an immediate Incident Response event. Proceed?');">
                                <input type="hidden" name="vault_action" value="inspect">
                                <input type="hidden" name="resource_id" value="res_ssh">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="cyber-btn w-full bg-red-950/40 hover:bg-red-900/50 text-red-400 border border-red-500/40 py-2.5 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center group glow-red">
                                    <i class="fa-solid fa-lock mr-2 text-red-500 group-hover:scale-110 transition"></i>
                                    <span>Access Locked (Trigger Violation)</span>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

            </div>

            <!-- AUDIT STREAM SNAPSHOT (Protected Resources Activity) -->
            <div class="cyber-card cyber-brackets rounded-2xl border border-purple-500/30 p-6 shadow-2xl mb-8">
                <div class="flex items-center justify-between mb-4 border-b border-slate-800/80 pb-3">
                    <div class="flex items-center space-x-2 text-white">
                        <i class="fa-solid fa-shield-halved text-purple-400 text-base"></i>
                        <h3 class="font-orbitron text-xs sm:text-sm font-bold tracking-wide">Protected Resources Live Audit Stream</h3>
                    </div>
                    <span class="text-[10px] font-tech text-purple-300 bg-purple-950/60 px-2.5 py-0.5 rounded border border-purple-500/40 font-bold">
                        IMMUTABLE MAC LEDGER
                    </span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs font-tech">
                        <thead class="bg-slate-950 text-slate-400 text-[11px] uppercase tracking-wider font-bold">
                            <tr>
                                <th class="px-4 py-3">Timestamp</th>
                                <th class="px-4 py-3">Event Type</th>
                                <th class="px-4 py-3">Target Identity</th>
                                <th class="px-4 py-3">Security Action & Description</th>
                                <th class="px-4 py-3 text-right">Client IP</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/60">
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
                            <tr class="hover:bg-slate-900/60 transition">
                                <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?php echo htmlspecialchars($vl['created_at']); ?></td>
                                <td class="px-4 py-3 whitespace-nowrap">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $is_denied ? 'bg-red-500/20 text-red-400 border border-red-500/40 glow-red' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 glow-emerald'; ?>">
                                        <?php echo htmlspecialchars($vl['action_type']); ?>
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-slate-300 whitespace-nowrap font-bold"><?php echo htmlspecialchars($vl['email'] ?? 'UID-' . $vl['user_id']); ?></td>
                                <td class="px-4 py-3 text-slate-400"><?php echo htmlspecialchars($vl['action_description']); ?></td>
                                <td class="px-4 py-3 text-cyan-400 text-right whitespace-nowrap font-mono"><?php echo htmlspecialchars($vl['ip_address']); ?></td>
                            </tr>
                            <?php 
                                endwhile;
                            else:
                            ?>
                            <tr>
                                <td colspan="5" class="px-4 py-8 text-center text-slate-500 font-tech">No vault security actions logged yet. Interact with a resource above to trigger events.</td>
                            </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        </main>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 1: INSPECT DECRYPTED CUSTOMER PII                       -->
    <!-- ============================================================== -->
    <div id="piiModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md flex justify-center items-center z-50 p-4">
        <div class="cyber-card cyber-brackets bg-slate-950/95 border border-cyan-500/50 rounded-2xl max-w-2xl w-full p-6 sm:p-8 shadow-2xl space-y-4 relative overflow-hidden">
            <div class="cyber-laser-beam opacity-30"></div>
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2.5 text-cyan-400">
                    <i class="fa-solid fa-id-card text-lg"></i>
                    <h3 class="font-orbitron font-bold text-white text-base">Customer PII Database &bull; Decrypted Enclave</h3>
                </div>
                <button onclick="closeModal('piiModal')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <p class="text-xs font-tech text-slate-400">
                Identity records decrypted via ephemeral Zero-Trust session key. Clearance Level 
                <strong class="text-cyan-400 font-bold"><?php echo htmlspecialchars($user_clearance); ?></strong> verified.
            </p>
            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left text-xs font-tech">
                    <thead class="bg-slate-950 text-slate-400 text-[10px] uppercase tracking-wider">
                        <tr>
                            <th class="p-3">Customer ID</th>
                            <th class="p-3">Full Name</th>
                            <th class="p-3">Decrypted National ID</th>
                            <th class="p-3">Billing Country</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/80 text-slate-300">
                        <tr>
                            <td class="p-3 text-cyan-400 font-bold font-mono">CUST-8491</td>
                            <td class="p-3 font-semibold text-white">Sophia Vance</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">928-44-8192</td>
                            <td class="p-3">United Kingdom</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-cyan-400 font-bold font-mono">CUST-8492</td>
                            <td class="p-3 font-semibold text-white">Marcus Chen</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">419-82-3341</td>
                            <td class="p-3">Canada</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-cyan-400 font-bold font-mono">CUST-8493</td>
                            <td class="p-3 font-semibold text-white">Elena Rostova</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">810-19-5109</td>
                            <td class="p-3">Germany</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-cyan-400 font-bold font-mono">CUST-8494</td>
                            <td class="p-3 font-semibold text-white">Tariq Al-Mansoor</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">552-30-7714</td>
                            <td class="p-3">United Arab Emirates</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="flex justify-end pt-2">
                <button onclick="closeModal('piiModal')" class="cyber-btn bg-slate-800 hover:bg-slate-700 text-white text-xs font-tech font-bold px-4 py-2 rounded-xl transition">
                    Close Inspection
                </button>
            </div>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 2: VIEW Q3 CORPORATE FINANCIAL LEDGER                   -->
    <!-- ============================================================== -->
    <div id="finModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md flex justify-center items-center z-50 p-4">
        <div class="cyber-card cyber-brackets bg-slate-950/95 border border-emerald-500/50 rounded-2xl max-w-2xl w-full p-6 sm:p-8 shadow-2xl space-y-4 relative overflow-hidden">
            <div class="cyber-laser-beam opacity-30"></div>
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2.5 text-emerald-400">
                    <i class="fa-solid fa-chart-pie text-lg"></i>
                    <h3 class="font-orbitron font-bold text-white text-base">Q3 Financial Statement &bull; Executive Ledger</h3>
                </div>
                <button onclick="closeModal('finModal')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <div class="grid grid-cols-2 gap-3 text-xs font-tech">
                <div class="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                    <span class="text-slate-500 uppercase font-bold text-[10px]">Gross Operating ARR:</span>
                    <p class="font-orbitron text-lg font-bold text-emerald-400 mt-1">$14,210,000</p>
                </div>
                <div class="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
                    <span class="text-slate-500 uppercase font-bold text-[10px]">Net EBITDA Margin:</span>
                    <p class="font-orbitron text-lg font-bold text-cyan-400 mt-1">$4,850,000 (+34.1%)</p>
                </div>
            </div>
            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left text-xs font-tech">
                    <thead class="bg-slate-950 text-slate-400 text-[10px] uppercase tracking-wider">
                        <tr>
                            <th class="p-3">Department</th>
                            <th class="p-3">Allocated Outlay</th>
                            <th class="p-3">Auditor Signature</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/80 text-slate-300">
                        <tr>
                            <td class="p-3 text-white font-semibold">Security Operations & IAM</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">$1,850,000</td>
                            <td class="p-3 text-slate-400 font-mono">VERIFIED // SOX-2026</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-white font-semibold">Cloud Compute Infrastructure</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">$2,400,000</td>
                            <td class="p-3 text-slate-400 font-mono">VERIFIED // SOX-2026</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-white font-semibold">Legal, Privacy & Compliance</td>
                            <td class="p-3 text-emerald-400 font-bold font-mono">$720,000</td>
                            <td class="p-3 text-slate-400 font-mono">VERIFIED // SOX-2026</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="flex justify-end pt-2">
                <button onclick="closeModal('finModal')" class="cyber-btn bg-slate-800 hover:bg-slate-700 text-white text-xs font-tech font-bold px-4 py-2 rounded-xl transition">
                    Close Ledger
                </button>
            </div>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 3: VIEW PRODUCTION SSH PRIVATE KEY                      -->
    <!-- ============================================================== -->
    <div id="sshModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md flex justify-center items-center z-50 p-4">
        <div class="cyber-card cyber-brackets bg-slate-950/95 border border-purple-500/50 rounded-2xl max-w-2xl w-full p-6 sm:p-8 shadow-2xl space-y-4 relative overflow-hidden">
            <div class="cyber-laser-beam opacity-30"></div>
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2.5 text-purple-400">
                    <i class="fa-solid fa-terminal text-lg"></i>
                    <h3 class="font-orbitron font-bold text-white text-base">Production Root Key Enclave (Ed25519)</h3>
                </div>
                <button onclick="closeModal('sshModal')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <div class="bg-purple-950/30 border border-purple-500/40 p-3 rounded-xl text-xs text-purple-300 font-tech">
                <i class="fa-solid fa-triangle-exclamation mr-1.5 text-purple-400"></i> TOP SECRET PRIVILEGED ASSET: Raw private key decrypted exclusively for UID-<?php echo $current_user_id; ?> (CISO/Admin).
            </div>
            <div class="relative">
                <pre id="sshKeyContent" class="bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto leading-relaxed select-all">-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCE0K/X92Z/lWjRjFj3Jq9N7o01ZLkLm0123456789ABCDEFGHAAAJsAoW
K2Cg123456789ABCDEFGHAAAAAtzc2gtZWQyNTUxOQAAACCE0K/X92Z/lWjRjFj3Jq9N7o
01ZLkLm0123456789ABCDEFGHAAAEC6JvG1/mock/production/cluster/admin/key==
-----END OPENSSH PRIVATE KEY-----</pre>
            </div>
            <div class="flex justify-between items-center pt-2">
                <button onclick="copySSHKey()" id="copyKeyBtn" class="cyber-btn bg-purple-600 hover:bg-purple-500 text-white text-xs font-orbitron font-bold px-4 py-2 rounded-xl transition flex items-center shadow-lg glow-purple">
                    <i class="fa-solid fa-copy mr-1.5"></i> Copy Private Key
                </button>
                <button onclick="closeModal('sshModal')" class="cyber-btn bg-slate-800 hover:bg-slate-700 text-white text-xs font-tech font-bold px-4 py-2 rounded-xl transition">
                    Close Window
                </button>
            </div>
        </div>
    </div>

    <!-- JavaScript Handlers -->
    <script>
        function toggleSidebar() {
            const sidebar = document.getElementById('appSidebar');
            const backdrop = document.getElementById('sidebarBackdrop');
            if (sidebar.classList.contains('-translate-x-full')) {
                sidebar.classList.remove('-translate-x-full');
                backdrop.classList.remove('hidden');
            } else {
                sidebar.classList.add('-translate-x-full');
                backdrop.classList.add('hidden');
            }
        }

        function toggleGlobalAudio() {
            if (window.CyberAudio) {
                const muted = CyberAudio.toggleMute();
                const icon = document.getElementById('navMuteIcon');
                if (icon) {
                    icon.className = muted ? 'fa-solid fa-volume-xmark text-xs text-red-400' : 'fa-solid fa-volume-high text-xs text-purple-400';
                }
                if (!muted) CyberAudio.accessGranted();
            }
        }

        function openModal(id) {
            if (window.CyberAudio) CyberAudio.click();
            document.getElementById(id).classList.remove('hidden');
        }

        function closeModal(id) {
            document.getElementById(id).classList.add('hidden');
        }

        function copySSHKey() {
            const keyText = document.getElementById('sshKeyContent').innerText;
            navigator.clipboard.writeText(keyText).then(() => {
                if (window.CyberAudio) CyberAudio.accessGranted();
                const btn = document.getElementById('copyKeyBtn');
                btn.innerHTML = '<i class="fa-solid fa-check mr-1.5"></i> Copied!';
                btn.classList.remove('bg-purple-600');
                btn.classList.add('bg-emerald-600');
                setTimeout(() => {
                    btn.innerHTML = '<i class="fa-solid fa-copy mr-1.5"></i> Copy Private Key';
                    btn.classList.remove('bg-emerald-600');
                    btn.classList.add('bg-purple-600');
                }, 2000);
            });
        }
    </script>
</body>
</html>
