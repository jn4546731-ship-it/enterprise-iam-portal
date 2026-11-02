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
        $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 text-sm flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 text-lg'></i> CSRF validation failed. Action aborted.</div>";
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

            $feedback_msg = "<div class='bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 p-4 rounded-xl mb-6 text-sm flex items-center shadow-lg'><i class='fa-solid fa-circle-check mr-2 text-lg text-emerald-400'></i> <strong>Access Authorized:</strong> Identity clearance {$user_clearance} validated. Operation logged to immutable audit trail.</div>";
        } else {
            // Unauthorized Breach / Access Attempt
            $action_type = "ACCESS_DENIED_UNAUTHORIZED_RESOURCE";
            $action_desc = "UNAUTHORIZED ACCESS ATTEMPT: User {$user_email} ({$user_clearance}) tried to access '{$res_label}' (Requires Tier {$required_tier}+). Action BLOCKED by Zero-Trust RBAC Policy.";
            $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
            $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
            $log->execute();

            $feedback_msg = "<div class='bg-red-500/15 border border-red-500/60 text-red-400 p-4 rounded-xl mb-6 text-sm flex items-center shadow-2xl animate-pulse'><i class='fa-solid fa-triangle-exclamation mr-3 text-xl text-red-500'></i> <div><strong class='font-bold text-red-300'>SECURITY ACCESS VIOLATION LOGGED:</strong> Access Denied for <strong>{$res_label}</strong>. Your current clearance (<strong>{$user_clearance}</strong>) is insufficient. This security incident has been permanently written to the SOC Audit Ledger and flagged for review.</div></div>";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Resources (Crown Jewels) - Enterprise Zero-Trust Vault</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <style>
        .custom-scrollbar::-webkit-scrollbar { width: 5px; height: 5px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.6); }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }

        @keyframes scanGlow {
            0%, 100% { border-color: rgba(59, 130, 246, 0.4); box-shadow: 0 0 15px rgba(59, 130, 246, 0.2); }
            50% { border-color: rgba(99, 102, 241, 0.6); box-shadow: 0 0 25px rgba(99, 102, 241, 0.35); }
        }
        .vault-card-glow {
            animation: scanGlow 4s ease-in-out infinite;
        }
    </style>
</head>
<body class="bg-slate-950 text-slate-300 font-sans min-h-screen flex flex-col antialiased">

    <!-- Top Navigation Bar -->
    <nav class="bg-slate-900/90 backdrop-blur border-b border-slate-800 py-3.5 px-6 flex justify-between items-center shadow-lg sticky top-0 z-30">
        <div class="flex items-center space-x-3">
            <button id="mobileSidebarToggle" onclick="toggleSidebar()" class="lg:hidden p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition">
                <i class="fa-solid fa-bars text-lg"></i>
            </button>
            <div class="h-9 w-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400 shadow-md">
                <i class="fa-solid fa-vault text-lg"></i>
            </div>
            <div>
                <h1 class="text-base sm:text-lg font-bold text-white tracking-wider flex items-center space-x-2">
                    <span>ENTERPRISE VAULT</span>
                    <span class="text-xs font-mono font-normal bg-purple-500/20 text-purple-300 border border-purple-500/40 px-2 py-0.5 rounded">CROWN JEWELS</span>
                </h1>
                <p class="text-[10px] font-mono text-slate-400 tracking-wider">MANDATORY ACCESS CONTROL (MAC) &bull; ROLE-BASED ACCESS CONTROL (RBAC)</p>
            </div>
        </div>

        <div class="flex items-center space-x-3 text-xs">
            <!-- Clearance Pill -->
            <div class="flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-700 font-mono">
                <span class="text-slate-400">Clearance:</span>
                <?php if ($tier_numeric === 3): ?>
                    <span class="text-purple-400 font-bold flex items-center"><i class="fa-solid fa-gem mr-1 text-[11px]"></i> TIER 3 (TOP SECRET)</span>
                <?php elseif ($tier_numeric === 2): ?>
                    <span class="text-cyan-400 font-bold flex items-center"><i class="fa-solid fa-file-shield mr-1 text-[11px]"></i> TIER 2 (CONFIDENTIAL)</span>
                <?php else: ?>
                    <span class="text-amber-400 font-bold flex items-center"><i class="fa-solid fa-id-badge mr-1 text-[11px]"></i> TIER 1 (RESTRICTED)</span>
                <?php endif; ?>
            </div>

            <!-- Identity Pill -->
            <div class="hidden md:flex items-center space-x-2 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-700 font-mono text-slate-400">
                <i class="fa-solid fa-user-shield text-blue-400"></i>
                <span class="text-white font-medium"><?php echo htmlspecialchars($user_name); ?></span>
                <span class="text-slate-600">|</span>
                <span class="text-emerald-400 font-semibold">UID-<?php echo str_pad($current_user_id, 4, '0', STR_PAD_LEFT); ?></span>
            </div>

            <a href="logout.php" class="font-semibold text-red-400 hover:text-red-300 transition flex items-center bg-red-950/30 hover:bg-red-950/50 border border-red-500/30 px-2.5 py-1.5 rounded-lg">
                <i class="fa-solid fa-arrow-right-from-bracket mr-1.5"></i> Logout
            </a>
        </div>
    </nav>

    <!-- Main Container With Unified Responsive Sidebar -->
    <div class="flex-1 flex overflow-hidden">

        <!-- Sidebar Navigation Drawer -->
        <aside id="appSidebar" class="fixed inset-y-0 left-0 z-40 w-64 bg-slate-900/95 backdrop-blur-md border-r border-slate-800 flex flex-col transition-transform duration-300 -translate-x-full lg:translate-x-0 lg:static lg:z-auto">
            
            <!-- Sidebar Header / Current Profile Card -->
            <div class="p-4 border-b border-slate-800">
                <div class="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
                    <div class="flex items-center space-x-3 mb-2">
                        <div class="h-10 w-10 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400 font-bold text-sm">
                            <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                        </div>
                        <div class="overflow-hidden">
                            <h4 class="text-xs font-bold text-white truncate"><?php echo htmlspecialchars($user_name); ?></h4>
                            <p class="text-[11px] font-mono text-slate-400 truncate"><?php echo htmlspecialchars($user_title); ?></p>
                        </div>
                    </div>
                    <div class="flex items-center justify-between text-[10px] font-mono pt-2 border-t border-slate-800/80">
                        <span class="text-slate-500">Dept:</span>
                        <span class="text-slate-300 truncate max-w-[130px]"><?php echo htmlspecialchars($user_dept); ?></span>
                    </div>
                    <div class="flex items-center justify-between text-[10px] font-mono pt-1">
                        <span class="text-slate-500">Role:</span>
                        <span class="text-blue-400 font-bold"><?php echo htmlspecialchars($user_role); ?></span>
                    </div>
                </div>
            </div>

            <!-- Navigation Links -->
            <nav class="flex-1 p-3 space-y-1.5 overflow-y-auto custom-scrollbar text-xs">
                <div class="px-3 py-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
                    Core Operations
                </div>

                <a href="dashboard.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition group">
                    <i class="fa-solid fa-gauge-high w-4 text-center text-slate-500 group-hover:text-blue-400 transition"></i>
                    <span class="font-medium">SOC Command Center</span>
                </a>

                <a href="vault.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg bg-purple-500/10 text-purple-300 border border-purple-500/30 font-semibold shadow-sm">
                    <i class="fa-solid fa-vault w-4 text-center text-purple-400"></i>
                    <span>Secure Vault (Crown Jewels)</span>
                    <span class="ml-auto text-[9px] font-mono bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded uppercase">RBAC</span>
                </a>

                <a href="api_management.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition group">
                    <i class="fa-solid fa-key w-4 text-center text-slate-500 group-hover:text-amber-400 transition"></i>
                    <span class="font-medium">API Management</span>
                </a>

                <div class="pt-4 px-3 py-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
                    Identity & Security
                </div>

                <a href="setup_mfa.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition group">
                    <i class="fa-solid fa-mobile-screen-button w-4 text-center text-slate-500 group-hover:text-emerald-400 transition"></i>
                    <span class="font-medium">Multi-Factor Auth (MFA)</span>
                </a>

                <a href="dashboard.php?export=csv" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition group">
                    <i class="fa-solid fa-file-csv w-4 text-center text-slate-500 group-hover:text-cyan-400 transition"></i>
                    <span class="font-medium">Export Audit Ledger</span>
                </a>
            </nav>

            <!-- Sidebar Footer Security Status -->
            <div class="p-3 border-t border-slate-800 text-[11px] font-mono text-slate-500">
                <div class="flex items-center space-x-2 text-emerald-400 mb-1">
                    <span class="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
                    <span class="font-bold">Zero-Trust Active</span>
                </div>
                <div class="truncate text-[10px]">TLS 1.3 &bull; SHA256 MAC Enforced</div>
            </div>
        </aside>

        <!-- Sidebar Backdrop for Mobile -->
        <div id="sidebarBackdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 hidden lg:hidden"></div>

        <!-- Main Workspace Area -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">

            <?php if (!empty($feedback_msg)) echo $feedback_msg; ?>

            <!-- Page Header -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-8 gap-4 border-b border-slate-800 pb-6">
                <div>
                    <div class="flex items-center space-x-2 mb-2">
                        <span class="px-2.5 py-1 text-[10px] font-mono font-bold uppercase rounded-md bg-purple-500/20 text-purple-300 border border-purple-500/40">
                            Enterprise Asset Protection Layer
                        </span>
                        <span class="text-xs text-slate-500 font-mono">&bull; Zero-Trust Access Gateway</span>
                    </div>
                    <h2 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Protected Resources: "The Crown Jewels"</h2>
                    <p class="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl">
                        Simulating the mission-critical assets of the enterprise. Enforcing dynamic 
                        <strong>Role-Based Access Control (RBAC)</strong> and <strong>Clearance Tiers</strong>. 
                        All interactions, both legitimate and unauthorized, generate cryptographic audit events.
                    </p>
                </div>

                <!-- Fast User Simulator Switcher (For Final Defense Demonstration) -->
                <div class="bg-slate-900 border border-slate-800 p-3 rounded-xl flex items-center space-x-3 shadow-md">
                    <div class="text-right">
                        <p class="text-[10px] font-mono uppercase text-slate-400 font-semibold">Active Identity State</p>
                        <p class="text-xs font-bold text-white"><?php echo htmlspecialchars($user_role); ?> (<?php echo htmlspecialchars($user_clearance); ?>)</p>
                    </div>
                    <div class="h-8 w-[1px] bg-slate-700"></div>
                    <a href="dashboard.php" class="text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center bg-blue-950/40 border border-blue-500/30 px-3 py-1.5 rounded-lg transition" title="Modify Clearance or User Roles in Command Center">
                        <i class="fa-solid fa-sliders mr-1.5"></i> Change Role
                    </a>
                </div>
            </div>

            <!-- Clearance Tier Matrix Card (Defense Visualizer) -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <!-- Tier 1 Overview -->
                <div class="bg-slate-900/60 p-4 rounded-xl border <?php echo ($tier_numeric === 1) ? 'border-amber-500/60 bg-amber-950/10 shadow-lg' : 'border-slate-800'; ?>">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-mono font-bold text-amber-400 flex items-center">
                            <i class="fa-solid fa-id-badge mr-1.5"></i> TIER 1 // RESTRICTED
                        </span>
                        <?php if ($tier_numeric === 1): ?>
                            <span class="text-[9px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded font-bold">YOUR LEVEL</span>
                        <?php endif; ?>
                    </div>
                    <p class="text-xs font-semibold text-white">Staff / General Employees</p>
                    <p class="text-[11px] text-slate-400 mt-1">General operational tools. Access to sensitive PII, executive financials, and SSH keys is strictly BLOCKED.</p>
                </div>

                <!-- Tier 2 Overview -->
                <div class="bg-slate-900/60 p-4 rounded-xl border <?php echo ($tier_numeric === 2) ? 'border-cyan-500/60 bg-cyan-950/10 shadow-lg' : 'border-slate-800'; ?>">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-mono font-bold text-cyan-400 flex items-center">
                            <i class="fa-solid fa-file-shield mr-1.5"></i> TIER 2 // CONFIDENTIAL
                        </span>
                        <?php if ($tier_numeric === 2): ?>
                            <span class="text-[9px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded font-bold">YOUR LEVEL</span>
                        <?php endif; ?>
                    </div>
                    <p class="text-xs font-semibold text-white">Auditors & Compliance Officers</p>
                    <p class="text-[11px] text-slate-400 mt-1">Read/inspect privileges for Customer PII records and Corporate Financial ledgers. Production SSH root keys locked.</p>
                </div>

                <!-- Tier 3 Overview -->
                <div class="bg-slate-900/60 p-4 rounded-xl border <?php echo ($tier_numeric === 3) ? 'border-purple-500/60 bg-purple-950/10 shadow-lg' : 'border-slate-800'; ?>">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs font-mono font-bold text-purple-400 flex items-center">
                            <i class="fa-solid fa-gem mr-1.5"></i> TIER 3 // TOP SECRET
                        </span>
                        <?php if ($tier_numeric === 3): ?>
                            <span class="text-[9px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40 px-2 py-0.5 rounded font-bold">YOUR LEVEL</span>
                        <?php endif; ?>
                    </div>
                    <p class="text-xs font-semibold text-white">SOC Administrators & CISOs</p>
                    <p class="text-[11px] text-slate-400 mt-1">Unrestricted administrative clearance across all enterprise resources, cryptographic keys, bastions, and telemetry.</p>
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
                <div class="bg-slate-900/80 rounded-2xl border <?php echo $can_access_pii ? 'border-cyan-500/40 shadow-xl' : 'border-red-500/40 bg-red-950/5'; ?> flex flex-col justify-between overflow-hidden relative group">
                    
                    <!-- Top Ribbon -->
                    <div class="p-5 border-b <?php echo $can_access_pii ? 'border-cyan-500/20 bg-cyan-950/20' : 'border-red-500/20 bg-red-950/30'; ?> flex justify-between items-center">
                        <div class="flex items-center space-x-2.5">
                            <div class="h-10 w-10 rounded-xl <?php echo $can_access_pii ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'; ?> flex items-center justify-center text-lg">
                                <i class="fa-solid <?php echo $can_access_pii ? 'fa-id-card' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="text-base font-bold text-white">Customer PII Database</h3>
                                <p class="text-[10px] font-mono text-slate-400 uppercase">Class: CONFIDENTIAL // TIER 2+</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-mono font-bold px-2.5 py-1 rounded-md <?php echo $can_access_pii ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'; ?>">
                            <?php echo $can_access_pii ? 'CLEARED' : 'LOCKED'; ?>
                        </span>
                    </div>

                    <!-- Body Content -->
                    <div class="p-5 flex-1 space-y-4">
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Encrypted relational cluster storing 45,820 customer identity records, Social Security/National ID numbers, cryptographic session tokens, and PCI-DSS billing hashes.
                        </p>

                        <!-- Mock Data Preview / Lock Overlay -->
                        <div class="bg-slate-950 rounded-xl p-3 border border-slate-800 text-[11px] font-mono relative overflow-hidden">
                            <?php if (!$can_access_pii): ?>
                                <!-- Red Denied Overlay -->
                                <div class="absolute inset-0 bg-red-950/90 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/50">
                                    <div class="h-10 w-10 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center text-red-400 mb-2">
                                        <i class="fa-solid fa-ban text-lg"></i>
                                    </div>
                                    <h4 class="text-xs font-bold text-red-400 tracking-wider">ACCESS DENIED: INSUFFICIENT CLEARANCE</h4>
                                    <p class="text-[10px] text-red-300/80 mt-1 max-w-[200px]">Requires Tier 2 (Auditor) or Tier 3 (Admin). Your clearance: <?php echo htmlspecialchars($user_clearance); ?>.</p>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_pii ? 'filter blur-sm select-none opacity-40' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-slate-800 pb-1">
                                    <span>Record UUID</span>
                                    <span>Identity Token</span>
                                    <span>Encryption</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-cyan-400">UID-9481-C</span>
                                    <span>Sophia Vance (SSN: ***-**-8192)</span>
                                    <span class="text-emerald-400">AES-256</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-cyan-400">UID-9482-D</span>
                                    <span>Marcus Chen (SSN: ***-**-3341)</span>
                                    <span class="text-emerald-400">AES-256</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-cyan-400">UID-9483-E</span>
                                    <span>Elena Rostova (SSN: ***-**-5109)</span>
                                    <span class="text-emerald-400">AES-256</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                            <span>Compliance: <span class="text-slate-300">GDPR / ISO-27001</span></span>
                            <span>Records: <span class="text-cyan-400 font-bold">45,820</span></span>
                        </div>
                    </div>

                    <!-- Footer Action Buttons -->
                    <div class="p-5 bg-slate-950/60 border-t border-slate-800/80">
                        <?php if ($can_access_pii): ?>
                            <div class="grid grid-cols-2 gap-2">
                                <button onclick="openModal('piiModal')" class="w-full bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center">
                                    <i class="fa-solid fa-eye mr-1.5 text-cyan-400"></i> Inspect PII
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="inspect">
                                    <input type="hidden" name="resource_id" value="res_pii">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center">
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
                                <button type="submit" class="w-full bg-red-950/40 hover:bg-red-900/50 text-red-400 border border-red-500/40 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center group">
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
                <div class="bg-slate-900/80 rounded-2xl border <?php echo $can_access_fin ? 'border-emerald-500/40 shadow-xl' : 'border-red-500/40 bg-red-950/5'; ?> flex flex-col justify-between overflow-hidden relative group">
                    
                    <!-- Top Ribbon -->
                    <div class="p-5 border-b <?php echo $can_access_fin ? 'border-emerald-500/20 bg-emerald-950/20' : 'border-red-500/20 bg-red-950/30'; ?> flex justify-between items-center">
                        <div class="flex items-center space-x-2.5">
                            <div class="h-10 w-10 rounded-xl <?php echo $can_access_fin ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'; ?> flex items-center justify-center text-lg">
                                <i class="fa-solid <?php echo $can_access_fin ? 'fa-chart-pie' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="text-base font-bold text-white">Q3 Corporate Financials</h3>
                                <p class="text-[10px] font-mono text-slate-400 uppercase">Class: RESTRICTED FINANCIAL // TIER 2+</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-mono font-bold px-2.5 py-1 rounded-md <?php echo $can_access_fin ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'; ?>">
                            <?php echo $can_access_fin ? 'CLEARED' : 'LOCKED'; ?>
                        </span>
                    </div>

                    <!-- Body Content -->
                    <div class="p-5 flex-1 space-y-4">
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Consolidated corporate treasury ledgers, Q3 net revenue performance ($14.2M), EBITDA forecasts, executive salary matrix, and bank wire routing authorizations.
                        </p>

                        <!-- Mock Data Preview / Lock Overlay -->
                        <div class="bg-slate-950 rounded-xl p-3 border border-slate-800 text-[11px] font-mono relative overflow-hidden">
                            <?php if (!$can_access_fin): ?>
                                <!-- Red Denied Overlay -->
                                <div class="absolute inset-0 bg-red-950/90 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/50">
                                    <div class="h-10 w-10 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center text-red-400 mb-2">
                                        <i class="fa-solid fa-ban text-lg"></i>
                                    </div>
                                    <h4 class="text-xs font-bold text-red-400 tracking-wider">ACCESS DENIED: INSUFFICIENT CLEARANCE</h4>
                                    <p class="text-[10px] text-red-300/80 mt-1 max-w-[200px]">Requires Tier 2 (Auditor) or Tier 3 (Admin). Your clearance: <?php echo htmlspecialchars($user_clearance); ?>.</p>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_fin ? 'filter blur-sm select-none opacity-40' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-slate-800 pb-1">
                                    <span>Fiscal Category</span>
                                    <span>Q3 Realized</span>
                                    <span>EBITDA Margin</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-emerald-400">Gross Enterprise ARR</span>
                                    <span class="font-bold">$14,210,000</span>
                                    <span class="text-emerald-400">+28.4%</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-emerald-400">R&D / SOC Security</span>
                                    <span>$3,190,000</span>
                                    <span class="text-cyan-400">Allocated</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-emerald-400">Corporate Treasury Cash</span>
                                    <span>$8,450,000</span>
                                    <span class="text-emerald-400">Audited</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                            <span>Audit Standard: <span class="text-slate-300">SOX-404 / GAAP</span></span>
                            <span>Ledger Status: <span class="text-emerald-400 font-bold">BALANCED</span></span>
                        </div>
                    </div>

                    <!-- Footer Action Buttons -->
                    <div class="p-5 bg-slate-950/60 border-t border-slate-800/80">
                        <?php if ($can_access_fin): ?>
                            <div class="grid grid-cols-2 gap-2">
                                <button onclick="openModal('finModal')" class="w-full bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center">
                                    <i class="fa-solid fa-chart-line mr-1.5 text-emerald-400"></i> View Ledger
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="download_fin_csv">
                                    <input type="hidden" name="resource_id" value="res_fin">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center">
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
                                <button type="submit" class="w-full bg-red-950/40 hover:bg-red-900/50 text-red-400 border border-red-500/40 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center group">
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
                <div class="bg-slate-900/80 rounded-2xl border <?php echo $can_access_ssh ? 'border-purple-500/40 shadow-xl' : 'border-red-500/40 bg-red-950/5'; ?> flex flex-col justify-between overflow-hidden relative group">
                    
                    <!-- Top Ribbon -->
                    <div class="p-5 border-b <?php echo $can_access_ssh ? 'border-purple-500/20 bg-purple-950/20' : 'border-red-500/20 bg-red-950/30'; ?> flex justify-between items-center">
                        <div class="flex items-center space-x-2.5">
                            <div class="h-10 w-10 rounded-xl <?php echo $can_access_ssh ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40' : 'bg-red-500/20 text-red-400 border border-red-500/40'; ?> flex items-center justify-center text-lg">
                                <i class="fa-solid <?php echo $can_access_ssh ? 'fa-key' : 'fa-lock'; ?>"></i>
                            </div>
                            <div>
                                <h3 class="text-base font-bold text-white">Production Server SSH Keys</h3>
                                <p class="text-[10px] font-mono text-slate-400 uppercase">Class: TOP SECRET // TIER 3 ADMIN ONLY</p>
                            </div>
                        </div>
                        <span class="text-[10px] font-mono font-bold px-2.5 py-1 rounded-md <?php echo $can_access_ssh ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'; ?>">
                            <?php echo $can_access_ssh ? 'CLEARED' : 'LOCKED'; ?>
                        </span>
                    </div>

                    <!-- Body Content -->
                    <div class="p-5 flex-1 space-y-4">
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Root Ed25519 cryptographic private key pairs granting root shell authorization into Kubernetes core control planes, AWS production VPCs, and database clusters.
                        </p>

                        <!-- Mock Data Preview / Lock Overlay -->
                        <div class="bg-slate-950 rounded-xl p-3 border border-slate-800 text-[11px] font-mono relative overflow-hidden">
                            <?php if (!$can_access_ssh): ?>
                                <!-- Red Denied Overlay -->
                                <div class="absolute inset-0 bg-red-950/90 backdrop-blur-xs flex flex-col items-center justify-center p-4 text-center z-10 border border-red-500/50">
                                    <div class="h-10 w-10 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center text-red-400 mb-2">
                                        <i class="fa-solid fa-shield-halved text-lg"></i>
                                    </div>
                                    <h4 class="text-xs font-bold text-red-400 tracking-wider">ACCESS DENIED: INSUFFICIENT CLEARANCE</h4>
                                    <p class="text-[10px] text-red-300/80 mt-1 max-w-[200px]">Requires Tier 3 (Super Admin / CISO). Even Tier 2 Auditors are blocked from raw root credentials.</p>
                                </div>
                            <?php endif; ?>

                            <div class="space-y-1.5 <?php echo !$can_access_ssh ? 'filter blur-sm select-none opacity-40' : ''; ?>">
                                <div class="flex justify-between text-slate-500 border-b border-slate-800 pb-1">
                                    <span>Target Host</span>
                                    <span>Cipher / Fingerprint</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-purple-400">k8s-prod-master-01</span>
                                    <span>SHA256:4X7mQ9p...</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-purple-400">bastion-east.defense.net</span>
                                    <span>SHA256:1v98Kll...</span>
                                </div>
                                <div class="flex justify-between text-slate-300">
                                    <span class="text-purple-400">mariadb-cluster-node-01</span>
                                    <span>SHA256:9a32Zxc...</span>
                                </div>
                            </div>
                        </div>

                        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                            <span>Cipher: <span class="text-slate-300">Ed25519 (OpenSSH)</span></span>
                            <span>Key Strength: <span class="text-purple-400 font-bold">MIL-SPEC 256-BIT</span></span>
                        </div>
                    </div>

                    <!-- Footer Action Buttons -->
                    <div class="p-5 bg-slate-950/60 border-t border-slate-800/80">
                        <?php if ($can_access_ssh): ?>
                            <div class="grid grid-cols-2 gap-2">
                                <button onclick="openModal('sshModal')" class="w-full bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/40 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center">
                                    <i class="fa-solid fa-terminal mr-1.5 text-purple-400"></i> View Key Pair
                                </button>
                                <form method="POST" action="" class="w-full">
                                    <input type="hidden" name="vault_action" value="download_ssh">
                                    <input type="hidden" name="resource_id" value="res_ssh">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center">
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
                                <button type="submit" class="w-full bg-red-950/40 hover:bg-red-900/50 text-red-400 border border-red-500/40 py-2 px-3 rounded-lg text-xs font-semibold transition flex items-center justify-center group">
                                    <i class="fa-solid fa-lock mr-2 text-red-500 group-hover:scale-110 transition"></i>
                                    <span>Access Locked (Trigger Violation)</span>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>

            </div>

            <!-- AUDIT STREAM SNAPSHOT (Protected Resources Activity) -->
            <div class="bg-slate-900/70 rounded-2xl border border-slate-800 p-6 shadow-xl">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center space-x-2 text-white">
                        <i class="fa-solid fa-shield-halved text-blue-400 text-base"></i>
                        <h3 class="text-sm font-bold tracking-wide">Protected Resources Live Audit Stream</h3>
                    </div>
                    <span class="text-[10px] font-mono text-slate-500">Immutable Ledger Filtering: Vault Events</span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs font-mono">
                        <thead class="bg-slate-950 text-slate-400 text-[11px] uppercase tracking-wider">
                            <tr>
                                <th class="px-4 py-3">Timestamp</th>
                                <th class="px-4 py-3">Event Type</th>
                                <th class="px-4 py-3">Target Identity</th>
                                <th class="px-4 py-3">Security Action & Description</th>
                                <th class="px-4 py-3 text-right">Client IP</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800">
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
                            <tr class="hover:bg-slate-800/40 transition">
                                <td class="px-4 py-3 text-slate-500 whitespace-nowrap"><?php echo htmlspecialchars($vl['created_at']); ?></td>
                                <td class="px-4 py-3 whitespace-nowrap">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold <?php echo $is_denied ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'; ?>">
                                        <?php echo htmlspecialchars($vl['action_type']); ?>
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-slate-300 whitespace-nowrap"><?php echo htmlspecialchars($vl['email'] ?? 'UID-' . $vl['user_id']); ?></td>
                                <td class="px-4 py-3 text-slate-400"><?php echo htmlspecialchars($vl['action_description']); ?></td>
                                <td class="px-4 py-3 text-slate-500 text-right whitespace-nowrap"><?php echo htmlspecialchars($vl['ip_address']); ?></td>
                            </tr>
                            <?php 
                                endwhile;
                            else:
                            ?>
                            <tr>
                                <td colspan="5" class="px-4 py-6 text-center text-slate-500">No vault security actions logged yet. Access a resource above to trigger events.</td>
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
    <div id="piiModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm flex justify-center items-center z-50 p-4">
        <div class="bg-slate-900 border border-cyan-500/40 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2 text-cyan-400">
                    <i class="fa-solid fa-id-card text-lg"></i>
                    <h3 class="font-bold text-white text-base">Customer PII Database &bull; Decrypted View</h3>
                </div>
                <button onclick="closeModal('piiModal')" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <p class="text-xs text-slate-400">
                Identity records decrypted via ephemeral session token. Clearance Level 
                <strong class="text-cyan-400"><?php echo htmlspecialchars($user_clearance); ?></strong> verified.
            </p>
            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left text-xs font-mono">
                    <thead class="bg-slate-950 text-slate-400">
                        <tr>
                            <th class="p-3">Customer ID</th>
                            <th class="p-3">Full Name</th>
                            <th class="p-3">Decrypted National ID</th>
                            <th class="p-3">Billing Country</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800 text-slate-300">
                        <tr>
                            <td class="p-3 text-cyan-400">CUST-8491</td>
                            <td class="p-3 font-semibold text-white">Sophia Vance</td>
                            <td class="p-3 text-emerald-400">928-44-8192</td>
                            <td class="p-3">United Kingdom</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-cyan-400">CUST-8492</td>
                            <td class="p-3 font-semibold text-white">Marcus Chen</td>
                            <td class="p-3 text-emerald-400">419-82-3341</td>
                            <td class="p-3">Canada</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-cyan-400">CUST-8493</td>
                            <td class="p-3 font-semibold text-white">Elena Rostova</td>
                            <td class="p-3 text-emerald-400">810-19-5109</td>
                            <td class="p-3">Germany</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-cyan-400">CUST-8494</td>
                            <td class="p-3 font-semibold text-white">Tariq Al-Mansoor</td>
                            <td class="p-3 text-emerald-400">552-30-7714</td>
                            <td class="p-3">United Arab Emirates</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="flex justify-end pt-2">
                <button onclick="closeModal('piiModal')" class="bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold px-4 py-2 rounded-lg transition">
                    Close Inspection
                </button>
            </div>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 2: VIEW Q3 CORPORATE FINANCIAL LEDGER                   -->
    <!-- ============================================================== -->
    <div id="finModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm flex justify-center items-center z-50 p-4">
        <div class="bg-slate-900 border border-emerald-500/40 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2 text-emerald-400">
                    <i class="fa-solid fa-chart-pie text-lg"></i>
                    <h3 class="font-bold text-white text-base">Q3 Financial Operating Statement &bull; Executive Ledger</h3>
                </div>
                <button onclick="closeModal('finModal')" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <div class="grid grid-cols-2 gap-3 text-xs font-mono">
                <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span class="text-slate-500">Gross Operating ARR:</span>
                    <p class="text-lg font-bold text-emerald-400">$14,210,000</p>
                </div>
                <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span class="text-slate-500">Net EBITDA Profit:</span>
                    <p class="text-lg font-bold text-cyan-400">$4,850,000 (34.1%)</p>
                </div>
            </div>
            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left text-xs font-mono">
                    <thead class="bg-slate-950 text-slate-400">
                        <tr>
                            <th class="p-3">Department</th>
                            <th class="p-3">Allocated Outlay</th>
                            <th class="p-3">Auditor Signature</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800 text-slate-300">
                        <tr>
                            <td class="p-3 text-white font-semibold">Security Operations & IAM</td>
                            <td class="p-3 text-emerald-400">$1,850,000</td>
                            <td class="p-3 text-slate-400">VERIFIED // SOX-2026</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-white font-semibold">Cloud Compute Infrastructure</td>
                            <td class="p-3 text-emerald-400">$2,400,000</td>
                            <td class="p-3 text-slate-400">VERIFIED // SOX-2026</td>
                        </tr>
                        <tr>
                            <td class="p-3 text-white font-semibold">Legal, Privacy & Compliance</td>
                            <td class="p-3 text-emerald-400">$720,000</td>
                            <td class="p-3 text-slate-400">VERIFIED // SOX-2026</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div class="flex justify-end pt-2">
                <button onclick="closeModal('finModal')" class="bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold px-4 py-2 rounded-lg transition">
                    Close Ledger
                </button>
            </div>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- MODAL 3: VIEW PRODUCTION SSH PRIVATE KEY                      -->
    <!-- ============================================================== -->
    <div id="sshModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm flex justify-center items-center z-50 p-4">
        <div class="bg-slate-900 border border-purple-500/40 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2 text-purple-400">
                    <i class="fa-solid fa-terminal text-lg"></i>
                    <h3 class="font-bold text-white text-base">Production Root Infrastructure Key Pair (Ed25519)</h3>
                </div>
                <button onclick="closeModal('sshModal')" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            <div class="bg-purple-950/20 border border-purple-500/30 p-3 rounded-lg text-xs text-purple-300 font-mono">
                <i class="fa-solid fa-triangle-exclamation mr-1.5"></i> TOP SECRET PRIVILEGED ASSET: Raw key exposed only to UID-<?php echo $current_user_id; ?> (CISO/Admin).
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
                <button onclick="copySSHKey()" id="copyKeyBtn" class="bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition flex items-center">
                    <i class="fa-solid fa-copy mr-1.5"></i> Copy Private Key
                </button>
                <button onclick="closeModal('sshModal')" class="bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold px-4 py-2 rounded-lg transition">
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
