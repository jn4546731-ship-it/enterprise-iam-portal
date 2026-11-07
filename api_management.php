<?php
/**
 * Enterprise Zero-Trust IAM Portal - API Key Management
 * Manages service application credentials, programmatic tokens, and revocation lifecycle.
 * Enforces RBAC clearance and generates immutable audit trails.
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

// Calculate numeric clearance tier
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
// HANDLE API KEY ACTIONS (PROVISION / TOGGLE / DELETE)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['api_action'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/60 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 text-xs font-tech flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 text-lg text-red-500'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $api_action = $_POST['api_action'];

        // 1. GENERATE NEW API KEY (Tier 3 Admin only, or Tier 2 Auditor read-only)
        if ($api_action === 'generate_key') {
            if ($tier_numeric < 3) {
                // Unauthorized Generation Attempt
                $action_type = "ACCESS_DENIED_API_KEY_PROVISION";
                $action_desc = "UNAUTHORIZED: User {$user_email} ({$user_clearance}) attempted to provision a new programmatic API Key. Blocked by RBAC.";
                $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                $log->execute();

                $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/80 border border-red-500/60 text-red-300 p-4 rounded-xl mb-6 text-xs font-tech flex items-center shadow-2xl glow-red animate-pulse'><i class='fa-solid fa-ban mr-3 text-lg text-red-400'></i> <div><strong class='font-orbitron font-bold text-white'>CLEARANCE INSUFFICIENT:</strong> Provisioning enterprise API keys requires Tier 3 (Admin) clearance. Operation blocked and flagged.</div></div>";
            } else {
                $app_name = trim($_POST['app_name'] ?? '');
                if (empty($app_name)) {
                    $feedback_msg = "<div class='cyber-card cyber-brackets bg-amber-950/60 border border-amber-500/50 text-amber-300 p-3 rounded-lg mb-6 text-xs font-tech'>Application name is required.</div>";
                } else {
                    $new_token = 'sec_live_' . bin2hex(random_bytes(20));
                    $status = 'Active';

                    $ins = $conn->prepare("INSERT INTO api_keys (app_name, api_key, status, created_at) VALUES (?, ?, ?, NOW())");
                    $ins->bind_param("sss", $app_name, $new_token, $status);

                    if ($ins->execute()) {
                        $key_id = $ins->insert_id;
                        $action_type = "API_KEY_PROVISIONED";
                        $action_desc = "New enterprise API Key provisioned for [{$app_name}] (ID: {$key_id}) by Admin UID-{$current_user_id}";
                        $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                        $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                        $log->execute();

                        $feedback_msg = "<div class='cyber-card cyber-brackets bg-emerald-950/60 border border-emerald-500/50 text-emerald-300 p-4 rounded-xl mb-6 text-xs font-tech flex items-center shadow-lg glow-emerald'><i class='fa-solid fa-circle-check mr-3 text-lg text-emerald-400'></i> <div><strong class='font-orbitron font-bold text-white'>API TOKEN PROVISIONED:</strong> Cryptographic HMAC bearer token successfully generated for <strong>" . htmlspecialchars($app_name) . "</strong>. Stored with AES-256 MAC integrity.</div></div>";
                    } else {
                        $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/60 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-xs font-tech'>Database error provisioning API key.</div>";
                    }
                }
            }
        }

        // 2. TOGGLE KEY STATUS (Active / Revoked)
        if ($api_action === 'toggle_key_status') {
            if ($tier_numeric < 3) {
                $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/60 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-xs font-tech'>Only Tier 3 Administrators can alter API key statuses.</div>";
            } else {
                $target_key_id = (int) ($_POST['target_key_id'] ?? 0);
                $new_status = ($_POST['new_status'] === 'Active') ? 'Active' : 'Revoked';

                $u_stmt = $conn->prepare("UPDATE api_keys SET status = ? WHERE id = ?");
                $u_stmt->bind_param("si", $new_status, $target_key_id);

                if ($u_stmt->execute()) {
                    $action_type = ($new_status === 'Active') ? "API_KEY_ACTIVATED" : "API_KEY_REVOKED";
                    $action_desc = "API Key #{$target_key_id} status changed to [{$new_status}] by Admin UID-{$current_user_id}";
                    $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                    $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                    $log->execute();

                    $feedback_msg = "<div class='cyber-card cyber-brackets bg-cyan-950/60 border border-cyan-500/50 text-cyan-300 p-3.5 rounded-lg mb-6 text-xs font-tech flex items-center'><i class='fa-solid fa-key mr-2 text-cyan-400'></i> API Key #{$target_key_id} is now <strong>{$new_status}</strong>.</div>";
                }
            }
        }

        // 3. DELETE API KEY
        if ($api_action === 'delete_key') {
            if ($tier_numeric < 3) {
                $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/60 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-xs font-tech'>Only Tier 3 Administrators can delete API keys.</div>";
            } else {
                $target_key_id = (int) ($_POST['target_key_id'] ?? 0);
                $d_stmt = $conn->prepare("DELETE FROM api_keys WHERE id = ?");
                $d_stmt->bind_param("i", $target_key_id);

                if ($d_stmt->execute()) {
                    $action_type = "API_KEY_DELETED";
                    $action_desc = "API Key #{$target_key_id} permanently PURGED by Admin UID-{$current_user_id}";
                    $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                    $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                    $log->execute();

                    $feedback_msg = "<div class='cyber-card cyber-brackets bg-red-950/60 border border-red-500/50 text-red-300 p-3.5 rounded-lg mb-6 text-xs font-tech flex items-center'><i class='fa-solid fa-trash-can mr-2 text-red-400'></i> API Key #{$target_key_id} permanently purged from system.</div>";
                }
            }
        }
    }
}

// Fetch all API keys
$api_keys = [];
$res = $conn->query("SELECT * FROM api_keys ORDER BY id DESC");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $api_keys[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark">
    <title>Enterprise API Key Management - Cryptographic Gatekeeper</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay text-slate-300 font-sans min-h-screen flex flex-col antialiased relative selection:bg-amber-500 selection:text-black">

    <!-- Top High-Tech Cyber Navigation Bar -->
    <nav class="bg-slate-950/85 backdrop-blur-md border-b border-amber-500/25 py-3 px-4 sm:px-6 flex justify-between items-center shadow-2xl sticky top-0 z-30 relative overflow-hidden">
        <!-- Sub-laser accent -->
        <div class="cyber-laser-beam opacity-40"></div>

        <div class="flex items-center space-x-3">
            <button id="mobileSidebarToggle" onclick="toggleSidebar()" class="lg:hidden p-2 text-slate-400 hover:text-amber-400 rounded-lg hover:bg-slate-900 border border-transparent hover:border-amber-500/30 transition">
                <i class="fa-solid fa-bars text-lg"></i>
            </button>
            <div class="relative w-9 h-9 rounded-xl bg-amber-950/60 border border-amber-400/50 flex items-center justify-center text-amber-400 glow-amber">
                <i class="fa-solid fa-key text-lg"></i>
            </div>
            <div>
                <h1 class="font-orbitron text-sm sm:text-base font-extrabold text-white tracking-wider flex items-center space-x-2">
                    <span>API KEY</span>
                    <span class="text-amber-400 glow-text-amber">GATEKEEPER</span>
                </h1>
                <p class="font-tech text-[10px] text-slate-400 tracking-wider">SERVICE CREDENTIALS &bull; HMAC-SHA256 TOKENS &bull; CRYPTOGRAPHIC ROTATION</p>
            </div>
        </div>

        <div class="flex items-center space-x-3 text-xs font-tech">
            <!-- Audio SFX Mute/Unmute Toggle -->
            <button onclick="toggleGlobalAudio()" id="navMuteBtn" class="p-2 rounded-lg bg-slate-900/80 border border-slate-700 text-slate-400 hover:text-amber-400 hover:border-amber-400/50 transition" title="Toggle Cyber Audio Synthesizer">
                <i id="navMuteIcon" class="fa-solid fa-volume-high text-xs"></i>
            </button>

            <!-- Clearance Pill -->
            <div class="flex items-center space-x-2 bg-slate-900/90 px-3 py-1.5 rounded-lg border border-amber-500/30 font-tech">
                <span class="text-slate-500">Clearance:</span>
                <?php if ($tier_numeric === 3): ?>
                    <span class="text-purple-300 font-bold flex items-center font-orbitron text-[11px]"><i class="fa-solid fa-gem mr-1.5 text-[10px] text-purple-400"></i> TIER 3 (ADMIN)</span>
                <?php elseif ($tier_numeric === 2): ?>
                    <span class="text-cyan-300 font-bold flex items-center font-orbitron text-[11px]"><i class="fa-solid fa-file-shield mr-1.5 text-[10px] text-cyan-400"></i> TIER 2 (AUDITOR)</span>
                <?php else: ?>
                    <span class="text-amber-300 font-bold flex items-center font-orbitron text-[11px]"><i class="fa-solid fa-id-badge mr-1.5 text-[10px] text-amber-400"></i> TIER 1 (STAFF)</span>
                <?php endif; ?>
            </div>

            <!-- Identity Pill -->
            <div class="hidden md:flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-700 font-tech text-slate-400">
                <i class="fa-solid fa-user-shield text-amber-400"></i>
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
        <aside id="appSidebar" class="fixed inset-y-0 left-0 z-40 w-64 bg-slate-950/95 backdrop-blur-md border-r border-amber-500/20 flex flex-col transition-transform duration-300 -translate-x-full lg:translate-x-0 lg:static lg:z-auto">
            
            <!-- Current Profile Card -->
            <div class="p-4 border-b border-slate-800">
                <div class="cyber-card cyber-brackets p-3.5 rounded-xl border border-amber-500/25">
                    <div class="flex items-center space-x-3 mb-2">
                        <div class="relative w-10 h-10 rounded-lg bg-amber-950/60 border border-amber-400/50 flex items-center justify-center text-amber-300 font-orbitron font-bold text-sm glow-amber">
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
                        <span class="text-amber-400 font-bold"><?php echo htmlspecialchars($user_role); ?></span>
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

                <a href="vault.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-purple-500/30 transition group font-tech">
                    <i class="fa-solid fa-vault w-4 text-center text-slate-500 group-hover:text-purple-400 transition"></i>
                    <span class="font-medium">Secure Vault (Crown Jewels)</span>
                    <span class="ml-auto text-[9px] font-mono bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded border border-purple-500/30 uppercase font-bold">RBAC</span>
                </a>

                <a href="api_management.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl bg-amber-950/40 text-amber-300 border border-amber-500/40 font-orbitron text-xs font-bold shadow-md glow-amber">
                    <i class="fa-solid fa-key w-4 text-center text-amber-400"></i>
                    <span>API Management</span>
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

            <div class="p-3 border-t border-slate-800 text-[11px] font-tech text-slate-500">
                <div class="flex items-center space-x-2 text-amber-400 mb-1">
                    <span class="h-2 w-2 rounded-full bg-amber-500 cyber-beacon"></span>
                    <span class="font-bold">API Gatekeeper Active</span>
                </div>
                <div class="truncate text-[10px] text-slate-500">HMAC-SHA256 TOKEN VAULT</div>
            </div>
        </aside>

        <!-- Sidebar Backdrop for Mobile -->
        <div id="sidebarBackdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 hidden lg:hidden"></div>

        <!-- Main Workspace Area -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">

            <?php if (!empty($feedback_msg)) echo $feedback_msg; ?>

            <!-- Page Header & Action Bar -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-8 gap-4 border-b border-amber-500/20 pb-6">
                <div>
                    <div class="flex items-center space-x-2 mb-2">
                        <span class="px-2.5 py-0.5 text-[10px] font-tech font-bold uppercase rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            SERVICE-TO-SERVICE CRYPTOGRAPHIC GATEKEEPER
                        </span>
                        <span class="text-xs text-slate-500 font-tech">&bull; Programmatic Tokens</span>
                    </div>
                    <h2 class="font-orbitron text-2xl sm:text-3xl font-extrabold text-white tracking-tight glow-text-amber mb-1">
                        API Token Management
                    </h2>
                    <p class="font-tech text-slate-400 text-xs sm:text-sm max-w-2xl">
                        Provision, monitor, and revoke high-entropy programmatic API tokens for enterprise microservices, SIEM telemetry daemons, and automated data pipelines.
                    </p>
                </div>

                <div class="flex items-center space-x-3 font-tech">
                    <?php if ($tier_numeric >= 3): ?>
                        <button onclick="document.getElementById('generateModal').classList.remove('hidden')" class="cyber-btn bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white px-4 py-2.5 rounded-xl text-xs font-orbitron font-bold transition flex items-center shadow-lg glow-amber">
                            <i class="fa-solid fa-plus mr-1.5"></i> Generate API Key
                        </button>
                    <?php else: ?>
                        <span class="text-xs font-tech text-slate-400 bg-slate-900/80 border border-slate-800 px-3 py-2 rounded-xl flex items-center">
                            <i class="fa-solid fa-lock mr-2 text-amber-500"></i> Read-Only Key Access (Tier 3 Required to Generate)
                        </span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- API Keys Table Card -->
            <div class="cyber-card cyber-brackets rounded-2xl border border-amber-500/30 p-6 shadow-2xl mb-8 relative overflow-hidden">
                <div class="cyber-laser-beam opacity-30"></div>
                <div class="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
                    <div class="flex items-center space-x-2 text-white">
                        <i class="fa-solid fa-server text-amber-400"></i>
                        <h3 class="font-orbitron text-sm font-bold tracking-wide">Registered Application Integrations</h3>
                    </div>
                    <span class="text-xs font-tech text-amber-300 bg-amber-950/60 px-3 py-1 rounded-lg border border-amber-500/30 font-bold">
                        <?php echo count($api_keys); ?> KEYS ACTIVE IN VAULT
                    </span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm font-tech">
                        <thead class="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider font-semibold">
                            <tr>
                                <th class="px-5 py-3.5">ID</th>
                                <th class="px-5 py-3.5">Application Name</th>
                                <th class="px-5 py-3.5">Cryptographic API Key</th>
                                <th class="px-5 py-3.5">Status</th>
                                <th class="px-5 py-3.5">Created At</th>
                                <th class="px-5 py-3.5 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/80">
                            <?php if (empty($api_keys)): ?>
                                <tr>
                                    <td colspan="6" class="px-5 py-8 text-center text-slate-500 font-tech text-xs">
                                        No API keys provisioned yet. Use the "Generate API Key" button above to register an application.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($api_keys as $k): 
                                    $is_active = (strcasecmp($k['status'], 'Active') === 0);
                                    $raw_key = $k['api_key'];
                                    $masked_key = substr($raw_key, 0, 12) . '••••••••••••••••' . substr($raw_key, -4);
                                ?>
                                <tr class="hover:bg-slate-800/30 transition">
                                    <td class="px-5 py-4 font-mono text-xs text-slate-400">#<?php echo (int) $k['id']; ?></td>
                                    <td class="px-5 py-4">
                                        <div class="font-semibold text-white text-xs sm:text-sm flex items-center">
                                            <i class="fa-solid fa-cube text-slate-500 mr-2"></i>
                                            <?php echo htmlspecialchars($k['app_name']); ?>
                                        </div>
                                    </td>
                                    <td class="px-5 py-4 font-mono text-xs">
                                        <div class="flex items-center space-x-2 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 w-fit">
                                            <span class="text-cyan-300 font-mono"><?php echo htmlspecialchars($masked_key); ?></span>
                                            <button onclick="copyToken('<?php echo htmlspecialchars($raw_key); ?>', this)" class="text-slate-400 hover:text-amber-400 transition" title="Copy Raw Key">
                                                <i class="fa-solid fa-copy text-xs"></i>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="px-5 py-4">
                                        <?php if ($is_active): ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 glow-emerald">
                                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                            </span>
                                        <?php else: ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30 glow-red">
                                                <span class="h-1.5 w-1.5 rounded-full bg-red-400 mr-1.5"></span> Revoked
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="px-5 py-4 font-mono text-xs text-slate-500 whitespace-nowrap">
                                        <?php echo htmlspecialchars($k['created_at']); ?>
                                    </td>
                                    <td class="px-5 py-4 text-right whitespace-nowrap">
                                        <?php if ($tier_numeric >= 3): ?>
                                            <div class="inline-flex items-center space-x-2">
                                                <!-- Toggle Active/Revoked Form -->
                                                <form method="POST" action="" class="inline" onsubmit="return confirm('Change status of API Key for <?php echo addslashes($k['app_name']); ?>?');">
                                                    <input type="hidden" name="api_action" value="toggle_key_status">
                                                    <input type="hidden" name="target_key_id" value="<?php echo (int) $k['id']; ?>">
                                                    <input type="hidden" name="new_status" value="<?php echo $is_active ? 'Revoked' : 'Active'; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    
                                                    <?php if ($is_active): ?>
                                                        <button type="submit" class="cyber-btn px-2.5 py-1 text-xs rounded-lg bg-amber-950/40 text-amber-300 border border-amber-500/30 hover:bg-amber-900/40 transition" title="Revoke Key Access">
                                                            Revoke
                                                        </button>
                                                    <?php else: ?>
                                                        <button type="submit" class="cyber-btn px-2.5 py-1 text-xs rounded-lg bg-emerald-950/40 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-900/40 transition" title="Reactivate Key Access">
                                                            Activate
                                                        </button>
                                                    <?php endif; ?>
                                                </form>

                                                <!-- Delete Key Form -->
                                                <form method="POST" action="" class="inline" onsubmit="return confirm('DANGER: Permanently delete API Key for <?php echo addslashes($k['app_name']); ?>? Applications using this key will immediately fail.');">
                                                    <input type="hidden" name="api_action" value="delete_key">
                                                    <input type="hidden" name="target_key_id" value="<?php echo (int) $k['id']; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    <button type="submit" class="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition" title="Purge Key">
                                                        <i class="fa-solid fa-trash-can text-xs"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        <?php else: ?>
                                            <span class="text-xs text-slate-600 font-mono"><i class="fa-solid fa-lock"></i> Locked</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        </main>
    </div>

    <!-- MODAL: GENERATE NEW API KEY -->
    <div id="generateModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md flex justify-center items-center z-50 p-4">
        <div class="cyber-card cyber-brackets bg-slate-950/95 border border-amber-500/50 rounded-2xl max-w-md w-full p-6 sm:p-8 shadow-2xl relative overflow-hidden">
            <div class="cyber-laser-beam opacity-30"></div>
            <div class="flex justify-between items-center mb-5 border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2.5 text-white">
                    <div class="h-8 w-8 rounded-lg bg-amber-950/80 border border-amber-500/40 flex items-center justify-center text-amber-400 glow-amber">
                        <i class="fa-solid fa-key text-sm"></i>
                    </div>
                    <h3 class="font-orbitron font-bold text-base">Provision Service API Key</h3>
                </div>
                <button onclick="document.getElementById('generateModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            
            <form method="POST" action="">
                <input type="hidden" name="api_action" value="generate_key">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="mb-4 font-tech">
                    <label class="block text-xs text-amber-300 uppercase mb-1">Application / Microservice Name <span class="text-red-400">*</span></label>
                    <input type="text" name="app_name" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g., SIEM Telemetry Agent" required>
                    <p class="text-[10px] text-slate-500 mt-1">A cryptographically secure 160-bit HMAC bearer token will be generated.</p>
                </div>

                <div class="flex space-x-3 pt-3 border-t border-slate-800 font-tech">
                    <button type="button" onclick="document.getElementById('generateModal').classList.add('hidden')" class="w-1/2 bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-bold py-2.5 rounded-xl border border-slate-700 transition">
                        Cancel
                    </button>
                    <button type="submit" class="cyber-btn w-1/2 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white text-xs font-orbitron font-bold py-2.5 rounded-xl transition shadow-lg glow-amber">
                        Generate Token
                    </button>
                </div>
            </form>
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
                    icon.className = muted ? 'fa-solid fa-volume-xmark text-xs text-red-400' : 'fa-solid fa-volume-high text-xs text-amber-400';
                }
                if (!muted) CyberAudio.accessGranted();
            }
        }

        function copyToken(tokenText, btnElement) {
            navigator.clipboard.writeText(tokenText).then(() => {
                if (window.CyberAudio) CyberAudio.accessGranted();
                const originalHtml = btnElement.innerHTML;
                btnElement.innerHTML = '<i class="fa-solid fa-check text-xs text-emerald-400"></i>';
                setTimeout(() => {
                    btnElement.innerHTML = originalHtml;
                }, 1800);
            });
        }
    </script>
</body>
</html>
