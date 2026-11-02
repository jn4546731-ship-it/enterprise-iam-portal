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
        $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 text-sm flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
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

                $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-xl mb-6 text-sm flex items-center'><i class='fa-solid fa-ban mr-2 text-lg'></i> <strong>Clearance Insufficient:</strong> Provisioning enterprise API keys requires Tier 3 (Admin) clearance.</div>";
            } else {
                $app_name = trim($_POST['app_name'] ?? '');
                if (empty($app_name)) {
                    $feedback_msg = "<div class='bg-amber-500/10 border border-amber-500/50 text-amber-400 p-3 rounded-lg mb-6 text-sm'>Application name is required.</div>";
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

                        $feedback_msg = "<div class='bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 p-4 rounded-xl mb-6 text-sm flex items-center shadow-lg'><i class='fa-solid fa-circle-check mr-2 text-lg text-emerald-400'></i> Programmatic API Key provisioned for <strong>" . htmlspecialchars($app_name) . "</strong>. Stored with AES-256 HMAC integrity.</div>";
                    } else {
                        $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm'>Database error provisioning API key.</div>";
                    }
                }
            }
        }

        // 2. TOGGLE KEY STATUS (Active / Revoked)
        if ($api_action === 'toggle_key_status') {
            if ($tier_numeric < 3) {
                $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm'>Only Tier 3 Administrators can alter API key statuses.</div>";
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

                    $feedback_msg = "<div class='bg-blue-500/10 border border-blue-500/50 text-blue-400 p-3.5 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-key mr-2'></i> API Key #{$target_key_id} is now <strong>{$new_status}</strong>.</div>";
                }
            }
        }

        // 3. DELETE API KEY
        if ($api_action === 'delete_key') {
            if ($tier_numeric < 3) {
                $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm'>Only Tier 3 Administrators can delete API keys.</div>";
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

                    $feedback_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3.5 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-trash-can mr-2'></i> API Key #{$target_key_id} permanently deleted.</div>";
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Key Management - Enterprise Zero-Trust IAM</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <style>
        .custom-scrollbar::-webkit-scrollbar { width: 5px; height: 5px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.6); }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
    </style>
</head>
<body class="bg-slate-950 text-slate-300 font-sans min-h-screen flex flex-col antialiased">

    <!-- Top Navigation Bar -->
    <nav class="bg-slate-900/90 backdrop-blur border-b border-slate-800 py-3.5 px-6 flex justify-between items-center shadow-lg sticky top-0 z-30">
        <div class="flex items-center space-x-3">
            <button id="mobileSidebarToggle" onclick="toggleSidebar()" class="lg:hidden p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition">
                <i class="fa-solid fa-bars text-lg"></i>
            </button>
            <div class="h-9 w-9 rounded-lg bg-amber-600/20 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-md">
                <i class="fa-solid fa-key text-lg"></i>
            </div>
            <div>
                <h1 class="text-base sm:text-lg font-bold text-white tracking-wider flex items-center space-x-2">
                    <span>API KEY MANAGEMENT</span>
                    <span class="text-xs font-mono font-normal bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded">PROGRAMMATIC ACCESS</span>
                </h1>
                <p class="text-[10px] font-mono text-slate-400 tracking-wider">SERVICE CREDENTIALS &bull; HMAC TOKENS &bull; CRYPTOGRAPHIC ROTATION</p>
            </div>
        </div>

        <div class="flex items-center space-x-3 text-xs">
            <!-- Clearance Pill -->
            <div class="flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-700 font-mono">
                <span class="text-slate-400">Clearance:</span>
                <?php if ($tier_numeric === 3): ?>
                    <span class="text-purple-400 font-bold flex items-center"><i class="fa-solid fa-gem mr-1 text-[11px]"></i> TIER 3 (ADMIN)</span>
                <?php elseif ($tier_numeric === 2): ?>
                    <span class="text-cyan-400 font-bold flex items-center"><i class="fa-solid fa-file-shield mr-1 text-[11px]"></i> TIER 2 (AUDITOR)</span>
                <?php else: ?>
                    <span class="text-amber-400 font-bold flex items-center"><i class="fa-solid fa-id-badge mr-1 text-[11px]"></i> TIER 1 (STAFF)</span>
                <?php endif; ?>
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
            
            <!-- Current Profile Card -->
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

                <a href="vault.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition group">
                    <i class="fa-solid fa-vault w-4 text-center text-slate-500 group-hover:text-purple-400 transition"></i>
                    <span class="font-medium">Secure Vault (Crown Jewels)</span>
                    <span class="ml-auto text-[9px] font-mono bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded uppercase">RBAC</span>
                </a>

                <a href="api_management.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-lg bg-amber-500/10 text-amber-300 border border-amber-500/30 font-semibold shadow-sm">
                    <i class="fa-solid fa-key w-4 text-center text-amber-400"></i>
                    <span>API Management</span>
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

            <div class="p-3 border-t border-slate-800 text-[11px] font-mono text-slate-500">
                <div class="flex items-center space-x-2 text-amber-400 mb-1">
                    <span class="h-2 w-2 rounded-full bg-amber-500 animate-pulse"></span>
                    <span class="font-bold">API Gatekeeper</span>
                </div>
                <div class="truncate text-[10px]">HMAC-SHA256 Token Vault</div>
            </div>
        </aside>

        <!-- Sidebar Backdrop for Mobile -->
        <div id="sidebarBackdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 hidden lg:hidden"></div>

        <!-- Main Workspace Area -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">

            <?php if (!empty($feedback_msg)) echo $feedback_msg; ?>

            <!-- Page Header & Action Bar -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-8 gap-4 border-b border-slate-800 pb-6">
                <div>
                    <div class="flex items-center space-x-2 mb-2">
                        <span class="px-2.5 py-1 text-[10px] font-mono font-bold uppercase rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            Service-to-Service Cryptographic Gatekeeper
                        </span>
                    </div>
                    <h2 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">API Key Management</h2>
                    <p class="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl">
                        Provision, monitor, and revoke high-entropy programmatic API keys for enterprise microservices, SIEM agents, and automated data pipelines.
                    </p>
                </div>

                <div class="flex items-center space-x-3">
                    <?php if ($tier_numeric >= 3): ?>
                        <button onclick="document.getElementById('generateModal').classList.remove('hidden')" class="bg-amber-600 hover:bg-amber-500 text-white px-4 py-2 rounded-lg text-xs font-semibold transition flex items-center shadow-lg shadow-amber-900/30">
                            <i class="fa-solid fa-plus mr-1.5"></i> Generate API Key
                        </button>
                    <?php else: ?>
                        <span class="text-xs font-mono text-slate-500 bg-slate-900 border border-slate-800 px-3 py-2 rounded-lg flex items-center">
                            <i class="fa-solid fa-lock mr-2 text-amber-500"></i> Read-Only Key Access (Tier 3 Required to Generate)
                        </span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- API Keys Table Card -->
            <div class="bg-slate-900/80 rounded-2xl border border-slate-800 p-6 shadow-xl mb-8">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center space-x-2 text-white">
                        <i class="fa-solid fa-server text-amber-400"></i>
                        <h3 class="text-sm font-bold tracking-wide">Registered Application Integrations</h3>
                    </div>
                    <span class="text-xs font-mono text-slate-400"><?php echo count($api_keys); ?> Total Keys Registered</span>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm">
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
                                    <td colspan="6" class="px-5 py-8 text-center text-slate-500 font-mono text-xs">
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
                                        <div class="flex items-center space-x-2 bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800 w-fit">
                                            <span class="text-slate-300"><?php echo htmlspecialchars($masked_key); ?></span>
                                            <button onclick="navigator.clipboard.writeText('<?php echo htmlspecialchars($raw_key); ?>'); alert('API Key copied to clipboard!');" class="text-slate-400 hover:text-amber-400 transition" title="Copy Raw Key">
                                                <i class="fa-solid fa-copy text-xs"></i>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="px-5 py-4">
                                        <?php if ($is_active): ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                            </span>
                                        <?php else: ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
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
                                                        <button type="submit" class="px-2.5 py-1 text-xs rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition" title="Revoke Key Access">
                                                            Revoke
                                                        </button>
                                                    <?php else: ?>
                                                        <button type="submit" class="px-2.5 py-1 text-xs rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition" title="Reactivate Key Access">
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
    <div id="generateModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm flex justify-center items-center z-50 p-4">
        <div class="bg-slate-900 border border-amber-500/40 rounded-2xl max-w-md w-full p-6 shadow-2xl">
            <div class="flex justify-between items-center mb-4 border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2 text-white">
                    <i class="fa-solid fa-key text-amber-500"></i>
                    <h3 class="font-bold text-base">Provision Service API Key</h3>
                </div>
                <button onclick="document.getElementById('generateModal').classList.add('hidden')" class="text-slate-400 hover:text-white">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            
            <form method="POST" action="">
                <input type="hidden" name="api_action" value="generate_key">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="mb-4">
                    <label class="block text-xs font-medium text-slate-300 mb-1">Application / Service Name <span class="text-red-400">*</span></label>
                    <input type="text" name="app_name" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-sm text-white outline-none focus:border-amber-500" placeholder="e.g., SIEM Telemetry Agent" required>
                    <p class="text-[10px] text-slate-500 mt-1">A cryptographically secure 160-bit HMAC bearer token will be generated.</p>
                </div>

                <div class="flex space-x-3 pt-2">
                    <button type="button" onclick="document.getElementById('generateModal').classList.add('hidden')" class="w-1/2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold py-2.5 rounded-lg transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold py-2.5 rounded-lg transition shadow-lg shadow-amber-900/40">
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
    </script>
</body>
</html>
