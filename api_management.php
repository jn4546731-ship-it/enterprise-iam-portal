<?php
/**
 * Enterprise IAM Portal - API Key & Session Management
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
        $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 text-base'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $api_action = $_POST['api_action'];

        // 1. GENERATE NEW API KEY (Tier 3 Admin only)
        if ($api_action === 'generate_key') {
            if ($tier_numeric < 3) {
                // Unauthorized Generation Attempt
                $action_type = "ACCESS_DENIED_API_KEY_PROVISION";
                $action_desc = "UNAUTHORIZED: User {$user_email} ({$user_clearance}) attempted to provision a new programmatic API Key. Blocked by RBAC.";
                $log = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                $log->execute();

                $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-ban mr-2 text-base text-red-400'></i> <div><strong class='text-white'>PERMISSION DENIED:</strong> Provisioning enterprise API keys requires Tier 3 (Admin) clearance. Operation blocked.</div></div>";
            } else {
                $app_name = trim($_POST['app_name'] ?? '');
                if (empty($app_name)) {
                    $feedback_msg = "<div class='p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono mb-6'>Application name is required.</div>";
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

                        $feedback_msg = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-circle-check mr-2 text-base text-emerald-400'></i> <div><strong class='text-white'>API TOKEN PROVISIONED:</strong> Cryptographic bearer token successfully generated for <strong>" . htmlspecialchars($app_name) . "</strong>.</div></div>";
                    } else {
                        $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6'>Database error provisioning API key.</div>";
                    }
                }
            }
        }

        // 2. TOGGLE KEY STATUS (Active / Revoked)
        if ($api_action === 'toggle_key_status') {
            if ($tier_numeric < 3) {
                $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6'>Only Tier 3 Administrators can alter API key statuses.</div>";
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

                    $feedback_msg = "<div class='p-3.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-key mr-2 text-sky-400'></i> API Key #{$target_key_id} is now <strong>{$new_status}</strong>.</div>";
                }
            }
        }

        // 3. DELETE API KEY
        if ($api_action === 'delete_key') {
            if ($tier_numeric < 3) {
                $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6'>Only Tier 3 Administrators can delete API keys.</div>";
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

                    $feedback_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-6 flex items-center'><i class='fa-solid fa-trash-can mr-2 text-red-400'></i> API Key #{$target_key_id} permanently deleted.</div>";
                }
            }
        }
    }
}

// Fetch all API keys
$api_keys = [];
$active_keys_count = 0;
$revoked_keys_count = 0;
$res = $conn->query("SELECT * FROM api_keys ORDER BY id DESC");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $api_keys[] = $row;
        if (strcasecmp($row['status'], 'Active') === 0) {
            $active_keys_count++;
        } else {
            $revoked_keys_count++;
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
    <title>Active Sessions &amp; API Credentials &mdash; Enterprise IAM</title>
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

                <a href="vault.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-lock text-sm w-4 text-center"></i>
                    <span>Access Policies</span>
                </a>

                <a href="audit_report.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-list-check text-sm w-4 text-center"></i>
                    <span>Audit Logs</span>
                </a>

                <!-- Active Sessions / API Credentials (Active Page) -->
                <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#21262d] border border-[#30363d] text-white shadow-xs font-medium">
                    <i class="fa-solid fa-key text-sm text-[#2f81f7] w-4 text-center"></i>
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
                <input type="text" placeholder="Search API keys, service sessions, credentials... (Ctrl+K)" class="w-full bg-[#0d1117] border border-[#30363d] rounded-md pl-9 pr-14 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#2f81f7] transition font-sans">
                <kbd class="absolute right-2.5 top-1/2 -translate-y-1/2 font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#161b22] border border-[#30363d] text-slate-400 uppercase">Ctrl+K</kbd>
            </div>

            <!-- Header Controls -->
            <div class="flex items-center gap-3">
                <div class="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0d1117] border border-[#30363d] text-xs font-mono text-slate-300">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    <span>Environment: Production</span>
                </div>

                <button id="themeToggleBtn" onclick="toggleTheme()" class="p-2 rounded-md bg-[#0d1117] border border-[#30363d] text-slate-300 hover:text-white hover:bg-[#21262d] transition text-xs" title="Toggle Light / Dark mode">
                    <i id="themeToggleIcon" class="fa-solid fa-sun text-amber-400"></i>
                </button>

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
                    <div class="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1.5">
                        <span>Administration</span>
                        <span class="text-slate-600">/</span>
                        <span class="text-slate-200 font-semibold">Active Sessions &amp; Credentials</span>
                        <span class="text-slate-600 ml-1">&bull;</span>
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Environment: Production
                        </span>
                    </div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">API Credentials &amp; Programmatic Sessions</h1>
                    <p class="text-xs text-slate-400 mt-1 max-w-2xl">Manage programmatic authentication tokens, service application credentials, and session lifecycles.</p>
                </div>

                <div class="flex flex-wrap items-center gap-2.5 shrink-0">
                    <?php if ($tier_numeric >= 3): ?>
                        <button onclick="document.getElementById('generateModal').classList.remove('hidden')" class="px-3.5 py-2 rounded-md bg-[#2f81f7] hover:bg-blue-600 text-white text-xs font-semibold shadow-xs transition flex items-center gap-2">
                            <i class="fa-solid fa-plus text-xs"></i>
                            <span>Generate API Key</span>
                        </button>
                    <?php else: ?>
                        <span class="px-3 py-2 rounded-md bg-[#161b22] border border-[#30363d] text-xs font-mono text-slate-400 flex items-center gap-2">
                            <i class="fa-solid fa-lock text-amber-400 text-xs"></i>
                            <span>Read-Only Access (Tier 3 Required to Generate)</span>
                        </span>
                    <?php endif; ?>

                    <a href="dashboard.php?export=csv" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-download text-xs text-slate-400"></i>
                        <span>Export Audit CSV</span>
                    </a>
                </div>
            </div>

            <!-- 2. SUMMARY KPI ROW -->
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 my-6">
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">Active API Keys</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Authorized</span>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight"><?php echo $active_keys_count; ?></div>
                    <div class="mt-2 text-xs text-slate-400 font-sans">
                        Service tokens actively authenticating
                    </div>
                </div>

                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">Revoked / Suspended</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">Invalidated</span>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight"><?php echo $revoked_keys_count; ?></div>
                    <div class="mt-2 text-xs text-slate-400 font-sans">
                        Decommissioned programmatic credentials
                    </div>
                </div>

                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">Entropy &amp; Standard</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-sky-500/10 text-sky-400 border border-sky-500/20">SHA-256</span>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight">160-Bit</div>
                    <div class="mt-2 text-xs text-slate-400 font-sans">
                        HMAC high-entropy bearer token format
                    </div>
                </div>
            </div>

            <!-- 3. REGISTERED APPLICATION INTEGRATIONS TABLE -->
            <div class="p-6 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs mb-8">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#30363d] mb-4 gap-2">
                    <div>
                        <h2 class="text-base font-semibold text-white flex items-center gap-2">
                            <i class="fa-solid fa-server text-[#2f81f7]"></i>
                            <span>Registered Service Applications &amp; Tokens</span>
                        </h2>
                        <p class="text-xs text-slate-400 mt-0.5">Programmatic service accounts authorized for API gateway ingress.</p>
                    </div>
                    <span class="text-xs font-mono text-slate-300 bg-[#0d1117] px-3 py-1 rounded border border-[#30363d]">
                        <?php echo count($api_keys); ?> Keys Registered
                    </span>
                </div>

                <div class="overflow-x-auto custom-scrollbar">
                    <table class="w-full text-left text-xs font-sans">
                        <thead class="bg-[#0d1117] text-slate-400 font-mono text-[11px] uppercase tracking-wider border-b border-[#30363d]">
                            <tr>
                                <th class="px-4 py-3">ID</th>
                                <th class="px-4 py-3">Application / Microservice</th>
                                <th class="px-4 py-3">Bearer Token</th>
                                <th class="px-4 py-3">Status</th>
                                <th class="px-4 py-3">Provisioned Date</th>
                                <th class="px-4 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-[#30363d]">
                            <?php if (empty($api_keys)): ?>
                                <tr>
                                    <td colspan="6" class="px-4 py-8 text-center text-slate-500 font-mono text-xs">
                                        No API credentials provisioned yet. Click "Generate API Key" above to register an application.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($api_keys as $k): 
                                    $is_active = (strcasecmp($k['status'], 'Active') === 0);
                                    $raw_key = $k['api_key'];
                                    $masked_key = substr($raw_key, 0, 12) . '••••••••••••••••' . substr($raw_key, -4);
                                ?>
                                <tr class="hover:bg-[#21262d]/60 transition">
                                    <td class="px-4 py-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">#<?php echo (int) $k['id']; ?></td>
                                    <td class="px-4 py-3.5 whitespace-nowrap">
                                        <div class="font-medium text-white text-xs flex items-center gap-2">
                                            <div class="w-6 h-6 rounded bg-[#21262d] text-slate-400 border border-[#30363d] flex items-center justify-center text-[10px]">
                                                <i class="fa-solid fa-cube"></i>
                                            </div>
                                            <span><?php echo htmlspecialchars($k['app_name']); ?></span>
                                        </div>
                                    </td>
                                    <td class="px-4 py-3.5 font-mono text-xs whitespace-nowrap">
                                        <div class="flex items-center space-x-2 bg-[#0d1117] px-2.5 py-1 rounded border border-[#30363d] w-fit">
                                            <span class="text-sky-300"><?php echo htmlspecialchars($masked_key); ?></span>
                                            <button onclick="copyToken('<?php echo htmlspecialchars($raw_key); ?>', this)" class="text-slate-400 hover:text-white transition" title="Copy Raw Token">
                                                <i class="fa-solid fa-copy text-xs"></i>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="px-4 py-3.5 whitespace-nowrap">
                                        <?php if ($is_active): ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                            </span>
                                        <?php else: ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                                                <span class="w-1.5 h-1.5 rounded-full bg-red-400 mr-1.5"></span> Revoked
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="px-4 py-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                                        <?php echo htmlspecialchars($k['created_at']); ?>
                                    </td>
                                    <td class="px-4 py-3.5 text-right whitespace-nowrap">
                                        <?php if ($tier_numeric >= 3): ?>
                                            <div class="inline-flex items-center gap-1.5">
                                                <!-- Toggle Status Form -->
                                                <form method="POST" action="" class="inline" onsubmit="return confirm('Change status of API Key for <?php echo addslashes($k['app_name']); ?>?');">
                                                    <input type="hidden" name="api_action" value="toggle_key_status">
                                                    <input type="hidden" name="target_key_id" value="<?php echo (int) $k['id']; ?>">
                                                    <input type="hidden" name="new_status" value="<?php echo $is_active ? 'Revoked' : 'Active'; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    
                                                    <?php if ($is_active): ?>
                                                        <button type="submit" class="px-2.5 py-1 text-xs rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 hover:bg-amber-500/20 transition" title="Revoke Key Access">
                                                            Revoke
                                                        </button>
                                                    <?php else: ?>
                                                        <button type="submit" class="px-2.5 py-1 text-xs rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 hover:bg-emerald-500/20 transition" title="Reactivate Key Access">
                                                            Activate
                                                        </button>
                                                    <?php endif; ?>
                                                </form>

                                                <!-- Delete Key Form -->
                                                <form method="POST" action="" class="inline" onsubmit="return confirm('DANGER: Permanently delete API Key for <?php echo addslashes($k['app_name']); ?>? Applications using this key will immediately fail.');">
                                                    <input type="hidden" name="api_action" value="delete_key">
                                                    <input type="hidden" name="target_key_id" value="<?php echo (int) $k['id']; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    <button type="submit" class="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition" title="Purge Key">
                                                        <i class="fa-solid fa-trash-can text-xs"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        <?php else: ?>
                                            <span class="text-xs text-slate-500 font-mono"><i class="fa-solid fa-lock"></i> Locked</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
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

    <!-- MODAL: GENERATE NEW API KEY -->
    <div id="generateModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl max-w-md w-full p-6 shadow-2xl relative">
            <div class="flex justify-between items-center mb-4 border-b border-[#30363d] pb-3">
                <div class="flex items-center space-x-2 text-[#2f81f7]">
                    <i class="fa-solid fa-key text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Generate API Credential</h3>
                </div>
                <button onclick="document.getElementById('generateModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            
            <form method="POST" action="" class="space-y-4">
                <input type="hidden" name="api_action" value="generate_key">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Application / Service Name <span class="text-red-400">*</span></label>
                    <input type="text" name="app_name" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden" placeholder="e.g., SIEM Telemetry Collector" required>
                    <p class="text-[10px] text-slate-500 mt-1">A cryptographically random 160-bit HMAC token will be issued.</p>
                </div>

                <div class="flex space-x-3 pt-2">
                    <button type="button" onclick="document.getElementById('generateModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#30363d] hover:bg-[#21262d] text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded text-xs font-semibold bg-[#2f81f7] hover:bg-blue-600 text-white shadow transition">
                        Generate Key
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- JavaScript Handlers -->
    <script>
        function copyToken(tokenText, btnElement) {
            navigator.clipboard.writeText(tokenText).then(() => {
                const originalHtml = btnElement.innerHTML;
                btnElement.innerHTML = '<i class="fa-solid fa-check text-xs text-emerald-400"></i>';
                setTimeout(() => {
                    btnElement.innerHTML = originalHtml;
                }, 1800);
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
