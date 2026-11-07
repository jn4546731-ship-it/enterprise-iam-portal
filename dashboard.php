<?php
session_start();
require_once 'db.php';
require_once 'ai_sentinel.php';

// Enforce Session Authentication
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$current_user_id = (int) $_SESSION['user_id'];

// Verify Current User Still Exists and is Active (Kill-Switch Session Revocation)
$auth_check_stmt = $conn->prepare("SELECT user_id, first_name, last_name, email, is_active, role_id, department, job_title, role, security_clearance FROM users WHERE user_id = ?");
$auth_check_stmt->bind_param("i", $current_user_id);
$auth_check_stmt->execute();
$current_user_res = $auth_check_stmt->get_result();
$current_user = $current_user_res->fetch_assoc();

if (!$current_user || (isset($current_user['is_active']) && (int) $current_user['is_active'] === 0)) {
    // Current user was deactivated by another administrator or policy
    session_unset();
    session_destroy();
    header("Location: index.php?error=suspended");
    exit();
}

$current_dept = !empty($current_user['department']) ? $current_user['department'] : 'Security Operations Center';
$current_job_title = !empty($current_user['job_title']) ? $current_user['job_title'] : 'Chief Information Security Officer (CISO)';
$current_functional_role = !empty($current_user['role']) ? $current_user['role'] : 'Admin';
$current_clearance = !empty($current_user['security_clearance']) ? $current_user['security_clearance'] : 'Tier 3';


// Ensure standard enterprise roles exist in the database (RBAC Integrity)
$standard_roles = [
    1 => ['name' => 'Super Admin', 'desc' => 'Full administrative access across identities and SOC telemetry'],
    2 => ['name' => 'Security Analyst', 'desc' => 'SOC telemetry monitoring and incident response'],
    3 => ['name' => 'IAM Auditor', 'desc' => 'Read-only compliance and immutable audit log review'],
    4 => ['name' => 'Employee', 'desc' => 'Standard corporate identity and workstation access']
];

foreach ($standard_roles as $roleId => $rData) {
    $stmt_check = $conn->prepare("SELECT role_id FROM roles WHERE role_name = ?");
    $stmt_check->bind_param("s", $rData['name']);
    $stmt_check->execute();
    $chk_res = $stmt_check->get_result();
    
    if ($chk_res->num_rows === 0) {
        // Role does not exist, insert it
        $ins_role = $conn->prepare("INSERT INTO roles (role_id, role_name, description) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE role_name = VALUES(role_name), description = VALUES(description)");
        $ins_role->bind_param("iss", $roleId, $rData['name'], $rData['desc']);
        @$ins_role->execute();
    }
}

// Fetch all available roles from the database
$roles = [];
$roles_result = $conn->query("SELECT * FROM roles ORDER BY role_id ASC");
if ($roles_result) {
    while ($r = $roles_result->fetch_assoc()) {
        $roles[$r['role_id']] = $r;
    }
}

// User Display Name & Clearance Resolution
$user_display_name = trim(($current_user['first_name'] ?? '') . ' ' . ($current_user['last_name'] ?? ''));
if (empty($user_display_name)) {
    $email_prefix = explode('@', $current_user['email'])[0];
    $user_display_name = ucwords(str_replace(['.', '_', '-'], ' ', $email_prefix));
}

$role_clearance_map = [
    1 => ['name' => 'Super Admin', 'clearance' => 'LEVEL 4 // TOP SECRET (FULL CONTROL)', 'color' => 'purple'],
    2 => ['name' => 'Security Analyst', 'clearance' => 'LEVEL 3 // SECRET (SOC RESPONSE)', 'color' => 'cyan'],
    3 => ['name' => 'IAM Auditor', 'clearance' => 'LEVEL 2 // CONFIDENTIAL (AUDIT REVIEW)', 'color' => 'indigo'],
    4 => ['name' => 'Employee', 'clearance' => 'LEVEL 1 // RESTRICTED ACCESS', 'color' => 'slate']
];
$current_role_id = (int) ($current_user['role_id'] ?? 4);
$current_role_info = $role_clearance_map[$current_role_id] ?? [
    'name' => $roles[$current_role_id]['role_name'] ?? 'Employee',
    'clearance' => 'RESTRICTED CLEARANCE',
    'color' => 'slate'
];

// Fresh Login Welcome HUD Trigger
$show_welcome_hud = false;
if (!empty($_SESSION['fresh_login'])) {
    $show_welcome_hud = true;
    unset($_SESSION['fresh_login']); // Consume flag so it displays once per login
}

// Ensure CSRF Token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

$feedback_alert = '';

// -------------------------------------------------------------
// 1. NATIVE CSV EXPORT LOGIC
// -------------------------------------------------------------
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="iam_security_audit_logs_' . date('Ymd_His') . '.csv"');
    $output = fopen('php://output', 'w');
    
    // Column Headers
    fputcsv($output, ['Log ID', 'User ID', 'Action Type', 'Action Description', 'IP Address', 'Timestamp']);
    
    $result = $conn->query("SELECT log_id, user_id, action_type, action_description, ip_address, created_at FROM audit_logs ORDER BY log_id DESC");
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            fputcsv($output, [
                $row['log_id'],
                $row['user_id'] ?? 'N/A',
                $row['action_type'],
                $row['action_description'],
                $row['ip_address'],
                $row['created_at']
            ]);
        }
    }
    fclose($output);
    exit();
}

// -------------------------------------------------------------
// 2. HANDLE RBAC: TOGGLE SUSPEND / ACTIVATE USER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_status') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $new_status = (int) ($_POST['new_status'] ?? 0); // 0 = suspend, 1 = activate
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Security Policy: Prevent self-suspension
        if ($target_user_id === $current_user_id) {
            $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-shield-halved mr-2'></i> Security Policy Violation: Administrators cannot suspend their own active session.</div>";
        } else {
            // Check if user exists
            $t_stmt = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
            $t_stmt->bind_param("i", $target_user_id);
            $t_stmt->execute();
            $target_res = $t_stmt->get_result();
            $target_user = $target_res->fetch_assoc();

            if ($target_user) {
                $target_email = $target_user['email'];
                $update_stmt = $conn->prepare("UPDATE users SET is_active = ? WHERE user_id = ?");
                $update_stmt->bind_param("ii", $new_status, $target_user_id);

                if ($update_stmt->execute()) {
                    if ($new_status === 0) {
                        $action_type = "ACCOUNT_SUSPENDED";
                        $action_desc = "Identity UID-{$target_user_id} ({$target_email}) was SUSPENDED by Admin UID-{$current_user_id} to mitigate potential credential compromise.";
                        $feedback_alert = "<div class='bg-amber-500/10 border border-amber-500/50 text-amber-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-lock mr-2'></i> Account <strong>{$target_email}</strong> has been suspended. Authentication access is revoked immediately.</div>";
                    } else {
                        $action_type = "ACCOUNT_ACTIVATED";
                        $action_desc = "Identity UID-{$target_user_id} ({$target_email}) was RE-ACTIVATED by Admin UID-{$current_user_id}.";
                        $feedback_alert = "<div class='bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-lock-open mr-2'></i> Account <strong>{$target_email}</strong> has been re-activated successfully.</div>";
                    }

                    // Audit Log entry
                    $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                    $log_stmt->bind_param("isss", $target_user_id, $action_type, $action_desc, $client_ip);
                    $log_stmt->execute();
                } else {
                    $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm'>Database error executing status change.</div>";
                }
            } else {
                $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm'>Target identity not found.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 3. HANDLE RBAC: UPDATE ROLE & CLEARANCE ASSIGNMENT
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_role') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $new_role_id = (int) ($_POST['new_role_id'] ?? 4);
        $new_functional_role = trim($_POST['new_functional_role'] ?? '');
        $new_clearance = trim($_POST['new_clearance'] ?? '');
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Auto-synchronize role and clearance if left default
        if (empty($new_functional_role)) {
            if ($new_role_id === 1) $new_functional_role = 'Admin';
            elseif ($new_role_id === 3) $new_functional_role = 'Auditor';
            else $new_functional_role = 'Staff';
        }
        if (empty($new_clearance)) {
            if ($new_functional_role === 'Admin') $new_clearance = 'Tier 3';
            elseif ($new_functional_role === 'Auditor') $new_clearance = 'Tier 2';
            else $new_clearance = 'Tier 1';
        }

        // Verify role exists in database before updating
        if (!isset($roles[$new_role_id])) {
            $fallback_role = reset($roles);
            $new_role_id = $fallback_role ? (int) $fallback_role['role_id'] : 4;
        }
        $role_title = $roles[$new_role_id]['role_name'] ?? 'Employee';

        $t_stmt = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
        $t_stmt->bind_param("i", $target_user_id);
        $t_stmt->execute();
        $target_res = $t_stmt->get_result();
        $target_user = $target_res->fetch_assoc();

        if ($target_user) {
            $target_email = $target_user['email'];
            $u_role = $conn->prepare("UPDATE users SET role_id = ?, role = ?, security_clearance = ? WHERE user_id = ?");
            $u_role->bind_param("issi", $new_role_id, $new_functional_role, $new_clearance, $target_user_id);

            if ($u_role->execute()) {
                $action_type = "ROLE_UPDATED";
                $action_desc = "Role & Clearance modified for UID-{$target_user_id} ({$target_email}) to [{$new_functional_role} // {$new_clearance}] by Admin UID-{$current_user_id}.";
                $feedback_alert = "<div class='bg-blue-500/10 border border-blue-500/50 text-blue-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-user-shield mr-2'></i> Access policy for <strong>{$target_email}</strong> updated to <strong>{$new_functional_role} ({$new_clearance})</strong>.</div>";

                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $target_user_id, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();
            } else {
                $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm'>Database error updating role.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 4. HANDLE NEW USER PROVISIONING (Phase 4.2: Enterprise RBAC)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'provision_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $provision_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded mb-4 text-sm'>CSRF token invalid.</div>";
    } else {
        $new_email = trim($_POST['new_email'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $first_name = trim($_POST['first_name'] ?? '');
        $last_name = trim($_POST['last_name'] ?? '');
        $department = trim($_POST['department'] ?? 'General Operations');
        $job_title = trim($_POST['job_title'] ?? 'Staff Analyst');
        $role_selected = trim($_POST['role'] ?? 'Staff'); // 'Admin', 'Auditor', 'Staff'
        $security_clearance = trim($_POST['security_clearance'] ?? 'Tier 1'); // 'Tier 1', 'Tier 2', 'Tier 3'
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Auto-synchronize role_id with chosen functional role
        if (strcasecmp($role_selected, 'Admin') === 0) {
            $role_id = 1; // Super Admin
            if ($security_clearance === 'Tier 1') $security_clearance = 'Tier 3';
        } elseif (strcasecmp($role_selected, 'Auditor') === 0) {
            $role_id = 3; // IAM Auditor
            if ($security_clearance === 'Tier 1') $security_clearance = 'Tier 2';
        } else {
            // Staff
            $role_id = 4; // Employee
        }

        // Allow explicit role_id override if present in POST
        if (!empty($_POST['role_id']) && isset($roles[(int)$_POST['role_id']])) {
            $role_id = (int)$_POST['role_id'];
        }

        if (empty($new_email) || empty($new_password)) {
            $provision_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded mb-4 text-sm'>Email and Password are required.</div>";
        } else {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $is_active = 1;

            $stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password_hash, department, job_title, role, security_clearance, role_id, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssssssii", $first_name, $last_name, $new_email, $hashed_password, $department, $job_title, $role_selected, $security_clearance, $role_id, $is_active);

            if ($stmt->execute()) {
                $new_uid = $stmt->insert_id;
                $action_type = "USER_PROVISIONED";
                $action_desc = "New enterprise identity provisioned: {$new_email} (Role: {$role_selected}, Clearance: {$security_clearance}, Dept: {$department}) by Admin UID-{$current_user_id}";

                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $new_uid, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();

                $feedback_alert = "<div class='bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 p-3.5 rounded-lg mb-6 text-sm flex items-center shadow-lg'><i class='fa-solid fa-circle-check mr-2 text-base text-emerald-400'></i> Identity <strong>{$new_email}</strong> provisioned successfully: Role [<strong>{$role_selected}</strong>], Clearance [<strong>{$security_clearance}</strong>], Dept [<strong>{$department}</strong>].</div>";
            } else {
                $provision_msg = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded mb-4 text-sm'>Error provisioning user: " . htmlspecialchars($conn->error) . "</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 5. LIVE DEFENSE SIMULATION TRIGGERS
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'simulate_threat') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $scenario = $_POST['scenario'] ?? 'brute_force';
        AISentinel::injectSimulationThreat($conn, $scenario);
        $feedback_alert = "<div class='bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 animate-bounce'></i> <strong>Defense Simulation Injected:</strong> Synthetic threat traffic generated ({$scenario}). Observe AI Sentinel response below!</div>";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reset_simulation') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        AISentinel::resetSimulationTelemetry($conn);
        $feedback_alert = "<div class='bg-emerald-500/10 border border-emerald-500/50 text-emerald-400 p-3 rounded-lg mb-6 text-sm flex items-center'><i class='fa-solid fa-rotate-left mr-2'></i> Simulation telemetry cleared. Threat baseline restored to normal.</div>";
    }
}

// -------------------------------------------------------------
// 6. FETCH SYSTEM METRICS & DIRECTORY DATA
// -------------------------------------------------------------
// Fetch Users with joined Role
$users_result = $conn->query("
    SELECT u.user_id, u.first_name, u.last_name, u.email, u.mfa_secret, u.role_id, u.is_active, u.created_at,
           u.department, u.job_title, u.role, u.security_clearance,
           COALESCE(r.role_name, 'Employee') AS role_name
    FROM users u
    LEFT JOIN roles r ON u.role_id = r.role_id
    ORDER BY u.user_id ASC
");

$users = [];
$total_users = 0;
$mfa_enabled = 0;
$suspended_count = 0;

if ($users_result) {
    while ($row = $users_result->fetch_assoc()) {
        $users[] = $row;
        $total_users++;
        if (!empty($row['mfa_secret'])) {
            $mfa_enabled++;
        }
        if (isset($row['is_active']) && (int) $row['is_active'] === 0) {
            $suspended_count++;
        }
    }
}
$mfa_rate = $total_users > 0 ? round(($mfa_enabled / $total_users) * 100) : 0;

// Fetch Recent Audit Logs
$audit_logs = [];
$logs_result = $conn->query("SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT 15");
if ($logs_result) {
    while ($row = $logs_result->fetch_assoc()) {
        $audit_logs[] = $row;
    }
}

// Fetch 24-hour total events count
$count_24h_res = $conn->query("SELECT COUNT(*) as c FROM audit_logs WHERE created_at >= NOW() - INTERVAL 24 HOUR");
$total_logs_24h = $count_24h_res ? (int) $count_24h_res->fetch_assoc()['c'] : count($audit_logs);

// -------------------------------------------------------------
// 7. RUN AI SENTINEL BEHAVIORAL THREAT SCAN
// -------------------------------------------------------------
$sentinel = AISentinel::analyzeThreatLevel($conn);
$threat_score = $sentinel['threat_score'];
$threat_level = $sentinel['threat_level'];
$status_color = $sentinel['status_color']; // emerald, amber, orange, red
$anomalies = $sentinel['anomalies'];
$terminal_logs = $sentinel['terminal_logs'];

// Map status color to Tailwind classes
$color_map = [
    'emerald' => [
        'text' => 'text-emerald-400',
        'bg' => 'bg-emerald-500/10',
        'border' => 'border-emerald-500/30',
        'dot' => 'bg-emerald-500',
        'ping' => 'bg-emerald-400',
        'bar' => 'bg-emerald-500'
    ],
    'amber' => [
        'text' => 'text-amber-400',
        'bg' => 'bg-amber-500/10',
        'border' => 'border-amber-500/30',
        'dot' => 'bg-amber-500',
        'ping' => 'bg-amber-400',
        'bar' => 'bg-amber-500'
    ],
    'orange' => [
        'text' => 'text-orange-400',
        'bg' => 'bg-orange-500/10',
        'border' => 'border-orange-500/30',
        'dot' => 'bg-orange-500',
        'ping' => 'bg-orange-400',
        'bar' => 'bg-orange-500'
    ],
    'red' => [
        'text' => 'text-red-400',
        'bg' => 'bg-red-500/10',
        'border' => 'border-red-500/30',
        'dot' => 'bg-red-500',
        'ping' => 'bg-red-400',
        'bar' => 'bg-red-500'
    ]
];
$active_theme = $color_map[$status_color] ?? $color_map['emerald'];
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark">
    <title>Enterprise Zero-Trust SOC Command Center - IAM Sentinel</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay text-slate-300 font-sans min-h-screen flex flex-col antialiased relative selection:bg-cyan-500 selection:text-black">

    <!-- Top High-Tech Cyber Navigation Bar -->
    <nav class="bg-slate-950/85 backdrop-blur-md border-b border-cyan-500/25 py-3 px-4 sm:px-6 flex justify-between items-center shadow-2xl sticky top-0 z-30 relative overflow-hidden">
        <!-- Sub-laser accent -->
        <div class="cyber-laser-beam opacity-40"></div>

        <div class="flex items-center space-x-3">
            <button id="mobileSidebarToggle" onclick="toggleSidebar()" class="lg:hidden p-2 text-slate-400 hover:text-cyan-400 rounded-lg hover:bg-slate-900 border border-transparent hover:border-cyan-500/30 transition">
                <i class="fa-solid fa-bars text-lg"></i>
            </button>
            <div class="relative w-9 h-9 rounded-xl bg-cyan-950/60 border border-cyan-400/50 flex items-center justify-center text-cyan-400 glow-cyan-sm">
                <i class="fa-solid fa-shield-halved text-lg"></i>
            </div>
            <div>
                <h1 class="font-orbitron text-sm sm:text-base font-extrabold text-white tracking-wider flex items-center space-x-2">
                    <span>ENTERPRISE SOC</span>
                    <span class="text-cyan-400 glow-text-cyan">COMMAND CENTER</span>
                </h1>
                <p class="font-tech text-[10px] text-slate-400 tracking-wider">ZERO-TRUST IDENTITY ARCHITECTURE &bull; AI SENTINEL HEURISTICS</p>
            </div>
        </div>

        <div class="flex items-center space-x-3 text-xs font-tech">
            <!-- HTTPS Domain Indicator Badge -->
            <div class="hidden xl:flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-[11px] text-emerald-400 shadow-sm" title="Active Enterprise Encrypted Domain">
                <i class="fa-solid fa-lock text-[10px] text-emerald-400"></i>
                <span class="font-bold">iam.secure-defense.internal</span>
            </div>

            <!-- Audio SFX Mute/Unmute Toggle -->
            <button onclick="toggleGlobalAudio()" id="navMuteBtn" class="p-2 rounded-lg bg-slate-900/80 border border-slate-700 text-slate-400 hover:text-cyan-400 hover:border-cyan-400/50 transition" title="Toggle Cyber Audio Synthesizer">
                <i id="navMuteIcon" class="fa-solid fa-volume-high text-xs"></i>
            </button>

            <!-- Identity Clearance HUD Replay Trigger -->
            <button onclick="triggerCyberWelcomeHUD(true)" class="font-orbitron text-[11px] font-bold text-cyan-300 hover:text-white transition flex items-center bg-cyan-950/40 border border-cyan-500/40 px-3 py-1.5 rounded-lg shadow-sm group hover:border-cyan-400 glow-cyan-sm" title="Replay Biometric Identity Clearance HUD">
                <i class="fa-solid fa-id-card-clip mr-1.5 text-cyan-400 group-hover:scale-110 transition"></i>
                <span>IDENTITY HUD</span>
            </button>

            <!-- Clearance Pill -->
            <div class="hidden sm:flex items-center space-x-2 bg-slate-900/90 px-3 py-1.5 rounded-lg border border-purple-500/30">
                <span class="text-slate-500">Tier:</span>
                <span class="text-purple-300 font-bold flex items-center"><i class="fa-solid fa-gem mr-1 text-[10px] text-purple-400"></i> <?php echo htmlspecialchars($current_clearance); ?></span>
            </div>

            <!-- Active User Identity Badge -->
            <div class="hidden md:flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400">
                <i class="fa-solid fa-user-shield text-cyan-400"></i>
                <span class="text-white font-medium"><?php echo htmlspecialchars($user_display_name); ?></span>
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
        <aside id="appSidebar" class="fixed inset-y-0 left-0 z-40 w-64 bg-slate-950/95 backdrop-blur-md border-r border-cyan-500/20 flex flex-col transition-transform duration-300 -translate-x-full lg:translate-x-0 lg:static lg:z-auto">
            
            <!-- Sidebar Header / Current Profile Card -->
            <div class="p-4 border-b border-slate-800">
                <div class="cyber-card cyber-brackets p-3.5 rounded-xl border border-cyan-500/25">
                    <div class="flex items-center space-x-3 mb-2">
                        <div class="relative w-10 h-10 rounded-lg bg-cyan-950/60 border border-cyan-400/50 flex items-center justify-center text-cyan-300 font-orbitron font-bold text-sm glow-cyan-sm">
                            <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                        </div>
                        <div class="overflow-hidden">
                            <h4 class="font-orbitron text-xs font-bold text-white truncate"><?php echo htmlspecialchars($user_display_name); ?></h4>
                            <p class="font-tech text-[11px] text-slate-400 truncate"><?php echo htmlspecialchars($current_job_title); ?></p>
                        </div>
                    </div>
                    <div class="flex items-center justify-between text-[10px] font-tech pt-2 border-t border-slate-800/80">
                        <span class="text-slate-500">Dept:</span>
                        <span class="text-slate-300 truncate max-w-[130px]"><?php echo htmlspecialchars($current_dept); ?></span>
                    </div>
                    <div class="flex items-center justify-between text-[10px] font-tech pt-1">
                        <span class="text-slate-500">Role:</span>
                        <span class="text-cyan-400 font-bold"><?php echo htmlspecialchars($current_functional_role); ?></span>
                    </div>
                </div>
            </div>

            <!-- Navigation Links -->
            <nav class="flex-1 p-3 space-y-1.5 overflow-y-auto custom-scrollbar text-xs">
                <div class="px-3 py-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
                    Core Operations
                </div>

                <a href="dashboard.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl bg-cyan-950/40 text-cyan-300 border border-cyan-500/40 font-orbitron text-xs font-bold shadow-md glow-cyan-sm">
                    <i class="fa-solid fa-gauge-high w-4 text-center text-cyan-400"></i>
                    <span>SOC Command Center</span>
                </a>

                <a href="vault.php" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-purple-500/30 transition group font-tech">
                    <i class="fa-solid fa-vault w-4 text-center text-slate-500 group-hover:text-purple-400 transition"></i>
                    <span class="font-medium">Secure Vault (Crown Jewels)</span>
                    <span class="ml-auto text-[9px] font-mono bg-purple-500/20 text-purple-300 px-1.5 py-0.5 rounded border border-purple-500/30 uppercase font-bold">RBAC</span>
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

                <a href="?export=csv" class="flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent hover:border-cyan-500/30 transition group font-tech">
                    <i class="fa-solid fa-file-csv w-4 text-center text-slate-500 group-hover:text-cyan-400 transition"></i>
                    <span class="font-medium">Export Audit Ledger</span>
                </a>
            </nav>

            <!-- Sidebar Footer Security Status -->
            <div class="p-3 border-t border-slate-800 text-[11px] font-tech text-slate-500">
                <div class="flex items-center space-x-2 text-emerald-400 mb-1">
                    <span class="h-2 w-2 rounded-full bg-emerald-500 cyber-beacon"></span>
                    <span class="font-bold">Zero-Trust Active</span>
                </div>
                <div class="truncate text-[10px] text-slate-500">TLS 1.3 &bull; SHA-256 MAC ENFORCED</div>
            </div>
        </aside>

        <!-- Sidebar Backdrop for Mobile -->
        <div id="sidebarBackdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/60 backdrop-blur-xs z-30 hidden lg:hidden"></div>

        <!-- Main Workspace Area -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">

        <?php if (!empty($feedback_alert)) echo $feedback_alert; ?>
        
        <!-- Header & Action Toolbar -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-8 gap-4 border-b border-cyan-500/20 pb-6">
            <div>
                <div class="flex items-center space-x-2 mb-2">
                    <span class="px-2.5 py-0.5 text-[10px] font-tech font-bold uppercase rounded-md bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                        SURVEILLANCE NODE // ACTIVE
                    </span>
                    <span class="text-xs text-slate-500 font-tech">&bull; Real-time Behavioral Telemetry</span>
                </div>
                <h2 class="font-orbitron text-2xl sm:text-3xl font-extrabold text-white tracking-tight glow-text-cyan mb-1">
                    SOC Telemetry & Access Control
                </h2>
                <p class="font-tech text-slate-400 text-xs sm:text-sm">Continuous Zero-Trust behavioral assessment, biometric session lifecycle, and automated breach mitigation.</p>
            </div>

            <div class="flex flex-wrap items-center gap-2.5 font-tech">
                <!-- Simulation Trigger (University Defense Mode) -->
                <div class="relative inline-block text-left" id="simulationDropdownContainer">
                    <button type="button" onclick="toggleSimMenu()" class="cyber-btn bg-purple-950/50 hover:bg-purple-900/60 text-purple-200 border border-purple-500/40 px-3.5 py-2.5 rounded-xl text-xs font-bold transition flex items-center shadow-lg glow-purple">
                        <i class="fa-solid fa-flask-vial mr-2 text-purple-400"></i>
                        <span>Simulate Threat (Defense Mode)</span>
                        <i class="fa-solid fa-chevron-down ml-2 text-[10px]"></i>
                    </button>
                    <div id="simMenu" class="hidden absolute right-0 mt-2 w-72 bg-slate-950 border border-purple-500/50 rounded-2xl shadow-2xl py-2 z-40 text-xs cyber-card cyber-brackets">
                        <div class="px-4 py-2 text-[10px] font-tech text-purple-300 uppercase tracking-widest font-bold border-b border-slate-800 mb-1 flex items-center justify-between">
                            <span>ATTACK VECTORS</span>
                            <span class="text-[9px] bg-purple-950 px-1.5 py-0.5 rounded text-purple-400">DEMO</span>
                        </div>
                        <form method="POST" action="">
                            <input type="hidden" name="action" value="simulate_threat">
                            <input type="hidden" name="scenario" value="brute_force">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit" class="w-full text-left px-4 py-2.5 text-slate-300 hover:bg-purple-950/40 hover:text-white flex items-center transition">
                                <i class="fa-solid fa-burst text-red-400 mr-2.5 text-base"></i>
                                <div>
                                    <p class="font-bold text-xs">1. Rapid MFA Brute-Force</p>
                                    <p class="text-[10px] text-slate-400">5 bursts of failed MFA challenges</p>
                                </div>
                            </button>
                        </form>
                        <form method="POST" action="">
                            <input type="hidden" name="action" value="simulate_threat">
                            <input type="hidden" name="scenario" value="ip_divergence">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit" class="w-full text-left px-4 py-2.5 text-slate-300 hover:bg-purple-950/40 hover:text-white flex items-center transition">
                                <i class="fa-solid fa-globe text-amber-400 mr-2.5 text-base"></i>
                                <div>
                                    <p class="font-bold text-xs">2. Identity IP Divergence</p>
                                    <p class="text-[10px] text-slate-400">Impossible travel across 2 distinct IPs</p>
                                </div>
                            </button>
                        </form>
                        <div class="border-t border-slate-800 my-1"></div>
                        <form method="POST" action="">
                            <input type="hidden" name="action" value="reset_simulation">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit" class="w-full text-left px-4 py-2 text-slate-400 hover:text-emerald-400 hover:bg-slate-900 flex items-center transition">
                                <i class="fa-solid fa-rotate-left mr-2 text-xs"></i> Reset Baseline Telemetry
                            </button>
                        </form>
                    </div>
                </div>

                <!-- Export CSV -->
                <a href="?export=csv" class="cyber-btn bg-slate-900/80 hover:bg-slate-800 text-slate-200 px-3.5 py-2.5 rounded-xl text-xs font-bold transition border border-slate-700 hover:border-cyan-400/50 shadow-md flex items-center">
                    <i class="fa-solid fa-download mr-1.5 text-cyan-400"></i> Export Audit Logs
                </a>

                <!-- Provision User -->
                <button onclick="document.getElementById('provisionModal').classList.remove('hidden')" class="cyber-btn bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white px-4 py-2.5 rounded-xl text-xs font-bold transition shadow-lg glow-cyan flex items-center">
                    <i class="fa-solid fa-user-plus mr-1.5"></i> Provision Identity
                </button>
            </div>
        </div>

        <!-- Telemetry Cards Data Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
            <!-- Total Identities -->
            <div class="cyber-card cyber-brackets p-5 rounded-2xl border border-cyan-500/30 relative overflow-hidden group">
                <div class="cyber-laser-beam opacity-30"></div>
                <div class="flex justify-between items-start mb-2">
                    <span class="text-xs font-tech uppercase tracking-wider text-cyan-300 font-bold">TOTAL IDENTITIES</span>
                    <span class="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 flex items-center justify-center text-sm"><i class="fa-solid fa-users"></i></span>
                </div>
                <div class="flex items-baseline space-x-2">
                    <p class="font-orbitron text-3xl font-extrabold text-white" data-cyber-count="<?php echo $total_users; ?>"><?php echo $total_users; ?></p>
                    <?php if ($suspended_count > 0): ?>
                        <span class="text-xs font-tech text-red-400 font-bold">(<?php echo $suspended_count; ?> Suspended)</span>
                    <?php else: ?>
                        <span class="text-xs font-tech text-emerald-400 font-bold">(100% Active)</span>
                    <?php endif; ?>
                </div>
                <div class="mt-3 text-[10px] font-tech text-slate-500 flex items-center justify-between border-t border-slate-800/80 pt-2">
                    <span>Directory Sync</span>
                    <span class="text-cyan-400 font-mono font-bold">RBAC ONLINE</span>
                </div>
            </div>
            
            <!-- MFA Enforcement -->
            <div class="cyber-card cyber-brackets p-5 rounded-2xl border border-emerald-500/30 relative overflow-hidden group">
                <div class="flex justify-between items-start mb-2">
                    <span class="text-xs font-tech uppercase tracking-wider text-emerald-300 font-bold">MFA ENFORCEMENT</span>
                    <span class="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 flex items-center justify-center text-sm"><i class="fa-solid fa-shield-check"></i></span>
                </div>
                <div class="flex items-baseline space-x-2">
                    <p class="font-orbitron text-3xl font-extrabold text-emerald-400" data-cyber-count="<?php echo $mfa_rate; ?>" data-suffix="%"><?php echo $mfa_rate; ?>%</p>
                    <span class="text-xs font-tech text-slate-400 font-mono"><?php echo $mfa_enabled; ?>/<?php echo $total_users; ?> enrolled</span>
                </div>
                <div class="mt-3 text-[10px] font-tech text-slate-500 flex items-center justify-between border-t border-slate-800/80 pt-2">
                    <span>Protocol</span>
                    <span class="text-emerald-400 font-mono font-bold">RFC 6238 TOTP</span>
                </div>
            </div>

            <!-- 24h Audit Events -->
            <div class="cyber-card cyber-brackets p-5 rounded-2xl border border-blue-500/30 relative overflow-hidden group">
                <div class="flex justify-between items-start mb-2">
                    <span class="text-xs font-tech uppercase tracking-wider text-blue-300 font-bold">24H AUDIT EVENTS</span>
                    <span class="w-8 h-8 rounded-lg bg-blue-950/80 border border-blue-500/40 text-blue-400 flex items-center justify-center text-sm"><i class="fa-solid fa-list-check"></i></span>
                </div>
                <div class="flex items-baseline space-x-2">
                    <p class="font-orbitron text-3xl font-extrabold text-white" data-cyber-count="<?php echo $total_logs_24h; ?>"><?php echo $total_logs_24h; ?></p>
                    <span class="text-xs font-tech text-cyan-400 font-mono">Live Telemetry</span>
                </div>
                <div class="mt-3 text-[10px] font-tech text-slate-500 flex items-center justify-between border-t border-slate-800/80 pt-2">
                    <span>Storage Integrity</span>
                    <span class="text-blue-400 font-mono font-bold">IMMUTABLE LOGS</span>
                </div>
            </div>

            <!-- AI Sentinel Threat Level Card -->
            <div class="cyber-card cyber-brackets p-5 rounded-2xl border <?php echo $active_theme['border']; ?> relative overflow-hidden transition">
                <div class="flex justify-between items-center mb-2">
                    <span class="text-xs font-tech uppercase tracking-wider text-slate-400 font-bold">AI THREAT POSTURE</span>
                    <span class="text-[10px] font-tech px-2 py-0.5 rounded <?php echo $active_theme['bg']; ?> <?php echo $active_theme['text']; ?> font-bold border <?php echo $active_theme['border']; ?>">
                        ATS: <?php echo $threat_score; ?>/100
                    </span>
                </div>
                <div class="flex items-center space-x-2.5">
                    <span class="relative flex h-3 w-3">
                        <span class="animate-ping absolute inline-flex h-full w-full rounded-full <?php echo $active_theme['ping']; ?> opacity-75"></span>
                        <span class="relative inline-flex rounded-full h-3 w-3 <?php echo $active_theme['dot']; ?>"></span>
                    </span>
                    <p class="font-orbitron text-base sm:text-lg font-bold <?php echo $active_theme['text']; ?> tracking-tight"><?php echo $threat_level; ?></p>
                </div>
                <!-- Risk Meter Bar -->
                <div class="w-full bg-slate-950 rounded-full h-2 mt-3 overflow-hidden border border-slate-800">
                    <div class="<?php echo $active_theme['bar']; ?> h-2 rounded-full transition-all duration-700 shadow-sm" style="width: <?php echo max(5, $threat_score); ?>%"></div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            
            <!-- Left Column: User Directory (RBAC Management) -->
            <div class="lg:col-span-2 space-y-8">
                <div class="cyber-card cyber-brackets rounded-2xl border border-cyan-500/30 overflow-hidden shadow-2xl">
                    <div class="border-b border-slate-800 p-5 bg-slate-950/70 flex justify-between items-center">
                        <div>
                            <h3 class="font-orbitron text-sm sm:text-base font-bold text-white flex items-center">
                                <i class="fa-solid fa-users-gear text-cyan-400 mr-2.5"></i> Identity & Role-Based Access Control (RBAC)
                            </h3>
                            <p class="font-tech text-xs text-slate-400 mt-0.5">Enforce Zero-Trust least privilege and trigger instant identity kill-switch locks.</p>
                        </div>
                        <span class="text-xs font-tech text-cyan-300 bg-cyan-950/60 px-3 py-1 rounded-lg border border-cyan-500/30 font-bold">
                            <?php echo count($users); ?> IDENTITIES REGISTERED
                        </span>
                    </div>

                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-900/60 text-slate-400 text-xs uppercase tracking-wider font-semibold">
                                <tr>
                                    <th class="px-5 py-3.5">User UID</th>
                                    <th class="px-5 py-3.5">Account / Identity</th>
                                    <th class="px-5 py-3.5">Role</th>
                                    <th class="px-5 py-3.5">Security Clearance</th>
                                    <th class="px-5 py-3.5">MFA Status</th>
                                    <th class="px-5 py-3.5">Status</th>
                                    <th class="px-5 py-3.5 text-right">SOC Actions</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-700/50">
                                <?php foreach ($users as $u): 
                                    $is_active = !isset($u['is_active']) || (int) $u['is_active'] === 1;
                                    $uid = (int) $u['user_id'];
                                    $user_email = htmlspecialchars($u['email'] ?? 'Unknown');
                                    $user_role_id = (int) ($u['role_id'] ?? 4);
                                    $user_role_name = htmlspecialchars($u['role_name'] ?? 'Employee');
                                    $user_functional_role = htmlspecialchars($u['role'] ?? $user_role_name);
                                    $user_clearance_val = $u['security_clearance'] ?? 'Tier 1';
                                    $user_dept_val = $u['department'] ?? 'General Operations';
                                    $user_title_val = $u['job_title'] ?? 'Staff Analyst';
                                    $is_self = ($uid === $current_user_id);

                                    // Role badge colors
                                    $role_badge = match($user_role_id) {
                                        1 => 'bg-purple-500/10 text-purple-400 border-purple-500/30',
                                        2 => 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
                                        3 => 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
                                        default => 'bg-slate-500/10 text-slate-400 border-slate-500/30',
                                    };

                                    // Clearance badge colors & icon
                                    $clearance_badge = match(true) {
                                        stripos($user_clearance_val, 'Tier 3') !== false => 'bg-purple-500/15 text-purple-300 border-purple-500/40',
                                        stripos($user_clearance_val, 'Tier 2') !== false => 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40',
                                        default => 'bg-amber-500/15 text-amber-300 border-amber-500/40',
                                    };
                                    $clearance_icon = match(true) {
                                        stripos($user_clearance_val, 'Tier 3') !== false => 'fa-gem',
                                        stripos($user_clearance_val, 'Tier 2') !== false => 'fa-file-shield',
                                        default => 'fa-id-badge',
                                    };
                                ?>
                                <tr class="hover:bg-slate-700/20 transition <?php echo !$is_active ? 'bg-red-950/10' : ''; ?>">
                                    <!-- User ID -->
                                    <td class="px-5 py-4 font-mono text-xs text-slate-400">
                                        UID-<?php echo str_pad($uid, 4, '0', STR_PAD_LEFT); ?>
                                    </td>

                                    <!-- Identity Email & Dept/Title -->
                                    <td class="px-5 py-4">
                                        <div class="flex items-center">
                                            <div class="h-9 w-9 rounded-lg <?php echo $is_active ? 'bg-slate-700 text-slate-300' : 'bg-red-950/50 text-red-400 border border-red-500/30'; ?> flex items-center justify-center mr-3 font-semibold text-xs border border-slate-600 flex-shrink-0">
                                                <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                                            </div>
                                            <div>
                                                <div class="text-white font-medium text-xs sm:text-sm flex items-center">
                                                    <?php echo $user_email; ?>
                                                    <?php if ($is_self): ?>
                                                        <span class="ml-2 text-[10px] font-mono bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.2 rounded font-semibold">YOU</span>
                                                    <?php endif; ?>
                                                </div>
                                                <div class="text-[11px] text-slate-400 font-mono mt-0.5">
                                                    <span><?php echo htmlspecialchars(trim(($u['first_name'] ?? '') . ' ' . ($u['last_name'] ?? ''))); ?></span>
                                                    <span class="text-slate-600">&bull;</span>
                                                    <span class="text-slate-500"><?php echo htmlspecialchars($user_dept_val); ?> (<?php echo htmlspecialchars($user_title_val); ?>)</span>
                                                </div>
                                            </div>
                                        </div>
                                    </td>

                                    <!-- Role Badge -->
                                    <td class="px-5 py-4">
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border <?php echo $role_badge; ?>">
                                            <i class="fa-solid fa-shield mr-1 text-[10px]"></i> <?php echo $user_functional_role; ?>
                                        </span>
                                    </td>

                                    <!-- Security Clearance Badge -->
                                    <td class="px-5 py-4">
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold border <?php echo $clearance_badge; ?>">
                                            <i class="fa-solid <?php echo $clearance_icon; ?> mr-1 text-[10px]"></i> <?php echo htmlspecialchars($user_clearance_val); ?>
                                        </span>
                                    </td>

                                    <!-- MFA Status -->
                                    <td class="px-5 py-4">
                                        <?php if (!empty($u['mfa_secret'])): ?>
                                            <span class="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                <i class="fa-solid fa-shield-check mr-1.5"></i> ENFORCED
                                            </span>
                                        <?php else: ?>
                                            <span class="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                                <i class="fa-solid fa-triangle-exclamation mr-1.5"></i> UNPROTECTED
                                            </span>
                                        <?php endif; ?>
                                    </td>

                                    <!-- Status (Active / Suspended) -->
                                    <td class="px-5 py-4">
                                        <?php if ($is_active): ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                            </span>
                                        <?php else: ?>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30 animate-pulse">
                                                <span class="h-1.5 w-1.5 rounded-full bg-red-400 mr-1.5"></span> SUSPENDED
                                            </span>
                                        <?php endif; ?>
                                    </td>

                                    <!-- Action Buttons -->
                                    <td class="px-5 py-4 text-right whitespace-nowrap">
                                        <div class="inline-flex items-center space-x-1">
                                            <!-- Toggle Suspend / Reactivate Form Button -->
                                            <?php if ($is_self): ?>
                                                <span class="p-2 text-slate-600 cursor-not-allowed text-xs" title="Self-suspension locked by security policy">
                                                    <i class="fa-solid fa-lock"></i>
                                                </span>
                                            <?php else: ?>
                                                <form method="POST" action="" class="inline" onsubmit="return confirm('<?php echo $is_active ? 'CRITICAL SOC ACTION: Are you sure you want to SUSPEND UID-' . $uid . ' (' . $user_email . ')? This will immediately terminate access and block authentication.' : 'Re-activate account access for UID-' . $uid . ' (' . $user_email . ')?'; ?>');">
                                                    <input type="hidden" name="action" value="toggle_status">
                                                    <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                    <input type="hidden" name="new_status" value="<?php echo $is_active ? 0 : 1; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    
                                                    <?php if ($is_active): ?>
                                                        <button type="submit" class="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition" title="Suspend Identity (Isolate Account)">
                                                            <i class="fa-solid fa-user-slash"></i>
                                                        </button>
                                                    <?php else: ?>
                                                        <button type="submit" class="p-2 text-red-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded-lg transition" title="Reactivate Account">
                                                            <i class="fa-solid fa-user-check"></i>
                                                        </button>
                                                    <?php endif; ?>
                                                </form>
                                            <?php endif; ?>

                                            <!-- Edit Role & Clearance Modal Trigger -->
                                            <button onclick="openRoleModal(<?php echo $uid; ?>, '<?php echo addslashes($user_email); ?>', <?php echo $user_role_id; ?>, '<?php echo addslashes($user_functional_role); ?>', '<?php echo addslashes($user_clearance_val); ?>')" class="p-2 text-slate-400 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition" title="Modify RBAC Role & Clearance">
                                                <i class="fa-solid fa-user-gear"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Anomaly Mitigation Intelligence Panel (When Anomalies Detected) -->
                <?php if (!empty($anomalies)): ?>
                <div class="bg-red-950/20 rounded-xl border border-red-500/40 p-5 shadow-xl">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center space-x-2 text-red-400">
                            <i class="fa-solid fa-shield-virus text-xl animate-pulse"></i>
                            <h3 class="font-bold text-sm tracking-wide uppercase">AI Sentinel Flagged Incident(s)</h3>
                        </div>
                        <span class="text-xs font-mono bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded font-bold">
                            <?php echo count($anomalies); ?> ACTIVE THREAT(S)
                        </span>
                    </div>

                    <div class="space-y-3">
                        <?php foreach ($anomalies as $anom): ?>
                        <div class="bg-slate-900/80 p-4 rounded-lg border border-slate-700/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div class="space-y-1">
                                <div class="flex items-center space-x-2">
                                    <span class="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-red-500/20 text-red-400 border border-red-500/30">
                                        <?php echo htmlspecialchars($anom['severity']); ?>
                                    </span>
                                    <h4 class="text-white text-xs font-bold"><?php echo htmlspecialchars($anom['title']); ?></h4>
                                    <span class="text-slate-500 text-xs">&bull;</span>
                                    <span class="text-xs font-mono text-slate-400">Confidence: <?php echo $anom['confidence']; ?>%</span>
                                </div>
                                <p class="text-xs text-slate-300"><?php echo htmlspecialchars($anom['description']); ?></p>
                                <div class="text-[11px] font-mono text-slate-400 flex items-center space-x-3 pt-1">
                                    <span><i class="fa-solid fa-user-secret mr-1 text-slate-500"></i> Target: <span class="text-blue-400"><?php echo htmlspecialchars($anom['target_user']); ?></span></span>
                                    <span><i class="fa-solid fa-network-wired mr-1 text-slate-500"></i> Source: <span class="text-amber-400"><?php echo htmlspecialchars($anom['ip_address']); ?></span></span>
                                </div>
                            </div>
                            
                            <?php if (!empty($anom['target_uid']) && (int) $anom['target_uid'] !== $current_user_id): ?>
                            <div class="flex-shrink-0">
                                <form method="POST" action="" onsubmit="return confirm('Immediately suspend <?php echo addslashes($anom['target_user']); ?> to curb credential abuse?');">
                                    <input type="hidden" name="action" value="toggle_status">
                                    <input type="hidden" name="target_user_id" value="<?php echo (int) $anom['target_uid']; ?>">
                                    <input type="hidden" name="new_status" value="0">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                    <button type="submit" class="bg-red-600 hover:bg-red-700 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition shadow flex items-center">
                                        <i class="fa-solid fa-user-slash mr-1.5"></i> Isolate Identity
                                    </button>
                                </form>
                            </div>
                            <?php endif; ?>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>

            </div>

            <!-- Right Column: AI Sentinel Live Terminal & Audit Stream -->
            <div class="space-y-8">
                
                <!-- AI Sentinel Terminal (Live Backend Heuristic Output) -->
                <div class="cyber-card cyber-brackets rounded-2xl border border-cyan-500/40 shadow-2xl overflow-hidden relative">
                    <div class="cyber-laser-beam opacity-30"></div>
                    <div class="border-b border-slate-800 px-4 py-3 flex justify-between items-center bg-slate-950/85">
                        <div class="flex items-center space-x-2">
                            <div class="flex space-x-1.5 mr-2">
                                <div class="w-2.5 h-2.5 rounded-full bg-red-500/90 shadow-[0_0_6px_#ef4444]"></div>
                                <div class="w-2.5 h-2.5 rounded-full bg-amber-500/90 shadow-[0_0_6px_#f59e0b]"></div>
                                <div class="w-2.5 h-2.5 rounded-full bg-emerald-500/90 shadow-[0_0_6px_#10b981]"></div>
                            </div>
                            <h3 class="text-xs font-orbitron font-bold text-white flex items-center">
                                <i class="fa-solid fa-microchip text-cyan-400 mr-2"></i> AI Sentinel Engine
                            </h3>
                        </div>
                        <span class="text-[10px] <?php echo $active_theme['text']; ?> font-tech tracking-widest border <?php echo $active_theme['border']; ?> px-2.5 py-0.5 rounded <?php echo $active_theme['bg']; ?> font-bold">
                            <?php echo $threat_level; ?>
                        </span>
                    </div>

                    <!-- Terminal Console Content -->
                    <div class="p-4 font-tech text-xs text-slate-400 space-y-2 h-72 overflow-y-auto custom-scrollbar bg-slate-950 relative">
                        <?php foreach ($terminal_logs as $tlog): 
                            $badge_color = match($tlog['type']) {
                                'SYSTEM' => 'text-cyan-400 font-bold',
                                'CRITICAL' => 'text-red-400 font-bold glow-text-red',
                                'WARN' => 'text-amber-400 font-bold',
                                'OK' => 'text-emerald-400 font-bold',
                                'SUMMARY' => 'text-purple-400 font-bold',
                                default => 'text-slate-400'
                            };
                        ?>
                        <div class="flex items-start space-x-2 leading-relaxed">
                            <span class="text-slate-600 select-none">[<?php echo $tlog['time']; ?>]</span>
                            <span class="<?php echo $badge_color; ?> select-none">[<?php echo $tlog['badge']; ?>]</span>
                            <span class="<?php echo ($tlog['type'] === 'CRITICAL') ? 'text-red-300 font-medium' : 'text-slate-300'; ?>">
                                <?php echo htmlspecialchars($tlog['msg']); ?>
                            </span>
                        </div>
                        <?php endforeach; ?>
                        
                        <div class="pt-2 flex items-center space-x-2 text-slate-500">
                            <span class="animate-pulse text-cyan-400 font-bold">&gt;</span>
                            <span class="text-[11px] text-cyan-300/70 font-tech">Sentinel heuristic engine scanning audit streams in real-time...</span>
                        </div>

                        <!-- Scanline overlay -->
                        <div class="absolute inset-0 scanlines-overlay opacity-30"></div>
                    </div>
                </div>

                <!-- Live Audit Stream -->
                <div class="cyber-card cyber-brackets rounded-2xl border border-slate-700/80 shadow-2xl overflow-hidden">
                    <div class="border-b border-slate-800 p-4 bg-slate-950/80 flex justify-between items-center">
                        <h3 class="text-xs font-orbitron font-bold text-white uppercase tracking-wider flex items-center">
                            <i class="fa-solid fa-server text-cyan-400 mr-2"></i> Live Audit Stream
                        </h3>
                        <span class="text-[10px] font-tech text-emerald-400 flex items-center font-bold">
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5 cyber-beacon"></span> LIVE INGEST
                        </span>
                    </div>
                    <div class="bg-slate-950/40">
                        <ul class="divide-y divide-slate-800/60 max-h-80 overflow-y-auto custom-scrollbar font-tech text-xs">
                            <?php if (count($audit_logs) > 0): ?>
                                <?php foreach ($audit_logs as $log): 
                                    $action_type = strtoupper($log['action_type'] ?? 'EVENT');
                                    $action_text = $log['action_description'] ?? 'System Event Logged';
                                    $ip = $log['ip_address'] ?? '127.0.0.1';
                                    $time = $log['created_at'] ?? '';
                                    
                                    $icon_data = match($action_type) {
                                        'LOGIN', 'MFA_AUTH' => ['icon' => 'fa-shield-check', 'color' => 'text-emerald-400', 'glow' => 'glow-emerald'],
                                        'MFA_FAIL', 'LOGIN_FAIL' => ['icon' => 'fa-triangle-exclamation', 'color' => 'text-red-400', 'glow' => 'glow-red'],
                                        'ACCOUNT_SUSPENDED' => ['icon' => 'fa-lock', 'color' => 'text-amber-400', 'glow' => ''],
                                        'ACCOUNT_ACTIVATED' => ['icon' => 'fa-lock-open', 'color' => 'text-emerald-400', 'glow' => ''],
                                        'ROLE_UPDATED' => ['icon' => 'fa-user-gear', 'color' => 'text-cyan-400', 'glow' => ''],
                                        'USER_PROVISIONED' => ['icon' => 'fa-user-plus', 'color' => 'text-purple-400', 'glow' => ''],
                                        'LOGOUT' => ['icon' => 'fa-arrow-right-from-bracket', 'color' => 'text-slate-400', 'glow' => ''],
                                        'SUSPENDED_LOGIN_ATTEMPT' => ['icon' => 'fa-ban', 'color' => 'text-red-500', 'glow' => 'glow-red'],
                                        default => ['icon' => 'fa-shield', 'color' => 'text-slate-400', 'glow' => '']
                                    };
                                ?>
                                <li class="p-3.5 hover:bg-slate-900/60 transition group">
                                    <div class="flex space-x-3">
                                        <div class="flex-shrink-0 mt-0.5">
                                            <i class="fa-solid <?php echo $icon_data['icon']; ?> <?php echo $icon_data['color']; ?> text-xs group-hover:scale-125 transition"></i>
                                        </div>
                                        <div class="min-w-0 flex-1">
                                            <p class="text-xs text-slate-300 font-medium break-words leading-snug"><?php echo htmlspecialchars($action_text); ?></p>
                                            <div class="flex items-center text-[10px] text-slate-500 mt-1 flex-wrap gap-x-2">
                                                <span><i class="fa-solid fa-network-wired mr-0.5 text-cyan-400/70"></i> <?php echo htmlspecialchars($ip); ?></span>
                                                <span class="text-slate-700">|</span>
                                                <span class="text-slate-400">UID-<?php echo htmlspecialchars($log['user_id'] ? str_pad($log['user_id'], 4, '0', STR_PAD_LEFT) : 'SYS'); ?></span>
                                                <span class="text-slate-700">|</span>
                                                <span><?php echo htmlspecialchars($time); ?></span>
                                            </div>
                                        </div>
                                    </div>
                                </li>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <li class="p-8 text-center text-xs text-slate-500 font-tech">
                                    <i class="fa-solid fa-ghost text-2xl mb-2 opacity-30 block text-slate-400"></i>
                                    Audit stream is currently empty.
                                </li>
                            <?php endif; ?>
                        </ul>
                    </div>
                </div>

            </div>
        </div>

        <!-- Academic Footer -->
        <div class="mt-12 text-center border-t border-slate-800 pt-6">
            <p class="text-xs text-slate-500 font-mono tracking-wider">
                <i class="fa-solid fa-shield-halved text-cyan-500/70 mr-1"></i>
                ENTERPRISE ZERO-TRUST IAM PORTAL &bull; ENCRYPTED VIA TLS 1.3 &bull; iam.secure-defense.internal
            </p>
        </div>
        </main>
    </div>

    <!-- MODAL 1: PROVISION IDENTITY (Phase 4.2: Enterprise RBAC & Clearance) -->
    <div id="provisionModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md flex justify-center items-center z-50 p-4">
        <div class="cyber-card cyber-brackets p-6 sm:p-8 rounded-2xl shadow-2xl w-full max-w-lg border border-cyan-500/40 max-h-[90vh] overflow-y-auto custom-scrollbar relative">
            <div class="cyber-laser-beam opacity-30"></div>
            <div class="flex justify-between items-center mb-5 border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2 text-white">
                    <div class="h-8 w-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 glow-cyan-sm">
                        <i class="fa-solid fa-user-plus text-sm"></i>
                    </div>
                    <h2 class="font-orbitron text-base font-bold">Provision Enterprise Identity</h2>
                </div>
                <button onclick="document.getElementById('provisionModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            
            <?php if (isset($provision_msg)) echo $provision_msg; ?>

            <form method="POST" action="">
                <input type="hidden" name="action" value="provision_user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="grid grid-cols-2 gap-3 mb-3.5 font-tech">
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">First Name</label>
                        <input type="text" name="first_name" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g. Jane">
                    </div>
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Last Name</label>
                        <input type="text" name="last_name" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g. Doe">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3.5 font-tech">
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Enterprise Email <span class="text-red-400">*</span></label>
                        <input type="email" name="new_email" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="user@organization.com" required>
                    </div>
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Temporary Password <span class="text-red-400">*</span></label>
                        <input type="password" name="new_password" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="••••••••••••" required>
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3.5 font-tech">
                    <!-- Department Dropdown -->
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Department</label>
                        <select name="department" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Security Operations Center (SOC)">Security Operations Center (SOC)</option>
                            <option value="IT & Cloud Infrastructure">IT & Cloud Infrastructure</option>
                            <option value="Finance & Treasury">Finance & Treasury</option>
                            <option value="Legal, Privacy & Compliance">Legal, Privacy & Compliance</option>
                            <option value="Engineering & DevOps">Engineering & DevOps</option>
                            <option value="Human Resources">Human Resources</option>
                            <option value="General Operations" selected>General Operations</option>
                        </select>
                    </div>

                    <!-- Job Title -->
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Job Title</label>
                        <input type="text" name="job_title" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g. SOC Security Analyst" value="Staff Analyst">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-5 font-tech">
                    <!-- Functional Role Dropdown -->
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Functional Role (RBAC)</label>
                        <select name="role" id="provRoleSelect" onchange="syncProvisioningDefaults()" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Staff" selected>Staff (Standard Employee)</option>
                            <option value="Auditor">Auditor (Compliance Officer)</option>
                            <option value="Admin">Admin (SOC Administrator)</option>
                        </select>
                    </div>

                    <!-- Security Clearance Tier Dropdown -->
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Security Clearance</label>
                        <select name="security_clearance" id="provClearanceSelect" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Tier 1" selected>Tier 1 // Restricted</option>
                            <option value="Tier 2">Tier 2 // Confidential</option>
                            <option value="Tier 3">Tier 3 // Top Secret</option>
                        </select>
                    </div>
                </div>

                <!-- Internal DB Role Mapping (Hidden / Synced) -->
                <input type="hidden" name="role_id" id="provRoleIdHidden" value="4">

                <div class="flex space-x-3 pt-3 border-t border-slate-800">
                    <button type="button" onclick="document.getElementById('provisionModal').classList.add('hidden')" class="w-1/2 bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-tech font-bold py-2.5 rounded-xl border border-slate-700 transition">
                        Cancel
                    </button>
                    <button type="submit" class="cyber-btn w-1/2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-orbitron font-bold py-2.5 rounded-xl transition shadow-lg glow-cyan">
                        Provision Identity
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL 2: EDIT ROLE & CLEARANCE (RBAC) -->
    <div id="roleModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md flex justify-center items-center z-50 p-4">
        <div class="cyber-card cyber-brackets p-6 sm:p-8 rounded-2xl shadow-2xl w-full max-w-md border border-cyan-500/40 relative overflow-hidden">
            <div class="cyber-laser-beam opacity-30"></div>
            <div class="flex justify-between items-center mb-5 border-b border-slate-800 pb-3">
                <div class="flex items-center space-x-2 text-white">
                    <div class="h-8 w-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 glow-cyan-sm">
                        <i class="fa-solid fa-user-gear text-sm"></i>
                    </div>
                    <h2 class="font-orbitron text-base font-bold">Modify RBAC Permissions</h2>
                </div>
                <button onclick="document.getElementById('roleModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <form method="POST" action="">
                <input type="hidden" name="action" value="update_role">
                <input type="hidden" name="target_user_id" id="roleModalUserId">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="mb-4 font-tech">
                    <label class="block text-xs text-slate-400 mb-1">Target Account</label>
                    <div id="roleModalEmail" class="text-xs font-bold text-white bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 font-mono"></div>
                </div>

                <div class="grid grid-cols-2 gap-3 mb-4 font-tech">
                    <!-- Functional Role Dropdown -->
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Functional Role</label>
                        <select name="new_functional_role" id="roleModalFuncRole" onchange="syncRoleModalDefaults()" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Staff">Staff</option>
                            <option value="Auditor">Auditor</option>
                            <option value="Admin">Admin</option>
                        </select>
                    </div>

                    <!-- Security Clearance Dropdown -->
                    <div>
                        <label class="block text-xs text-cyan-300 uppercase mb-1">Clearance Tier</label>
                        <select name="new_clearance" id="roleModalClearance" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Tier 1">Tier 1 (Restricted)</option>
                            <option value="Tier 2">Tier 2 (Confidential)</option>
                            <option value="Tier 3">Tier 3 (Top Secret)</option>
                        </select>
                    </div>
                </div>

                <div class="mb-5 font-tech">
                    <label class="block text-xs text-cyan-300 uppercase mb-1">Database Role Group</label>
                    <select name="new_role_id" id="roleModalSelect" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                        <?php foreach ($roles as $r): ?>
                            <option value="<?php echo (int) $r['role_id']; ?>">
                                <?php echo htmlspecialchars($r['role_name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="flex space-x-3 pt-3 border-t border-slate-800">
                    <button type="button" onclick="document.getElementById('roleModal').classList.add('hidden')" class="w-1/2 bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-tech font-bold py-2.5 rounded-xl border border-slate-700 transition">
                        Cancel
                    </button>
                    <button type="submit" class="cyber-btn w-1/2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-orbitron font-bold py-2.5 rounded-xl transition shadow-lg glow-cyan">
                        Apply Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ============================================================= -->
    <!-- MODAL 3: ANIMATED CYBERSECURITY BIOMETRIC WELCOME HUD         -->
    <!-- ============================================================= -->
    <div id="cyberWelcomeHUD" class="<?php echo $show_welcome_hud ? '' : 'hidden'; ?> fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-md flex items-center justify-center p-4 transition-all duration-300">
        <div class="relative w-full max-w-2xl bg-slate-900/95 border-2 border-cyan-500/60 rounded-2xl p-6 sm:p-8 hud-glow overflow-hidden text-slate-200 shadow-2xl">
            
            <!-- Futuristic Scanlines & Laser Line -->
            <div class="absolute inset-0 pointer-events-none opacity-20" style="background: repeating-linear-gradient(0deg, rgba(6, 182, 212, 0.15), rgba(6, 182, 212, 0.15) 1px, transparent 1px, transparent 3px);"></div>
            <div class="laser-line absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent pointer-events-none shadow-[0_0_12px_#22d3ee]"></div>

            <!-- Header Security Enclave Readout -->
            <div class="flex justify-between items-center border-b border-cyan-500/30 pb-4 mb-6">
                <div class="flex items-center space-x-2">
                    <span class="inline-flex h-2.5 w-2.5 rounded-full bg-cyan-400 animate-ping"></span>
                    <span class="font-mono text-xs text-cyan-400 uppercase tracking-widest font-bold">
                        // ZERO-TRUST IDENTITY ENCLAVE ACCESSED
                    </span>
                </div>
                <div class="flex items-center space-x-3 text-xs font-mono">
                    <span class="text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
                        <i class="fa-solid fa-lock mr-1 text-[10px]"></i> TLS 1.3 SECURED
                    </span>
                    <button onclick="toggleAudioMute()" id="hudMuteBtn" class="text-slate-400 hover:text-cyan-400 transition" title="Toggle Sci-Fi SFX">
                        <i class="fa-solid fa-volume-high"></i>
                    </button>
                </div>
            </div>

            <!-- Center Biometric Scanner & Welcome Readout -->
            <div class="flex flex-col sm:flex-row items-center gap-6 mb-6">
                <!-- Biometric Rotating Scanner -->
                <div class="relative w-28 h-28 flex-shrink-0 flex items-center justify-center">
                    <!-- Rotating Outer Rings -->
                    <div class="absolute inset-0 rounded-full border border-dashed border-cyan-500/40 radar-rotate"></div>
                    <div class="absolute inset-2 rounded-full border border-cyan-400/30"></div>
                    <div class="absolute inset-4 rounded-full bg-cyan-950/40 border border-cyan-500/50 flex items-center justify-center">
                        <i class="fa-solid fa-fingerprint text-4xl text-cyan-400 animate-pulse"></i>
                    </div>
                </div>

                <!-- Identity Welcome Text -->
                <div class="text-center sm:text-left flex-1 space-y-1">
                    <p class="text-xs font-mono text-slate-400 uppercase tracking-wider">
                        IDENTITY CONFIRMED &bull; ACCESS GRANTED
                    </p>
                    <h2 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                        Welcome, <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400"><?php echo htmlspecialchars($user_display_name); ?></span>
                    </h2>
                    <div class="flex flex-wrap items-center justify-center sm:justify-start gap-2 pt-1 font-mono text-xs">
                        <span class="bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded font-semibold">
                            UID-<?php echo str_pad($current_user_id, 4, '0', STR_PAD_LEFT); ?>
                        </span>
                        <span class="text-slate-400">&bull;</span>
                        <span class="text-cyan-300"><?php echo htmlspecialchars($current_user['email']); ?></span>
                    </div>
                </div>
            </div>

            <!-- Clearance & Telemetry Grid -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs mb-6">
                <div class="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">Clearance Level</p>
                    <p class="text-purple-400 font-bold truncate mt-0.5"><?php echo $current_role_info['name']; ?></p>
                </div>
                <div class="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">Encryption</p>
                    <p class="text-emerald-400 font-bold truncate mt-0.5">TLS 1.3 / AES-256</p>
                </div>
                <div class="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">MFA Protocol</p>
                    <p class="text-cyan-400 font-bold truncate mt-0.5">RFC 6238 PASSED</p>
                </div>
                <div class="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">Node Ingress</p>
                    <p class="text-blue-400 font-bold truncate mt-0.5"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'); ?></p>
                </div>
            </div>

            <!-- Terminal Typewriter Readout -->
            <div class="bg-slate-950 p-3 rounded-lg border border-cyan-500/20 font-mono text-[11px] text-slate-400 mb-6 space-y-1">
                <p><span class="text-cyan-400">&gt;</span> Identity handshake established at <span class="text-slate-300"><?php echo date('Y-m-d H:i:s'); ?></span></p>
                <p><span class="text-emerald-400">&gt;</span> Zero-Trust cryptographic challenge verified with clock drift &lt; 0.1s</p>
                <p><span class="text-purple-400">&gt;</span> Assigned Clearance: <span class="text-purple-300"><?php echo $current_role_info['clearance']; ?></span></p>
                <p><span class="text-blue-400">&gt;</span> AI Sentinel anomaly patrol standing by. System baseline: <span class="text-emerald-400 font-bold">ONLINE</span></p>
            </div>

            <!-- Actions & Countdown Progress -->
            <div class="space-y-3">
                <div class="flex items-center justify-between">
                    <span class="text-[11px] font-mono text-slate-500" id="hudTimerText">Auto-entering command center in 6s...</span>
                    <button onclick="dismissCyberWelcomeHUD()" class="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold px-5 py-2 rounded-lg text-xs font-mono uppercase tracking-wider transition shadow-lg shadow-cyan-900/40 flex items-center">
                        <span>Access Command Center</span>
                        <i class="fa-solid fa-arrow-right ml-2 text-[10px]"></i>
                    </button>
                </div>
                <!-- Progress Countdown Bar -->
                <div class="w-full bg-slate-950 rounded-full h-1 overflow-hidden border border-slate-800">
                    <div id="hudProgressBar" class="bg-gradient-to-r from-cyan-400 to-blue-500 h-1 transition-all duration-100 ease-linear" style="width: 100%;"></div>
                </div>
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

        function syncProvisioningDefaults() {
            const role = document.getElementById('provRoleSelect').value;
            const clearance = document.getElementById('provClearanceSelect');
            const hiddenRoleId = document.getElementById('provRoleIdHidden');
            if (role === 'Admin') {
                clearance.value = 'Tier 3';
                hiddenRoleId.value = '1';
            } else if (role === 'Auditor') {
                clearance.value = 'Tier 2';
                hiddenRoleId.value = '3';
            } else {
                clearance.value = 'Tier 1';
                hiddenRoleId.value = '4';
            }
        }

        function syncRoleModalDefaults() {
            const fRole = document.getElementById('roleModalFuncRole').value;
            const clearance = document.getElementById('roleModalClearance');
            const roleSelect = document.getElementById('roleModalSelect');
            if (fRole === 'Admin') {
                clearance.value = 'Tier 3';
                roleSelect.value = '1';
            } else if (fRole === 'Auditor') {
                clearance.value = 'Tier 2';
                roleSelect.value = '3';
            } else {
                clearance.value = 'Tier 1';
                roleSelect.value = '4';
            }
        }

        function openRoleModal(userId, email, currentRoleId, currentFunctionalRole, currentClearance) {
            document.getElementById('roleModalUserId').value = userId;
            document.getElementById('roleModalEmail').innerText = email + ' (UID-' + String(userId).padStart(4, '0') + ')';
            document.getElementById('roleModalSelect').value = currentRoleId;
            
            const funcRoleEl = document.getElementById('roleModalFuncRole');
            if (funcRoleEl) {
                funcRoleEl.value = currentFunctionalRole || (currentRoleId === 1 ? 'Admin' : (currentRoleId === 3 ? 'Auditor' : 'Staff'));
            }
            
            const clearEl = document.getElementById('roleModalClearance');
            if (clearEl) {
                clearEl.value = currentClearance || (currentRoleId === 1 ? 'Tier 3' : (currentRoleId === 3 ? 'Tier 2' : 'Tier 1'));
            }
            
            document.getElementById('roleModal').classList.remove('hidden');
        }

        function toggleSimMenu() {
            const menu = document.getElementById('simMenu');
            menu.classList.toggle('hidden');
        }

        // Close dropdown when clicking outside
        window.addEventListener('click', function(e) {
            const container = document.getElementById('simulationDropdownContainer');
            if (container && !container.contains(e.target)) {
                document.getElementById('simMenu').classList.add('hidden');
            }
        });

        // =============================================================
        // CYBERSECURITY WELCOME HUD SCRIPT (AUDIO & AUTO-TIMER)
        // =============================================================
        let hudTimerInterval = null;
        let hudRemainingSeconds = 6;
        let audioMuted = false;

        function playSciFiChime() {
            if (audioMuted) return;
            try {
                const AudioCtx = window.AudioContext || window.webkitAudioContext;
                if (!AudioCtx) return;
                const ctx = new AudioCtx();

                const now = ctx.currentTime;
                // Note 1: 520Hz
                createBeep(ctx, 520, now, 0.12);
                // Note 2: 660Hz
                createBeep(ctx, 660, now + 0.12, 0.12);
                // Note 3: 880Hz (Confirmation Chord)
                createBeep(ctx, 880, now + 0.24, 0.25);
            } catch (e) {
                // AudioContext autoplay restrictions are handled gracefully
            }
        }

        function createBeep(ctx, freq, startTime, duration) {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();

            osc.type = 'sine';
            osc.frequency.setValueAtTime(freq, startTime);

            gain.gain.setValueAtTime(0.001, startTime);
            gain.gain.exponentialRampToValueAtTime(0.15, startTime + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration);

            osc.connect(gain);
            gain.connect(ctx.destination);

            osc.start(startTime);
            osc.stop(startTime + duration);
        }

        function toggleGlobalAudio() {
            let isMuted = false;
            if (window.CyberAudio) {
                isMuted = CyberAudio.toggleMute();
            } else {
                audioMuted = !audioMuted;
                isMuted = audioMuted;
            }
            audioMuted = isMuted;
            const navIcon = document.getElementById('navMuteIcon');
            if (navIcon) {
                navIcon.className = isMuted ? 'fa-solid fa-volume-xmark text-xs text-red-400' : 'fa-solid fa-volume-high text-xs text-cyan-400';
            }
            const hudBtn = document.getElementById('hudMuteBtn');
            if (hudBtn) {
                hudBtn.innerHTML = isMuted ? '<i class="fa-solid fa-volume-xmark text-red-400"></i>' : '<i class="fa-solid fa-volume-high text-cyan-400"></i>';
            }
            if (!isMuted && window.CyberAudio) {
                CyberAudio.accessGranted();
            }
        }

        function toggleAudioMute() {
            toggleGlobalAudio();
        }

        function dismissCyberWelcomeHUD() {
            if (hudTimerInterval) clearInterval(hudTimerInterval);
            const hud = document.getElementById('cyberWelcomeHUD');
            if (hud) hud.classList.add('hidden');
        }

        function triggerCyberWelcomeHUD(manualTrigger = false) {
            const hud = document.getElementById('cyberWelcomeHUD');
            if (!hud) return;
            hud.classList.remove('hidden');

            playSciFiChime();

            hudRemainingSeconds = 6;
            const totalDuration = 6000;
            const startTime = Date.now();

            if (hudTimerInterval) clearInterval(hudTimerInterval);

            const progressBar = document.getElementById('hudProgressBar');
            const timerText = document.getElementById('hudTimerText');

            hudTimerInterval = setInterval(() => {
                const elapsed = Date.now() - startTime;
                const remaining = Math.max(0, totalDuration - elapsed);
                const percent = (remaining / totalDuration) * 100;

                if (progressBar) progressBar.style.width = percent + '%';
                if (timerText) {
                    const secs = Math.ceil(remaining / 1000);
                    timerText.innerText = 'Auto-entering command center in ' + secs + 's...';
                }

                if (remaining <= 0) {
                    clearInterval(hudTimerInterval);
                    dismissCyberWelcomeHUD();
                }
            }, 100);
        }

        // Trigger automatically on fresh login
        <?php if ($show_welcome_hud): ?>
        window.addEventListener('DOMContentLoaded', () => {
            triggerCyberWelcomeHUD(false);
        });
        <?php endif; ?>
    </script>

    <?php if (isset($provision_msg)): ?>
    <script>
        document.getElementById('provisionModal').classList.remove('hidden');
    </script>
    <?php endif; ?>

</body>
</html>
