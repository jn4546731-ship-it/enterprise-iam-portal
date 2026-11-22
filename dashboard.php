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
    1 => ['name' => 'Super Admin', 'desc' => 'Full administrative access across identities and system telemetry'],
    2 => ['name' => 'Security Analyst', 'desc' => 'Access monitoring, threat triage, and incident response'],
    3 => ['name' => 'IAM Auditor', 'desc' => 'Read-only compliance and immutable audit log review'],
    4 => ['name' => 'Employee', 'desc' => 'Standard corporate identity and workstation access']
];

foreach ($standard_roles as $roleId => $rData) {
    $stmt_check = $conn->prepare("SELECT role_id FROM roles WHERE role_name = ?");
    $stmt_check->bind_param("s", $rData['name']);
    $stmt_check->execute();
    $chk_res = $stmt_check->get_result();
    
    if ($chk_res->num_rows === 0) {
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
    unset($_SESSION['fresh_login']);
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
// 2. ACTIVE FEATURE: ENCLAVE EMERGENCY LOCKDOWN & LIFT
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'emergency_lockdown') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        // Suspend all users except current admin
        $lock_stmt = $conn->prepare("UPDATE users SET is_active = 0 WHERE user_id != ?");
        $lock_stmt->bind_param("i", $current_user_id);
        $lock_stmt->execute();
        $affected = $lock_stmt->affected_rows;

        $action_type = "EMERGENCY_LOCKDOWN_TRIGGERED";
        $action_desc = "CRITICAL DEFENSE ACTION: Enclave Emergency Lockdown engaged by CISO/Admin UID-{$current_user_id}. {$affected} workforce identities isolated and suspended immediately.";
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
        $log_stmt->execute();

        $feedback_alert = "<div class='p-4 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-mono flex items-center gap-2.5 mb-6 shadow-sm'><span class='w-2.5 h-2.5 rounded-full bg-red-400 animate-ping'></span><span><strong>EMERGENCY LOCKDOWN ENGAGED:</strong> All non-admin workforce accounts have been suspended immediately. Lateral movement is blocked.</span></div>";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'lift_lockdown') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        // Reactivate standard workforce accounts
        $lift_stmt = $conn->query("UPDATE users SET is_active = 1 WHERE is_active = 0");
        $reactivated = $lift_stmt ? $conn->affected_rows : 0;

        $action_type = "EMERGENCY_LOCKDOWN_LIFTED";
        $action_desc = "ADMIN ACTION: Enclave Lockdown lifted by CISO/Admin UID-{$current_user_id}. {$reactivated} workforce accounts restored to active state.";
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
        $log_stmt->execute();

        $feedback_alert = "<div class='p-4 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-2.5 mb-6 shadow-sm'><i class='fa-solid fa-lock-open text-emerald-400'></i><span><strong>LOCKDOWN LIFTED:</strong> {$reactivated} workforce accounts reactivated. Enclave normalized.</span></div>";
    }
}

// -------------------------------------------------------------
// 3. WORKFORCE IDENTITY PROVISIONING HANDLER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'provision_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $provision_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-4'><i class='fa-solid fa-triangle-exclamation mr-1.5'></i> Security Error: Invalid or expired CSRF token.</div>";
    } else {
        $fname = trim($_POST['first_name'] ?? '');
        $lname = trim($_POST['last_name'] ?? '');
        $new_email = trim($_POST['new_email'] ?? '');
        $new_pass = $_POST['new_password'] ?? '';
        $new_role_id = (int) ($_POST['role_id'] ?? 4);
        $dept = trim($_POST['department'] ?? 'General Operations');
        $job_title = trim($_POST['job_title'] ?? 'Staff Analyst');
        $functional_role = trim($_POST['role'] ?? 'Staff');
        $clearance = trim($_POST['security_clearance'] ?? 'Tier 1');

        if (empty($fname) || empty($lname) || empty($new_email) || empty($new_pass)) {
            $provision_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-4'><i class='fa-solid fa-triangle-exclamation mr-1.5'></i> Validation Error: All fields are required.</div>";
        } elseif (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
            $provision_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-4'><i class='fa-solid fa-triangle-exclamation mr-1.5'></i> Format Error: Invalid email address format.</div>";
        } else {
            // Check for duplicate identity
            $dup_check = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
            $dup_check->bind_param("s", $new_email);
            $dup_check->execute();
            if ($dup_check->get_result()->num_rows > 0) {
                $provision_msg = "<div class='p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono mb-4'><i class='fa-solid fa-triangle-exclamation mr-1.5'></i> Conflict: Identity with this email already exists.</div>";
            } else {
                $hashed_pass = password_hash($new_pass, PASSWORD_BCRYPT);
                $ins_stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password_hash, role_id, department, job_title, role, security_clearance, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)");
                $ins_stmt->bind_param("ssssissss", $fname, $lname, $new_email, $hashed_pass, $new_role_id, $dept, $job_title, $functional_role, $clearance);
                
                if ($ins_stmt->execute()) {
                    $new_uid = $ins_stmt->insert_id;
                    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
                    $log_act = "USER_PROVISIONED";
                    $log_desc = "Identity Provisioned: {$fname} {$lname} ({$new_email}) registered with Role {$functional_role} / {$clearance} by Admin UID-{$current_user_id}";
                    $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                    $log_stmt->bind_param("isss", $current_user_id, $log_act, $log_desc, $client_ip);
                    $log_stmt->execute();

                    $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono mb-4 flex items-center'><i class='fa-solid fa-circle-check mr-2'></i> Identity provisioned successfully: {$new_email} (UID-{$new_uid}).</div>";
                } else {
                    $provision_msg = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono mb-4'><i class='fa-solid fa-triangle-exclamation mr-1.5'></i> Database Error: Failed to provision identity.</div>";
                }
            }
        }
    }
}

// -------------------------------------------------------------
// 4. RBAC ROLE & CLEARANCE UPDATE HANDLER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_role') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $new_role_id = (int) ($_POST['new_role_id'] ?? 4);
        $new_func_role = trim($_POST['new_functional_role'] ?? 'Staff');
        $new_clearance = trim($_POST['new_clearance'] ?? 'Tier 1');

        if ($target_user_id > 0) {
            $upd_stmt = $conn->prepare("UPDATE users SET role_id = ?, role = ?, security_clearance = ? WHERE user_id = ?");
            $upd_stmt->bind_param("issi", $new_role_id, $new_func_role, $new_clearance, $target_user_id);
            if ($upd_stmt->execute()) {
                $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
                $role_name_applied = $roles[$new_role_id]['role_name'] ?? 'Employee';
                $action_type = "ROLE_UPDATED";
                $action_desc = "RBAC Policy Modified: User UID-{$target_user_id} assigned Role: {$new_func_role} ({$role_name_applied}) / Clearance: {$new_clearance} by Admin UID-{$current_user_id}";
                
                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();

                $feedback_alert = "<div class='p-3.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400 text-xs font-mono flex items-center'><i class='fa-solid fa-user-shield mr-2'></i> Access policy updated: User UID-{$target_user_id} promoted/adjusted to {$new_func_role} ({$new_clearance}).</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 5. USER SUSPENSION HANDLER (KILL-SWITCH REVOCATION)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'suspend_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        if ($target_user_id === $current_user_id) {
            $feedback_alert = "<div class='p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> Security Rule Violation: You cannot suspend your own administrative session.</div>";
        } elseif ($target_user_id > 0) {
            $susp_stmt = $conn->prepare("UPDATE users SET is_active = 0 WHERE user_id = ?");
            $susp_stmt->bind_param("i", $target_user_id);
            if ($susp_stmt->execute()) {
                $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
                $action_type = "ACCOUNT_SUSPENDED";
                $action_desc = "Kill-Switch Engaged: Account UID-{$target_user_id} suspended immediately. Session tokens invalidated.";
                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();

                $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-ban mr-2'></i> Account UID-{$target_user_id} suspended. Real-time access terminated.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 6. USER ACTIVATION HANDLER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'activate_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        if ($target_user_id > 0) {
            $act_stmt = $conn->prepare("UPDATE users SET is_active = 1 WHERE user_id = ?");
            $act_stmt->bind_param("i", $target_user_id);
            if ($act_stmt->execute()) {
                $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
                $action_type = "ACCOUNT_ACTIVATED";
                $action_desc = "Identity Reactivated: Account UID-{$target_user_id} restored to active operational status.";
                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();

                $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center'><i class='fa-solid fa-circle-check mr-2'></i> Account UID-{$target_user_id} reactivated successfully.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 7. USER PURGE / DEPROVISIONING HANDLER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'purge_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        if ($target_user_id === $current_user_id) {
            $feedback_alert = "<div class='p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> Self-Destruct Blocked: You cannot purge your own root identity.</div>";
        } elseif ($target_user_id > 0) {
            $del_stmt = $conn->prepare("DELETE FROM users WHERE user_id = ?");
            $del_stmt->bind_param("i", $target_user_id);
            if ($del_stmt->execute()) {
                $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
                $action_type = "USER_PURGED";
                $action_desc = "Deprovisioning Complete: Identity record UID-{$target_user_id} purged from directory by Admin UID-{$current_user_id}";
                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();

                $feedback_alert = "<div class='p-3.5 rounded-lg bg-slate-500/10 border border-slate-500/30 text-slate-300 text-xs font-mono flex items-center'><i class='fa-solid fa-trash-can mr-2'></i> Identity UID-{$target_user_id} permanently purged from directory.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 8. SIMULATION / BASELINE HANDLER (PRESERVED BACKEND)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'simulate_threat') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $scenario = $_POST['scenario'] ?? 'brute_force';
        if ($scenario === 'reset') {
            AISentinel::clearSimulation($conn);
            $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono flex items-center'><i class='fa-solid fa-rotate-left mr-2'></i> Simulation telemetry cleared. Threat baseline restored to normal.</div>";
        } else {
            AISentinel::injectSimulation($conn, $scenario);
            $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> <strong>Threat Telemetry Injected:</strong> Simulation ({$scenario}) recorded in audit stream.</div>";
        }
    }
}

// -------------------------------------------------------------
// 9. FETCH SYSTEM METRICS & DIRECTORY DATA
// -------------------------------------------------------------
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
$active_users_count = $total_users - $suspended_count;
$mfa_pending = $total_users - $mfa_enabled;
$active_roles_count = count($roles);

// Failed logins in last 24 hours
$failed_logins_query = $conn->query("
    SELECT COUNT(*) as failed_count 
    FROM audit_logs 
    WHERE (action_type LIKE '%FAIL%' OR action_type LIKE '%INVALID%' OR action_type LIKE '%DENIED%') 
      AND created_at >= NOW() - INTERVAL 24 HOUR
");
$failed_logins_24h = $failed_logins_query ? (int) $failed_logins_query->fetch_assoc()['failed_count'] : 0;

// Last 7 days authentication activity (Success vs Failed)
$activity_7d = [];
for ($i = 6; $i >= 0; $i--) {
    $date_key = date('Y-m-d', strtotime("-$i days"));
    $day_name = date('D', strtotime("-$i days"));
    $display_date = date('M j', strtotime("-$i days"));
    $activity_7d[$date_key] = [
        'date' => $date_key,
        'day' => $day_name,
        'label' => $display_date,
        'success' => 0,
        'failed' => 0
    ];
}

$chart_query = $conn->query("
    SELECT DATE(created_at) as log_date,
           SUM(CASE WHEN (action_type LIKE '%FAIL%' OR action_type LIKE '%INVALID%' OR action_type LIKE '%DENIED%') THEN 1 ELSE 0 END) as failed_cnt,
           SUM(CASE WHEN (action_type LIKE '%LOGIN%' OR action_type = 'MFA_AUTH' OR action_type = 'VAULT_ACCESS_GRANTED') AND action_type NOT LIKE '%FAIL%' THEN 1 ELSE 0 END) as success_cnt
    FROM audit_logs
    WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
    GROUP BY DATE(created_at)
");

if ($chart_query) {
    while ($r = $chart_query->fetch_assoc()) {
        $ld = $r['log_date'];
        if (isset($activity_7d[$ld])) {
            $activity_7d[$ld]['success'] = (int)$r['success_cnt'];
            $activity_7d[$ld]['failed'] = (int)$r['failed_cnt'];
        }
    }
}

// Compute totals and max value for chart scaling
$max_activity_count = 1;
$total_7d_success = 0;
$total_7d_failed = 0;
foreach ($activity_7d as $day_data) {
    $total_7d_success += $day_data['success'];
    $total_7d_failed += $day_data['failed'];
    if ($day_data['success'] > $max_activity_count) $max_activity_count = $day_data['success'];
    if ($day_data['failed'] > $max_activity_count) $max_activity_count = $day_data['failed'];
}

// Fetch structured Recent Authentication & Audit Logs (70% left panel)
$recent_auth_logs = [];
$recent_logs_query = $conn->query("
    SELECT a.log_id, a.user_id, a.action_type, a.action_description, a.ip_address, a.created_at,
           COALESCE(u.email, 'system@internal') AS user_email,
           u.first_name, u.last_name
    FROM audit_logs a
    LEFT JOIN users u ON a.user_id = u.user_id
    ORDER BY a.log_id DESC
    LIMIT 10
");
if ($recent_logs_query) {
    while ($row = $recent_logs_query->fetch_assoc()) {
        $recent_auth_logs[] = $row;
    }
}

// Check for active enclave lockdown
$lockdown_active = false;
$other_users_query = $conn->query("SELECT COUNT(*) as c FROM users WHERE user_id != {$current_user_id} AND is_active = 0");
if ($other_users_query && (int)$other_users_query->fetch_assoc()['c'] > 0 && (int)$other_users_query->fetch_assoc()['c'] === ($total_users - 1)) {
    $lockdown_active = true;
}

// Format audit log events cleanly
function getAuditLogDisplayData($action_type, $action_description) {
    $type = strtoupper(trim((string)$action_type));
    
    if (str_contains($type, 'FAIL') || str_contains($type, 'INVALID') || str_contains($type, 'DENIED') || str_contains($type, 'PURGED')) {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">Failed</span>';
        $icon = 'fa-circle-xmark text-red-400';
    } elseif ($type === 'ACCOUNT_SUSPENDED' || $type === 'EMERGENCY_LOCKDOWN_TRIGGERED') {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">Suspended</span>';
        $icon = 'fa-triangle-exclamation text-amber-400';
    } elseif ($type === 'ROLE_UPDATED' || $type === 'USER_PROVISIONED') {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-sky-500/10 text-sky-400 border border-sky-500/20">Policy</span>';
        $icon = 'fa-user-gear text-sky-400';
    } elseif ($type === 'MFA_AUTH') {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">MFA Verified</span>';
        $icon = 'fa-shield-halved text-emerald-400';
    } elseif ($type === 'LOGIN' || $type === 'LOGIN_SUCCESS' || $type === 'VAULT_ACCESS_GRANTED' || $type === 'ACCOUNT_ACTIVATED' || $type === 'EMERGENCY_LOCKDOWN_LIFTED' || $type === 'BASELINE_RESET') {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Success</span>';
        $icon = 'fa-circle-check text-emerald-400';
    } elseif ($type === 'LOGOUT') {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20">Signed Out</span>';
        $icon = 'fa-arrow-right-from-bracket text-slate-400';
    } else {
        $badge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-500/10 text-slate-400 border border-slate-500/20">Info</span>';
        $icon = 'fa-circle-info text-slate-400';
    }
    
    $event_name = match($type) {
        'LOGIN', 'LOGIN_SUCCESS' => 'Login Success',
        'LOGIN_FAIL' => 'Failed Login Attempt',
        'MFA_AUTH' => 'MFA Verified (TOTP)',
        'MFA_FAIL' => 'Invalid MFA Code',
        'LOGOUT' => 'User Signed Out',
        'USER_PROVISIONED' => 'User Account Provisioned',
        'USER_PURGED' => 'User Account Purged',
        'ROLE_UPDATED' => 'Role & Clearance Updated',
        'ACCOUNT_SUSPENDED' => 'Account Suspended',
        'ACCOUNT_ACTIVATED' => 'Account Reactivated',
        'VAULT_ACCESS_GRANTED' => 'Vault Secret Accessed',
        'SUSPENDED_LOGIN_ATTEMPT' => 'Suspended User Blocked',
        'EMERGENCY_LOCKDOWN_TRIGGERED' => 'Enclave Lockdown Engaged',
        'EMERGENCY_LOCKDOWN_LIFTED' => 'Enclave Lockdown Lifted',
        'BASELINE_RESET' => 'Threat Baseline Reset',
        default => ucwords(strtolower(str_replace('_', ' ', $type)))
    };
    
    return [
        'badge' => $badge,
        'icon' => $icon,
        'event_name' => $event_name
    ];
}
?>
<!DOCTYPE html>
<html class="dark" lang="en">
<head>
    <meta charset="utf-8"/>
    <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
    <meta name="color-scheme" content="dark light">
    <title>Identity &amp; Access Overview &mdash; Enterprise IAM</title>

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

    <!-- 100% Offline Air-Gapped Tailwind & Theme Engine -->
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
    <!-- LEFT FIXED NAVIGATION SIDEBAR (Standard Enterprise IAM Modules)            -->
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

            <!-- Categorized Navigation (Clean Standard IAM Modules) -->
            <nav class="flex-1 px-3 py-2 space-y-1 text-xs font-sans">
                <!-- 1. Overview -->
                <a href="dashboard.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#21262d] border border-[#30363d] text-white shadow-xs font-medium">
                    <i class="fa-solid fa-table-cells-large text-sm text-[#2f81f7] w-4 text-center"></i>
                    <span>Overview</span>
                </a>

                <!-- 2. Authentication & MFA -->
                <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-fingerprint text-sm w-4 text-center"></i>
                    <span>Authentication &amp; MFA</span>
                </a>

                <!-- 3. Users & Directory -->
                <a href="#usersDirectory" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-users text-sm w-4 text-center"></i>
                    <span>Users &amp; Directory</span>
                </a>

                <!-- 4. Roles & Permissions (RBAC) -->
                <a href="#usersDirectory" onclick="openRoleModal(<?php echo $current_user_id; ?>, '<?php echo htmlspecialchars($current_user['email']); ?>', <?php echo $current_role_id; ?>, '<?php echo htmlspecialchars($current_functional_role); ?>', '<?php echo htmlspecialchars($current_clearance); ?>')" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-user-shield text-sm w-4 text-center"></i>
                    <span>Roles &amp; Permissions (RBAC)</span>
                </a>

                <!-- 5. Access Policies -->
                <a href="vault.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-lock text-sm w-4 text-center"></i>
                    <span>Access Policies</span>
                </a>

                <!-- 6. Audit Logs -->
                <a href="audit_report.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-list-check text-sm w-4 text-center"></i>
                    <span>Audit Logs</span>
                </a>

                <!-- 7. Active Sessions -->
                <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-key text-sm w-4 text-center"></i>
                    <span>Active Sessions</span>
                </a>

                <!-- 8. System Settings -->
                <a href="#systemSettings" onclick="alert('System Settings:\n• Enclave: iam.secure-defense.internal\n• Directory Sync: Real-time MySQL\n• Protocol: RFC 6238 TOTP\n• Air-Gap: 100% Offline Verified');" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-gear text-sm w-4 text-center"></i>
                    <span>System Settings</span>
                </a>
            </nav>

            <!-- Current User Summary Card in Sidebar Footer -->
            <div class="p-3 border-t border-[#30363d] bg-[#0d1117]">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded-full bg-[#2f81f7]/15 text-[#2f81f7] flex items-center justify-center font-bold text-xs shrink-0 border border-[#2f81f7]/30">
                        <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                    </div>
                    <div class="min-w-0">
                        <p class="text-xs font-semibold text-white truncate"><?php echo htmlspecialchars($user_display_name); ?></p>
                        <p class="text-[10px] font-mono text-emerald-400 truncate flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            <span><?php echo htmlspecialchars($current_functional_role); ?> (Active)</span>
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
                <input type="text" id="directorySearchInput" onkeyup="filterDirectoryTable()" placeholder="Search users, roles, audit logs... (Ctrl+K)" class="w-full bg-[#0d1117] border border-[#30363d] rounded-md pl-9 pr-14 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#2f81f7] transition font-sans">
                <kbd class="absolute right-2.5 top-1/2 -translate-y-1/2 font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#161b22] border border-[#30363d] text-slate-400 uppercase">Ctrl+K</kbd>
            </div>

            <!-- Top Header Right Controls -->
            <div class="flex items-center gap-3">
                <!-- Environment Badge -->
                <div class="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0d1117] border border-[#30363d] text-xs font-mono text-slate-300">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    <span>Environment: Production</span>
                </div>

                <!-- Theme Switcher -->
                <button id="themeToggleBtn" onclick="toggleTheme()" class="p-2 rounded-md bg-[#0d1117] border border-[#30363d] text-slate-300 hover:text-white hover:bg-[#21262d] transition text-xs" title="Toggle Light / Dark mode">
                    <i id="themeToggleIcon" class="fa-solid fa-sun text-amber-400"></i>
                </button>

                <!-- User Profile (Full Job Title Without Awkward Truncation) -->
                <div class="flex items-center gap-3 pl-3 border-l border-[#30363d]">
                    <div class="w-8 h-8 rounded-full bg-[#2f81f7]/20 border border-[#2f81f7]/40 flex items-center justify-center font-bold text-xs text-[#2f81f7] shrink-0">
                        <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                    </div>
                    <div class="hidden md:flex flex-col text-left">
                        <span class="text-xs font-semibold text-white leading-tight whitespace-nowrap"><?php echo htmlspecialchars($user_display_name); ?></span>
                        <span class="text-[11px] font-mono text-slate-400 whitespace-nowrap"><?php echo htmlspecialchars($current_job_title); ?></span>
                    </div>
                    <a href="logout.php" class="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-md transition ml-1" title="Sign out of enterprise session">
                        <i class="fa-solid fa-arrow-right-from-bracket text-xs"></i>
                    </a>
                </div>
            </div>
        </header>

        <!-- Main Content Area -->
        <main class="relative pt-20 w-full min-h-screen bg-[#0d1117] px-6 py-6 text-[#e6edf3]">
            
            <!-- Active Lockdown Notification Banner (if engaged) -->
            <?php if ($lockdown_active): ?>
            <div class="mb-6 p-4 rounded-lg bg-red-500/15 border border-red-500/40 text-red-200 text-xs font-mono flex flex-col sm:flex-row items-center justify-between gap-3 shadow-md">
                <div class="flex items-center gap-3">
                    <span class="w-3 h-3 rounded-full bg-red-400 animate-ping"></span>
                    <div>
                        <strong class="text-white">ENCLAVE EMERGENCY LOCKDOWN ACTIVE:</strong>
                        <span class="text-red-300 ml-1">All workforce accounts remain suspended. Access is restricted exclusively to Root CISO.</span>
                    </div>
                </div>
                <form method="POST" action="" class="shrink-0">
                    <input type="hidden" name="action" value="lift_lockdown">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <button type="submit" class="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-sans text-xs font-bold transition flex items-center gap-1.5 shadow">
                        <i class="fa-solid fa-lock-open"></i> Lift Lockdown
                    </button>
                </form>
            </div>
            <?php endif; ?>

            <!-- Feedback Alert (Flash Message) -->
            <?php if (!empty($feedback_alert)): ?>
                <div class="mb-6"><?php echo $feedback_alert; ?></div>
            <?php endif; ?>

            <!-- 1. BREADCRUMB, MAIN HEADING & ACTION BUTTONS -->
            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#30363d]">
                <div>
                    <!-- Clean Breadcrumb & Environment Status -->
                    <div class="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1.5">
                        <span>Administration</span>
                        <span class="text-slate-600">/</span>
                        <span class="text-slate-200 font-semibold">Access Overview</span>
                        <span class="text-slate-600 ml-1">&bull;</span>
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Environment: Production
                        </span>
                    </div>
                    <!-- Main Heading & Subtitle -->
                    <h1 class="text-2xl font-bold text-white tracking-tight">Identity &amp; Access Overview</h1>
                    <p class="text-xs text-slate-400 mt-1 max-w-2xl">Manage user accounts, role assignments, TOTP multi-factor authentication, and session audit logs.</p>
                </div>

                <!-- Practical Administrative Action Buttons -->
                <div class="flex flex-wrap items-center gap-2.5 shrink-0">
                    <button type="button" onclick="document.getElementById('provisionModal').classList.remove('hidden')" class="px-3.5 py-2 rounded-md bg-[#2f81f7] hover:bg-blue-600 text-white text-xs font-semibold shadow-xs transition flex items-center gap-2">
                        <i class="fa-solid fa-user-plus text-xs"></i>
                        <span>+ Add User</span>
                    </button>

                    <a href="dashboard.php?export=csv" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-download text-xs text-slate-400"></i>
                        <span>Export Audit CSV</span>
                    </a>

                    <a href="#usersDirectory" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-user-shield text-xs text-[#2f81f7]"></i>
                        <span>Manage Roles</span>
                    </a>
                </div>
            </div>

            <!-- 2. REFINED KPI STRIP (Subtle 1px Borders, Flat Dark Surfaces, Real Data) -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 my-6">
                <!-- Card 1: Total Users -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">Total Users</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Active Directory</span>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight"><?php echo $total_users; ?></div>
                    <div class="mt-2 text-xs text-slate-400 font-sans">
                        Active: <strong class="text-slate-200"><?php echo $active_users_count; ?></strong> &bull; Suspended: <strong class="text-slate-200"><?php echo $suspended_count; ?></strong>
                    </div>
                </div>

                <!-- Card 2: MFA Enrollment Rate -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">MFA Enrollment Rate</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-sky-500/10 text-sky-400 border border-sky-500/20">RFC 6238 TOTP</span>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight"><?php echo $mfa_rate; ?>%</div>
                    <div class="mt-2 text-xs text-slate-400 font-sans">
                        <strong class="text-slate-200"><?php echo $mfa_enabled; ?></strong> Enrolled &bull; <strong class="text-slate-200"><?php echo $mfa_pending; ?></strong> Pending Setup
                    </div>
                </div>

                <!-- Card 3: Active Roles (RBAC) -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">Active Roles (RBAC)</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">Configured</span>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight"><?php echo $active_roles_count; ?></div>
                    <div class="mt-2 text-xs text-slate-400 font-sans truncate" title="Super Admin, Security Analyst, IAM Auditor, Employee">
                        Super Admin, Analyst, Auditor, Employee
                    </div>
                </div>

                <!-- Card 4: Failed Logins (24h) -->
                <div class="p-5 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs">
                    <div class="flex items-center justify-between text-slate-400 text-xs mb-2">
                        <span class="font-medium text-slate-300">Failed Logins (24h)</span>
                        <?php if ($failed_logins_24h === 0): ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Normal</span>
                        <?php else: ?>
                            <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">Flagged</span>
                        <?php endif; ?>
                    </div>
                    <div class="text-2xl font-bold text-white tracking-tight"><?php echo $failed_logins_24h; ?></div>
                    <div class="mt-2 text-xs text-slate-400 font-sans">
                        <?php echo $failed_logins_24h === 0 ? 'No failed attempts recorded' : $failed_logins_24h . ' failed events in last 24h'; ?>
                    </div>
                </div>
            </div>

            <!-- 3. TWO FUNCTIONAL PANELS: RECENT AUDIT LOGS (70%) + AUTHENTICATION ACTIVITY (30%) -->
            <div class="grid grid-cols-1 lg:grid-cols-10 gap-6 mb-8">
                
                <!-- Left/Main Panel (70% width -> lg:col-span-7): Recent Authentication & Audit Logs -->
                <div class="lg:col-span-7 p-6 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs flex flex-col justify-between">
                    <div>
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#30363d] mb-4 gap-2">
                            <div>
                                <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                                    <i class="fa-solid fa-list-check text-[#2f81f7]"></i>
                                    <span>Recent Authentication &amp; Audit Logs</span>
                                </h3>
                                <p class="text-xs text-slate-400 mt-0.5">Immutable event stream recording sign-in verifications and administrative actions.</p>
                            </div>
                            <a href="audit_report.php" class="text-xs text-[#2f81f7] hover:underline font-mono inline-flex items-center gap-1 self-start sm:self-auto">
                                <span>Full Audit Explorer</span>
                                <i class="fa-solid fa-arrow-right text-[10px]"></i>
                            </a>
                        </div>

                        <!-- Structured Table -->
                        <div class="overflow-x-auto custom-scrollbar">
                            <table class="w-full text-left text-xs font-sans">
                                <thead class="text-slate-400 font-mono text-[11px] uppercase tracking-wider bg-[#0d1117] border-b border-[#30363d]">
                                    <tr>
                                        <th class="px-3.5 py-2.5">Timestamp</th>
                                        <th class="px-3.5 py-2.5">User</th>
                                        <th class="px-3.5 py-2.5">Event</th>
                                        <th class="px-3.5 py-2.5">IP Address</th>
                                        <th class="px-3.5 py-2.5 text-right">Status</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-[#30363d]">
                                    <?php if (!empty($recent_auth_logs)): ?>
                                        <?php foreach ($recent_auth_logs as $log): 
                                            $disp = getAuditLogDisplayData($log['action_type'], $log['action_description']);
                                            $user_email = htmlspecialchars($log['user_email']);
                                            $display_name = trim(($log['first_name'] ?? '') . ' ' . ($log['last_name'] ?? ''));
                                            if (empty($display_name)) {
                                                $display_name = explode('@', $user_email)[0];
                                            }
                                        ?>
                                        <tr class="hover:bg-[#21262d]/60 transition">
                                            <td class="px-3.5 py-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                                                <?php echo htmlspecialchars($log['created_at']); ?>
                                            </td>
                                            <td class="px-3.5 py-3">
                                                <div class="flex items-center gap-2">
                                                    <div class="w-6 h-6 rounded-full bg-[#21262d] text-slate-300 border border-[#30363d] flex items-center justify-center text-[10px] font-bold shrink-0">
                                                        <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                                                    </div>
                                                    <div class="min-w-0">
                                                        <div class="text-white font-medium text-xs truncate max-w-[170px]" title="<?php echo $user_email; ?>">
                                                            <?php echo $user_email; ?>
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td class="px-3.5 py-3">
                                                <div class="flex items-center gap-1.5">
                                                    <i class="fa-solid <?php echo $disp['icon']; ?> text-[10px]"></i>
                                                    <span class="text-slate-200 font-medium"><?php echo $disp['event_name']; ?></span>
                                                </div>
                                                <div class="text-[10px] text-slate-400 truncate max-w-[240px] font-mono mt-0.5" title="<?php echo htmlspecialchars($log['action_description']); ?>">
                                                    <?php echo htmlspecialchars($log['action_description']); ?>
                                                </div>
                                            </td>
                                            <td class="px-3.5 py-3 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                                                <code><?php echo htmlspecialchars($log['ip_address'] ?? '127.0.0.1'); ?></code>
                                            </td>
                                            <td class="px-3.5 py-3 text-right whitespace-nowrap">
                                                <?php echo $disp['badge']; ?>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <tr>
                                            <td colspan="5" class="px-4 py-8 text-center text-slate-500 font-mono text-xs">
                                                No authentication events recorded in audit log.
                                            </td>
                                        </tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="mt-4 pt-3 border-t border-[#30363d] flex items-center justify-between text-xs text-slate-400 font-mono">
                        <span>Showing last 10 audit records</span>
                        <a href="audit_report.php" class="text-slate-300 hover:text-white transition flex items-center gap-1">
                            <span>Export Full Report</span>
                            <i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>
                        </a>
                    </div>
                </div>

                <!-- Right Panel (30% width -> lg:col-span-3): Authentication Activity (Last 7 Days) -->
                <div class="lg:col-span-3 p-6 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs flex flex-col justify-between">
                    <div>
                        <div class="flex items-center justify-between pb-4 border-b border-[#30363d] mb-4">
                            <div>
                                <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                                    <i class="fa-solid fa-chart-simple text-[#2f81f7]"></i>
                                    <span>Authentication Activity</span>
                                </h3>
                                <p class="text-xs text-slate-400 mt-0.5">Last 7 days sign-ins</p>
                            </div>
                            <span class="text-[11px] font-mono text-slate-300 bg-[#0d1117] px-2 py-0.5 rounded border border-[#30363d]">
                                <?php echo ($total_7d_success + $total_7d_failed); ?> Events
                            </span>
                        </div>

                        <!-- Clean Legend -->
                        <div class="flex items-center gap-4 text-xs font-mono text-slate-400 mb-6">
                            <div class="flex items-center gap-1.5">
                                <span class="w-2.5 h-2.5 rounded-xs bg-[#2f81f7]"></span>
                                <span class="text-slate-300 font-medium">Success (<?php echo $total_7d_success; ?>)</span>
                            </div>
                            <div class="flex items-center gap-1.5">
                                <span class="w-2.5 h-2.5 rounded-xs bg-[#f85149]"></span>
                                <span class="text-slate-300 font-medium">Failed (<?php echo $total_7d_failed; ?>)</span>
                            </div>
                        </div>

                        <!-- Clean Bar Chart Visualization -->
                        <div class="h-44 flex items-end justify-between gap-2 pt-4 pb-2 border-b border-[#30363d]">
                            <?php foreach ($activity_7d as $day): 
                                $succ_h = $day['success'] > 0 ? max(12, round(($day['success'] / $max_activity_count) * 100)) : 4;
                                $fail_h = $day['failed'] > 0 ? max(12, round(($day['failed'] / $max_activity_count) * 100)) : ($day['success'] === 0 ? 4 : 0);
                            ?>
                            <div class="flex-1 flex flex-col items-center h-full justify-end group relative">
                                <!-- Tooltip on hover -->
                                <div class="opacity-0 group-hover:opacity-100 transition pointer-events-none absolute -top-10 bg-[#0d1117] text-white text-[10px] font-mono py-1 px-2 rounded border border-[#30363d] shadow-lg z-20 whitespace-nowrap">
                                    <?php echo $day['label']; ?>: <?php echo $day['success']; ?> ok, <?php echo $day['failed']; ?> fail
                                </div>
                                
                                <!-- Dual Bar Stack -->
                                <div class="w-full flex items-end justify-center gap-1 h-32">
                                    <!-- Success Bar -->
                                    <div class="w-3 rounded-t-xs bg-[#2f81f7] hover:bg-blue-400 transition-all" style="height: <?php echo $succ_h; ?>%;"></div>
                                    <!-- Failed Bar -->
                                    <div class="w-3 rounded-t-xs <?php echo $day['failed'] > 0 ? 'bg-[#f85149] hover:bg-red-400' : 'bg-transparent'; ?> transition-all" style="height: <?php echo $fail_h; ?>%;"></div>
                                </div>

                                <!-- Day Label -->
                                <span class="text-[11px] font-mono text-slate-400 mt-2 font-medium">
                                    <?php echo $day['day']; ?>
                                </span>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <!-- Summary Footnote -->
                    <div class="mt-4 pt-3 flex items-center justify-between text-xs text-slate-400 font-mono">
                        <span>7-Day Success Rate:</span>
                        <strong class="text-emerald-400">
                            <?php echo ($total_7d_success + $total_7d_failed) > 0 ? round(($total_7d_success / ($total_7d_success + $total_7d_failed)) * 100) : 100; ?>%
                        </strong>
                    </div>
                </div>

            </div>

            <!-- 4. IDENTITIES & DIRECTORY (RBAC CONTROL MATRIX) -->
            <div id="usersDirectory" class="p-6 rounded-lg bg-[#161b22] border border-[#30363d] shadow-xs mb-8">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#30363d] mb-4 gap-3">
                    <div>
                        <h2 class="text-base font-semibold text-white flex items-center gap-2">
                            <i class="fa-solid fa-users text-[#2f81f7]"></i>
                            <span>Users &amp; Directory</span>
                        </h2>
                        <p class="text-xs text-slate-400 mt-0.5">Active directory identities, role assignments, and multi-factor status.</p>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="text-xs font-mono text-slate-300 bg-[#0d1117] px-3 py-1 rounded border border-[#30363d]">
                            <?php echo count($users); ?> Identities Registered
                        </span>
                        <button type="button" onclick="document.getElementById('provisionModal').classList.remove('hidden')" class="px-3 py-1 rounded bg-[#2f81f7] hover:bg-blue-600 text-white text-xs font-semibold transition">
                            + Add User
                        </button>
                    </div>
                </div>

                <!-- Table -->
                <div class="overflow-x-auto custom-scrollbar">
                    <table id="directoryTable" class="w-full text-left text-xs font-sans">
                        <thead class="text-slate-400 font-mono text-[11px] uppercase tracking-wider bg-[#0d1117] border-b border-[#30363d]">
                            <tr>
                                <th class="px-4 py-3">UID</th>
                                <th class="px-4 py-3">Account / Identity</th>
                                <th class="px-4 py-3">Role</th>
                                <th class="px-4 py-3">Clearance</th>
                                <th class="px-4 py-3">MFA Status</th>
                                <th class="px-4 py-3">Status</th>
                                <th class="px-4 py-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-[#30363d]">
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

                                $role_badge = match($user_role_id) {
                                    1 => 'bg-purple-500/10 text-purple-400 border-purple-500/30',
                                    2 => 'bg-sky-500/10 text-sky-400 border-sky-500/30',
                                    3 => 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
                                    default => 'bg-slate-500/10 text-slate-400 border-slate-500/30',
                                };

                                $clearance_badge = match(true) {
                                    stripos($user_clearance_val, 'Tier 3') !== false => 'bg-purple-500/15 text-purple-300 border-purple-500/30',
                                    stripos($user_clearance_val, 'Tier 2') !== false => 'bg-sky-500/15 text-sky-300 border-sky-500/30',
                                    default => 'bg-slate-500/15 text-slate-300 border-slate-500/30',
                                };
                            ?>
                            <tr class="hover:bg-[#21262d]/60 transition <?php echo !$is_active ? 'bg-red-950/15' : ''; ?>">
                                <!-- UID -->
                                <td class="px-4 py-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                                    UID-<?php echo str_pad($uid, 4, '0', STR_PAD_LEFT); ?>
                                </td>

                                <!-- Account Email -->
                                <td class="px-4 py-3.5">
                                    <div class="flex items-center gap-2.5">
                                        <div class="w-8 h-8 rounded <?php echo $is_active ? 'bg-[#21262d] text-slate-200 border border-[#30363d]' : 'bg-red-950/50 text-red-400 border border-red-500/30'; ?> flex items-center justify-center font-bold text-xs shrink-0">
                                            <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                                        </div>
                                        <div class="min-w-0">
                                            <div class="text-white font-medium text-xs flex items-center gap-1.5">
                                                <span class="truncate"><?php echo $user_email; ?></span>
                                                <?php if ($is_self): ?>
                                                    <span class="text-[9px] font-mono bg-[#2f81f7]/20 text-[#2f81f7] border border-[#2f81f7]/30 px-1 py-0.2 rounded font-bold">YOU</span>
                                                <?php endif; ?>
                                            </div>
                                            <div class="text-[10px] text-slate-400 font-mono truncate">
                                                <?php echo htmlspecialchars(trim(($u['first_name'] ?? '') . ' ' . ($u['last_name'] ?? ''))); ?> &bull; <?php echo htmlspecialchars($user_dept_val); ?>
                                            </div>
                                        </div>
                                    </div>
                                </td>

                                <!-- Role -->
                                <td class="px-4 py-3.5 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border <?php echo $role_badge; ?>">
                                        <i class="fa-solid fa-shield mr-1 text-[9px]"></i> <?php echo $user_functional_role; ?>
                                    </span>
                                </td>

                                <!-- Clearance -->
                                <td class="px-4 py-3.5 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold border <?php echo $clearance_badge; ?>">
                                        <?php echo htmlspecialchars($user_clearance_val); ?>
                                    </span>
                                </td>

                                <!-- MFA Status -->
                                <td class="px-4 py-3.5 whitespace-nowrap">
                                    <?php if (!empty($u['mfa_secret'])): ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                            <i class="fa-solid fa-check mr-1 text-[9px]"></i> Verified (TOTP)
                                        </span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                            <i class="fa-solid fa-clock mr-1 text-[9px]"></i> Pending Setup
                                        </span>
                                    <?php endif; ?>
                                </td>

                                <!-- Account Status -->
                                <td class="px-4 py-3.5 whitespace-nowrap">
                                    <?php if ($is_active): ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                        </span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                                            <span class="w-1.5 h-1.5 rounded-full bg-red-400 mr-1.5"></span> Suspended
                                        </span>
                                    <?php endif; ?>
                                </td>

                                <!-- Actions -->
                                <td class="px-4 py-3.5 text-right whitespace-nowrap">
                                    <div class="flex items-center justify-end gap-1.5">
                                        <!-- Edit Role Modal Trigger -->
                                        <button onclick="openRoleModal(<?php echo $uid; ?>, '<?php echo addslashes($user_email); ?>', <?php echo $user_role_id; ?>, '<?php echo addslashes($user_functional_role); ?>', '<?php echo addslashes($user_clearance_val); ?>')" class="p-1.5 text-slate-400 hover:text-white hover:bg-[#21262d] rounded transition" title="Modify RBAC Role">
                                            <i class="fa-solid fa-user-pen text-xs"></i>
                                        </button>

                                        <!-- Suspend / Reactivate Form -->
                                        <?php if (!$is_self): ?>
                                            <?php if ($is_active): ?>
                                                <form method="POST" action="" class="inline" onsubmit="return confirm('Suspend user <?php echo addslashes($user_email); ?>? Session access will be revoked.');">
                                                    <input type="hidden" name="action" value="suspend_user">
                                                    <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    <button type="submit" class="p-1.5 text-slate-400 hover:text-amber-400 hover:bg-amber-500/10 rounded transition" title="Suspend Identity">
                                                        <i class="fa-solid fa-ban text-xs"></i>
                                                    </button>
                                                </form>
                                            <?php else: ?>
                                                <form method="POST" action="" class="inline">
                                                    <input type="hidden" name="action" value="activate_user">
                                                    <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                    <button type="submit" class="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded transition" title="Reactivate Identity">
                                                        <i class="fa-solid fa-check text-xs"></i>
                                                    </button>
                                                </form>
                                            <?php endif; ?>

                                            <!-- Deprovision Form -->
                                            <form method="POST" action="" class="inline" onsubmit="return confirm('Permanently purge <?php echo addslashes($user_email); ?> from directory? This cannot be undone.');">
                                                <input type="hidden" name="action" value="purge_user">
                                                <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <button type="submit" class="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition" title="Purge Identity">
                                                    <i class="fa-solid fa-trash-can text-xs"></i>
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
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

    <!-- ========================================================================= -->
    <!-- MODAL 1: PROVISION IDENTITY (+ Add User)                                  -->
    <!-- ========================================================================= -->
    <div id="provisionModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-[#30363d] w-full max-w-xl rounded-xl p-6 shadow-2xl relative overflow-hidden">
            <div class="flex justify-between items-center border-b border-[#30363d] pb-3 mb-4">
                <div class="flex items-center space-x-2 text-[#2f81f7]">
                    <i class="fa-solid fa-user-plus text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Add New Workforce User</h3>
                </div>
                <button onclick="document.getElementById('provisionModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <?php if (isset($provision_msg)) echo $provision_msg; ?>

            <form method="POST" action="" class="space-y-4">
                <input type="hidden" name="action" value="provision_user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">First Name</label>
                        <input type="text" name="first_name" placeholder="John" required class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Last Name</label>
                        <input type="text" name="last_name" placeholder="Doe" required class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Enterprise Email Address</label>
                        <input type="email" name="new_email" placeholder="j.doe@organization.com" required class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Initial Password</label>
                        <input type="password" name="new_password" required placeholder="••••••••••••" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Department</label>
                        <input type="text" name="department" placeholder="Engineering" value="General Operations" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Job Title</label>
                        <input type="text" name="job_title" placeholder="DevOps Engineer" value="Staff Analyst" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Functional Access Role</label>
                        <select name="role" id="provRoleSelect" onchange="syncProvisioningDefaults()" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                            <option value="Staff">Staff (Standard Access)</option>
                            <option value="Auditor">Auditor (Compliance &amp; Logs)</option>
                            <option value="Admin">Admin (Full System Access)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Security Clearance</label>
                        <select name="security_clearance" id="provClearanceSelect" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                            <option value="Tier 1">Tier 1 &mdash; General Workspace</option>
                            <option value="Tier 2">Tier 2 &mdash; Sensitive Logs &amp; PII</option>
                            <option value="Tier 3">Tier 3 &mdash; Root Credentials &amp; Vault</option>
                        </select>
                    </div>
                </div>
                <input type="hidden" name="role_id" id="provRoleIdHidden" value="4">

                <div class="flex space-x-3 pt-3">
                    <button type="button" onclick="document.getElementById('provisionModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#30363d] hover:bg-[#21262d] text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded text-xs font-semibold bg-[#2f81f7] hover:bg-blue-600 text-white shadow transition">
                        Add User
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 2: EDIT ROLE & CLEARANCE (RBAC)                                     -->
    <!-- ========================================================================= -->
    <div id="roleModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-[#30363d] w-full max-w-md rounded-xl p-6 shadow-2xl relative">
            <div class="flex justify-between items-center border-b border-[#30363d] pb-3 mb-4">
                <div class="flex items-center space-x-2 text-[#2f81f7]">
                    <i class="fa-solid fa-user-gear text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Modify Role &amp; Permissions</h3>
                </div>
                <button onclick="document.getElementById('roleModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            
            <form method="POST" action="" class="space-y-4">
                <input type="hidden" name="action" value="update_role">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="target_user_id" id="roleModalUserId">
                
                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Target Account</label>
                    <div id="roleModalEmail" class="text-xs font-bold text-[#2f81f7] bg-[#0d1117] px-3 py-2 rounded border border-[#30363d] font-mono"></div>
                </div>

                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Functional Access Role</label>
                    <select name="new_functional_role" id="roleModalFuncRole" onchange="syncRoleModalDefaults()" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                        <option value="Staff">Staff (Standard Access)</option>
                        <option value="Auditor">Auditor (Compliance &amp; Logs)</option>
                        <option value="Admin">Admin (Full System Access)</option>
                    </select>
                </div>

                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Security Clearance Level</label>
                    <select name="new_clearance" id="roleModalClearance" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                        <option value="Tier 1">Tier 1 &mdash; General Workspace</option>
                        <option value="Tier 2">Tier 2 &mdash; Sensitive Logs &amp; PII</option>
                        <option value="Tier 3">Tier 3 &mdash; Root Credentials &amp; Vault</option>
                    </select>
                </div>

                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">RBAC System Role</label>
                    <select name="new_role_id" id="roleModalSelect" class="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#30363d] text-white text-xs focus:border-[#2f81f7] focus:outline-hidden">
                        <?php foreach ($roles as $r): ?>
                            <option value="<?php echo $r['role_id']; ?>"><?php echo htmlspecialchars($r['role_name']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="flex space-x-3 pt-3">
                    <button type="button" onclick="document.getElementById('roleModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#30363d] hover:bg-[#21262d] text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded text-xs font-semibold bg-[#2f81f7] hover:bg-blue-600 text-white shadow transition">
                        Apply Role
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 3: EMERGENCY LOCKDOWN CONFIRMATION (PRESERVED BACKEND)               -->
    <!-- ========================================================================= -->
    <div id="lockdownModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-[#161b22] border border-red-500/50 w-full max-w-md rounded-xl p-6 shadow-2xl relative space-y-4">
            <div class="flex items-center space-x-3 text-red-500">
                <i class="fa-solid fa-triangle-exclamation text-2xl"></i>
                <h3 class="font-sans font-bold text-white text-lg">Confirm Emergency Lockdown</h3>
            </div>
            
            <p class="text-xs text-slate-300 leading-relaxed font-sans">
                You are about to engage the <strong>Emergency Lockdown</strong> protocol. 
                This action will instantly suspend all non-administrator user accounts and terminate active sessions.
            </p>
            
            <form method="POST" action="" class="flex space-x-3 pt-2">
                <input type="hidden" name="action" value="emergency_lockdown">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <button type="button" onclick="document.getElementById('lockdownModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#30363d] hover:bg-[#21262d] text-slate-300 transition">
                    Abort
                </button>
                <button type="submit" class="w-1/2 py-2 rounded text-xs font-bold bg-red-600 hover:bg-red-700 text-white shadow transition flex items-center justify-center gap-1.5">
                    <i class="fa-solid fa-power-off"></i> Engage Lockdown
                </button>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 4: BIOMETRIC WELCOME HUD                                            -->
    <!-- ========================================================================= -->
    <div id="cyberWelcomeHUD" class="<?php echo $show_welcome_hud ? '' : 'hidden'; ?> fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-xs flex items-center justify-center p-4">
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl max-w-lg w-full p-6 sm:p-8 shadow-2xl space-y-5 text-center relative">
            <div class="w-14 h-14 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400">
                <i class="fa-solid fa-fingerprint text-2xl"></i>
            </div>
            
            <div class="space-y-1">
                <h3 class="font-sans font-bold text-white text-lg">Session Authenticated</h3>
                <p class="font-mono text-xs text-emerald-400 font-semibold">Zero-Trust Access Verified &bull; TLS 1.3 Active</p>
            </div>
            
            <div class="grid grid-cols-2 gap-3 text-left font-mono text-xs">
                <div class="bg-[#0d1117] p-2.5 rounded border border-[#30363d]">
                    <span class="text-slate-500 text-[10px] uppercase">Identity:</span>
                    <p class="text-white font-medium truncate"><?php echo htmlspecialchars($current_user['email']); ?></p>
                </div>
                <div class="bg-[#0d1117] p-2.5 rounded border border-[#30363d]">
                    <span class="text-slate-500 text-[10px] uppercase">Role:</span>
                    <p class="text-[#2f81f7] font-medium"><?php echo htmlspecialchars($current_functional_role); ?></p>
                </div>
                <div class="bg-[#0d1117] p-2.5 rounded border border-[#30363d]">
                    <span class="text-slate-500 text-[10px] uppercase">Clearance:</span>
                    <p class="text-purple-400 font-medium"><?php echo htmlspecialchars($current_clearance); ?></p>
                </div>
                <div class="bg-[#0d1117] p-2.5 rounded border border-[#30363d]">
                    <span class="text-slate-500 text-[10px] uppercase">Enclave Host:</span>
                    <p class="text-emerald-400 font-medium">iam.secure-defense.internal</p>
                </div>
            </div>

            <button onclick="dismissCyberWelcomeHUD()" class="w-full py-2.5 rounded bg-[#2f81f7] hover:bg-blue-600 text-white font-sans text-xs font-bold transition shadow">
                Continue to Admin Console
            </button>
            <p id="welcomeHudTimer" class="font-mono text-[10px] text-slate-500">Entering console in 3s...</p>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- INTERACTIVE JAVASCRIPT CONTROLLERS                                        -->
    <!-- ========================================================================= -->
    <script>
        // Filter Directory Table (Instant Search)
        function filterDirectoryTable() {
            const input = document.getElementById('directorySearchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('directoryTable');
            if (!table) return;
            const tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {
                const text = tr[i].innerText.toLowerCase();
                if (text.indexOf(filter) > -1) {
                    tr[i].style.display = '';
                } else {
                    tr[i].style.display = 'none';
                }
            }
        }

        // Ctrl+K Shortcut Handler
        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                const searchInput = document.getElementById('directorySearchInput');
                if (searchInput) {
                    searchInput.focus();
                    searchInput.select();
                }
            }
        });

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

        // RBAC Provisioning Defaults Synchronization
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
                funcRoleEl.value = currentFunctionalRole || 'Staff';
            }
            
            const clearEl = document.getElementById('roleModalClearance');
            if (clearEl) {
                clearEl.value = currentClearance || 'Tier 1';
            }
            
            document.getElementById('roleModal').classList.remove('hidden');
        }

        // Biometric Welcome HUD auto-dismiss
        let hudTimerInterval = null;
        function dismissCyberWelcomeHUD() {
            if (hudTimerInterval) clearInterval(hudTimerInterval);
            const hud = document.getElementById('cyberWelcomeHUD');
            if (hud) hud.classList.add('hidden');
        }

        function triggerCyberWelcomeHUD() {
            const hud = document.getElementById('cyberWelcomeHUD');
            if (!hud) return;
            hud.classList.remove('hidden');
            let remaining = 3000;
            const timerText = document.getElementById('welcomeHudTimer');
            hudTimerInterval = setInterval(() => {
                remaining -= 100;
                if (timerText) {
                    const secs = Math.ceil(remaining / 1000);
                    timerText.innerText = 'Entering console in ' + secs + 's...';
                }
                if (remaining <= 0) {
                    clearInterval(hudTimerInterval);
                    dismissCyberWelcomeHUD();
                }
            }, 100);
        }

        <?php if ($show_welcome_hud): ?>
        window.addEventListener('DOMContentLoaded', () => {
            triggerCyberWelcomeHUD();
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
