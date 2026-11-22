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

        $feedback_alert = "<div class='p-4 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-mono flex items-center gap-2.5 mb-6 shadow-lg'><span class='w-2.5 h-2.5 rounded-full bg-red-400 animate-ping'></span><span><strong>EMERGENCY LOCKDOWN ENGAGED:</strong> All non-admin workforce accounts have been suspended immediately. Lateral movement is blocked.</span></div>";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'lift_lockdown') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $unlock_stmt = $conn->query("UPDATE users SET is_active = 1 WHERE is_active = 0");

        $action_type = "EMERGENCY_LOCKDOWN_LIFTED";
        $action_desc = "Emergency Lockdown LIFTED by Admin UID-{$current_user_id}. All enterprise workforce identities reactivated.";
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
        $log_stmt->execute();

        AISentinel::resetSimulationTelemetry($conn);

        $feedback_alert = "<div class='p-4 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-2.5 mb-6 shadow-lg'><i class='fa-solid fa-lock-open text-emerald-400'></i><span><strong>LOCKDOWN LIFTED:</strong> All workforce identities reactivated successfully. Baseline security telemetry restored to safe normal.</span></div>";
    }
}

// Check if Lockdown is currently engaged
$lockdown_check = $conn->query("SELECT action_type FROM audit_logs WHERE action_type IN ('EMERGENCY_LOCKDOWN_TRIGGERED', 'EMERGENCY_LOCKDOWN_LIFTED') ORDER BY log_id DESC LIMIT 1");
$is_lockdown_active = false;
if ($lockdown_check && $row = $lockdown_check->fetch_assoc()) {
    if ($row['action_type'] === 'EMERGENCY_LOCKDOWN_TRIGGERED') {
        $is_lockdown_active = true;
    }
}

// -------------------------------------------------------------
// 3. HANDLE RBAC: TOGGLE SUSPEND / ACTIVATE USER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_status') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $new_status = (int) ($_POST['new_status'] ?? 0);
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        if ($target_user_id === $current_user_id) {
            $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-shield-halved mr-2'></i> Security Policy Violation: Administrators cannot suspend their own active session.</div>";
        } else {
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
                        $feedback_alert = "<div class='p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono flex items-center'><i class='fa-solid fa-lock mr-2'></i> Account <strong>{$target_email}</strong> suspended. Authentication access revoked immediately.</div>";
                    } else {
                        $action_type = "ACCOUNT_ACTIVATED";
                        $action_desc = "Identity UID-{$target_user_id} ({$target_email}) was RE-ACTIVATED by Admin UID-{$current_user_id}.";
                        $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center'><i class='fa-solid fa-lock-open mr-2'></i> Account <strong>{$target_email}</strong> has been re-activated successfully.</div>";
                    }

                    $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                    $log_stmt->bind_param("isss", $target_user_id, $action_type, $action_desc, $client_ip);
                    $log_stmt->execute();
                } else {
                    $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono'>Database error executing status change.</div>";
                }
            } else {
                $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono'>Target identity not found.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 4. HANDLE RBAC: UPDATE ROLE & CLEARANCE ASSIGNMENT
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_role') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $new_role_id = (int) ($_POST['new_role_id'] ?? 4);
        $new_functional_role = trim($_POST['new_functional_role'] ?? '');
        $new_clearance = trim($_POST['new_clearance'] ?? '');
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

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

        if (!isset($roles[$new_role_id])) {
            $fallback_role = reset($roles);
            $new_role_id = $fallback_role ? (int) $fallback_role['role_id'] : 4;
        }

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
                $feedback_alert = "<div class='p-3.5 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-300 text-xs font-mono flex items-center'><i class='fa-solid fa-user-shield mr-2'></i> Access policy for <strong>{$target_email}</strong> updated to <strong>{$new_functional_role} ({$new_clearance})</strong>.</div>";

                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $target_user_id, $action_type, $action_desc, $client_ip);
                $log_stmt->execute();
            } else {
                $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono'>Database error updating role.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 5. HANDLE RBAC: PERMANENTLY PURGE IDENTITY (CRUD: Delete)
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        if ($target_user_id === $current_user_id) {
            $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-shield-halved mr-2 text-red-400'></i> Security Policy Violation: Administrators cannot purge their own active identity.</div>";
        } else {
            $t_stmt = $conn->prepare("SELECT email FROM users WHERE user_id = ?");
            $t_stmt->bind_param("i", $target_user_id);
            $t_stmt->execute();
            $target_res = $t_stmt->get_result();
            $target_user = $target_res->fetch_assoc();

            if ($target_user) {
                $target_email = $target_user['email'];

                $u_log = $conn->prepare("UPDATE audit_logs SET user_id = NULL WHERE user_id = ?");
                $u_log->bind_param("i", $target_user_id);
                $u_log->execute();

                $del_stmt = $conn->prepare("DELETE FROM users WHERE user_id = ?");
                $del_stmt->bind_param("i", $target_user_id);

                if ($del_stmt->execute()) {
                    $action_type = "USER_PURGED";
                    $action_desc = "Identity UID-{$target_user_id} ({$target_email}) was PERMANENTLY PURGED from directory by Admin UID-{$current_user_id}.";
                    $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                    $log_stmt->bind_param("isss", $current_user_id, $action_type, $action_desc, $client_ip);
                    $log_stmt->execute();

                    $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs font-mono flex items-center'><i class='fa-solid fa-trash-can mr-2 text-red-400'></i> Identity <strong>{$target_email}</strong> (UID-{$target_user_id}) permanently purged from directory.</div>";
                } else {
                    $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono'>Database error purging identity.</div>";
                }
            } else {
                $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono'>Target identity not found.</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 6. HANDLE NEW USER PROVISIONING
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'provision_user') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $provision_msg = "<div class='p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 mb-4 text-xs font-mono'>CSRF token invalid.</div>";
    } else {
        $new_email = trim($_POST['new_email'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $first_name = trim($_POST['first_name'] ?? '');
        $last_name = trim($_POST['last_name'] ?? '');
        $department = trim($_POST['department'] ?? 'General Operations');
        $job_title = trim($_POST['job_title'] ?? 'Staff Analyst');
        $role_selected = trim($_POST['role'] ?? 'Staff');
        $security_clearance = trim($_POST['security_clearance'] ?? 'Tier 1');
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        if (strcasecmp($role_selected, 'Admin') === 0) {
            $role_id = 1;
            if ($security_clearance === 'Tier 1') $security_clearance = 'Tier 3';
        } elseif (strcasecmp($role_selected, 'Auditor') === 0) {
            $role_id = 3;
            if ($security_clearance === 'Tier 1') $security_clearance = 'Tier 2';
        } else {
            $role_id = 4;
        }

        if (!empty($_POST['role_id']) && isset($roles[(int)$_POST['role_id']])) {
            $role_id = (int)$_POST['role_id'];
        }

        if (empty($new_email) || empty($new_password)) {
            $provision_msg = "<div class='p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 mb-4 text-xs font-mono'>Email and Password are required.</div>";
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

                $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center'><i class='fa-solid fa-circle-check mr-2 text-emerald-400'></i> Identity <strong>{$new_email}</strong> provisioned: Role [<strong>{$role_selected}</strong>], Clearance [<strong>{$security_clearance}</strong>], Dept [<strong>{$department}</strong>].</div>";
            } else {
                $provision_msg = "<div class='p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 mb-4 text-xs font-mono'>Error provisioning user: " . htmlspecialchars($conn->error) . "</div>";
            }
        }
    }
}

// -------------------------------------------------------------
// 7. LIVE DEFENSE SIMULATION TRIGGERS
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'simulate_threat') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $scenario = $_POST['scenario'] ?? 'brute_force';
        AISentinel::injectSimulationThreat($conn, $scenario);
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> <strong>Defense Simulation Injected:</strong> Synthetic threat traffic generated ({$scenario}). Observe AI Sentinel response below!</div>";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reset_simulation') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        AISentinel::resetSimulationTelemetry($conn);
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center'><i class='fa-solid fa-rotate-left mr-2'></i> Simulation telemetry cleared. Threat baseline restored to normal.</div>";
    }
}

// -------------------------------------------------------------
// 8. FETCH SYSTEM METRICS & DIRECTORY DATA
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
// 9. RUN AI SENTINEL BEHAVIORAL THREAT SCAN
// -------------------------------------------------------------
$sentinel = AISentinel::analyzeThreatLevel($conn);
$threat_score = $sentinel['threat_score'];
$threat_level = $sentinel['threat_level'];
$status_color = $sentinel['status_color'];
$anomalies = $sentinel['anomalies'];
$terminal_logs = $sentinel['terminal_logs'];

// Map status color to style properties
$color_map = [
    'emerald' => [
        'text' => 'text-emerald-400',
        'bg' => 'bg-emerald-500/10',
        'border' => 'border-emerald-500/20',
        'badge' => 'OPTIMAL',
        'badge_bg' => 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
        'bar' => 'from-sky-400 to-emerald-400',
        'ping' => 'bg-emerald-400'
    ],
    'amber' => [
        'text' => 'text-amber-400',
        'bg' => 'bg-amber-500/10',
        'border' => 'border-amber-500/20',
        'badge' => 'ELEVATED',
        'badge_bg' => 'bg-amber-500/10 text-amber-400 border-amber-500/20',
        'bar' => 'from-amber-400 to-amber-500',
        'ping' => 'bg-amber-400'
    ],
    'orange' => [
        'text' => 'text-orange-400',
        'bg' => 'bg-orange-500/10',
        'border' => 'border-orange-500/20',
        'badge' => 'HIGH RISK',
        'badge_bg' => 'bg-orange-500/10 text-orange-400 border-orange-500/20',
        'bar' => 'from-orange-500 to-red-500',
        'ping' => 'bg-orange-400'
    ],
    'red' => [
        'text' => 'text-red-400',
        'bg' => 'bg-red-500/10',
        'border' => 'border-red-500/20',
        'badge' => 'CRITICAL',
        'badge_bg' => 'bg-red-500/10 text-red-400 border-red-500/20',
        'bar' => 'from-red-500 to-rose-600',
        'ping' => 'bg-red-400'
    ]
];
$active_theme = $color_map[$status_color] ?? $color_map['emerald'];
?>
<!DOCTYPE html>
<html class="dark" lang="en">
<head>
    <meta charset="utf-8"/>
    <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
    <meta name="color-scheme" content="dark light">
    <title>Aegis IAM &mdash; Zero-Trust Security Command Center &amp; Posture Intel</title>

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

    <!-- 100% Offline Air-Gapped Tailwind & Theme Engine -->
    <script src="assets/js/tailwind.js"></script>
    <script id="tailwind-config">
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            colors: {
              "surface": "#0f131c",
              "surface-dim": "#0f131c",
              "surface-bright": "#353942",
              "surface-container-lowest": "#0a0e16",
              "surface-container-low": "#181c24",
              "surface-container": "#1c2028",
              "surface-container-high": "#262a33",
              "surface-container-highest": "#31353e",
              "on-surface": "#dfe2ee",
              "on-surface-variant": "#bdc8d1",
              "outline": "#87929a",
              "outline-variant": "#3e484f",
              "primary": "#8ed5ff",
              "primary-container": "#38bdf8",
              "on-primary": "#00354a",
              "on-primary-container": "#004965",
              "secondary": "#4edea3",
              "secondary-container": "#00a572",
              "tertiary": "#ffc174",
              "tertiary-container": "#f59e0b",
              "error": "#ffb4ab",
              "error-container": "#93000a",
              "on-error": "#690005"
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
<body class="bg-surface font-sans text-on-surface antialiased selection:bg-primary-container selection:text-slate-900 min-h-screen">

    <!-- Left Fixed Navigation Sidebar (Stitch Obsidian Cipher) -->
    <aside id="appSidebar" class="fixed left-0 top-0 h-screen w-64 bg-surface-container-low border-r border-[#1e293b] z-50 flex flex-col justify-between shadow-2xl transition-transform duration-300">
        <div class="flex flex-col h-full overflow-y-auto custom-scrollbar">
            <!-- Brand Header -->
            <div class="h-16 flex items-center gap-3 px-5 bg-[#0b0f17] border-b border-[#1e293b]">
                <div class="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0 shadow-[0_0_8px_rgba(56,189,248,0.4)]">
                    <i class="fa-solid fa-shield-halved text-base"></i>
                </div>
                <div class="flex flex-col min-w-0">
                    <span class="text-base text-white font-semibold tracking-tight truncate">Aegis IAM</span>
                    <span class="text-[10px] font-mono text-[#38bdf8] tracking-wider uppercase font-medium">Zero-Trust Suite</span>
                </div>
            </div>

            <!-- Policy Engine Status Chip -->
            <div class="px-4 py-3">
                <div class="flex items-center gap-2 px-3 py-1.5 rounded bg-[#111827] border border-[#1e293b]">
                    <span class="w-1.5 h-1.5 rounded-full bg-[#10b981] shadow-[0_0_8px_#10b981] animate-pulse"></span>
                    <span class="font-mono text-[10px] text-slate-300 uppercase font-medium truncate">Policy Engine: Active</span>
                </div>
            </div>

            <!-- Categorized Navigation -->
            <nav class="flex-1 px-3 py-1 space-y-4 text-xs font-sans">
                <!-- Group 1: Core -->
                <div class="space-y-1">
                    <div class="px-3 font-mono text-[10px] uppercase tracking-wider text-slate-400 font-semibold">Core</div>
                    <div class="space-y-0.5">
                        <a href="dashboard.php" class="flex items-center gap-2.5 px-3 py-2 rounded bg-surface-container border border-[#334155] text-white shadow-sm transition-colors">
                            <i class="fa-solid fa-shield text-[14px] text-[#38bdf8] w-4 text-center"></i>
                            <span class="font-medium text-xs">Security Overview &amp; Posture</span>
                        </a>
                        <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-fingerprint text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Authentication &amp; 2FA Gateway</span>
                        </a>
                    </div>
                </div>

                <!-- Group 2: Directory -->
                <div class="space-y-1">
                    <div class="px-3 font-mono text-[10px] uppercase tracking-wider text-slate-400 font-semibold">Directory</div>
                    <div class="space-y-0.5">
                        <a href="#directorySection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-id-badge text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Identities &amp; Directory</span>
                        </a>
                        <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-robot text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Service Accounts &amp; Bots</span>
                        </a>
                        <a href="#directorySection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-users text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Groups &amp; Teams</span>
                        </a>
                    </div>
                </div>

                <!-- Group 3: Access Governance -->
                <div class="space-y-1">
                    <div class="px-3 font-mono text-[10px] uppercase tracking-wider text-slate-400 font-semibold">Access Governance</div>
                    <div class="space-y-0.5">
                        <a href="#triageSection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-scale-balanced text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Conditional Access</span>
                        </a>
                        <a href="vault.php" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-key text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Privileged Access (PIM)</span>
                            <span class="ml-auto text-[9px] font-mono px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30">RBAC</span>
                        </a>
                        <a href="#directorySection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-user-shield text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Role-Based Access (RBAC)</span>
                        </a>
                    </div>
                </div>

                <!-- Group 4: Compliance & Logs -->
                <div class="space-y-1">
                    <div class="px-3 font-mono text-[10px] uppercase tracking-wider text-slate-400 font-semibold">Compliance &amp; Logs</div>
                    <div class="space-y-0.5">
                        <a href="#auditStreamSection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-file-invoice text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Real-Time Audit Logs</span>
                        </a>
                        <a href="#telemetrySection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-laptop-code text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Session Explorer</span>
                        </a>
                        <a href="audit_report.php" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                            <i class="fa-solid fa-certificate text-[14px] w-4 text-center"></i>
                            <span class="text-xs">Compliance Reports</span>
                            <span class="ml-auto text-[9px] font-mono px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 font-bold border border-sky-500/30">NIST</span>
                        </a>
                    </div>
                </div>
            </nav>

            <!-- Bottom System Settings -->
            <div class="p-3 mt-auto bg-surface-container-low border-t border-[#1e293b]">
                <a href="#hsmSection" class="flex items-center gap-2.5 px-3 py-2 rounded text-slate-400 hover:bg-surface-container hover:text-white transition-colors">
                    <i class="fa-solid fa-gear text-[14px] w-4 text-center"></i>
                    <span class="text-xs">System Settings &amp; HSM</span>
                </a>
            </div>
        </div>
    </aside>

    <!-- Main Container With Left Fixed Padding -->
    <div class="pl-64">
        <!-- Top Enterprise Header Bar -->
        <header class="fixed top-0 left-64 right-0 h-16 bg-[#0b0f17]/90 backdrop-blur-xl border-b border-[#1e293b] z-40 px-6 flex items-center justify-between gap-4">
            <div class="flex items-center gap-3 min-w-0">
                <div class="flex items-center gap-2 px-3 py-1 bg-[#181c24] border border-[#1e293b] rounded text-xs">
                    <i class="fa-solid fa-server text-[13px] text-[#38bdf8]"></i>
                    <span class="font-mono text-slate-200 font-medium truncate max-w-[200px]">Global Enterprise Production - us-east-1</span>
                    <i class="fa-solid fa-chevron-down text-[10px] text-slate-400"></i>
                </div>
                <div class="hidden xl:flex items-center gap-2 px-3 py-1 rounded bg-[#111827] border border-[#1e293b] text-xs">
                    <span class="w-1.5 h-1.5 rounded-full bg-[#10b981] shadow-[0_0_6px_#10b981]"></span>
                    <span class="font-mono text-[#4edea3] font-semibold uppercase tracking-wider text-[11px]">Zero-Trust Enforced: SOC2 / FedRAMP</span>
                </div>
            </div>

            <!-- Center Search Bar -->
            <div class="flex-1 max-w-md hidden md:flex items-center gap-2 px-3 py-1.5 rounded bg-[#111827] border border-[#1e293b] shadow-inner text-xs">
                <i class="fa-solid fa-magnifying-glass text-slate-400 text-xs"></i>
                <span class="text-slate-400 truncate flex-1">Cmd + K to search users, policies, audit logs...</span>
                <kbd class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#181c24] border border-[#334155] text-slate-300 uppercase font-medium">Ctrl+K</kbd>
            </div>

            <!-- Right Status, Theme, Profile -->
            <div class="flex items-center gap-3 shrink-0 text-xs">
                <!-- Dynamic Threat State Indicator -->
                <?php if ($threat_score >= 40): ?>
                    <div class="hidden lg:flex items-center gap-2 px-3 py-1 rounded bg-red-500/10 border border-red-500/30">
                        <span class="w-2 h-2 rounded-full bg-[#ef4444] shadow-[0_0_8px_#ef4444] animate-ping"></span>
                        <span class="font-mono text-red-400 font-bold truncate text-[11px]">CRITICAL: Threat Active (ATS: <?php echo $threat_score; ?>/100)</span>
                    </div>
                <?php else: ?>
                    <div class="hidden lg:flex items-center gap-2 px-3 py-1 rounded bg-[#111827] border border-[#1e293b]">
                        <span class="w-2 h-2 rounded-full bg-[#10b981] shadow-[0_0_8px_#10b981] animate-pulse"></span>
                        <span class="font-mono text-[#4edea3] font-medium truncate text-[11px]">System Normal - 0 Critical Threats</span>
                    </div>
                <?php endif; ?>

                <!-- Theme Toggle Button -->
                <button onclick="toggleTheme()" id="themeToggleBtn" class="px-2.5 py-1 rounded bg-[#181c24] hover:bg-surface-container border border-[#1e293b] text-slate-300 hover:text-white transition flex items-center gap-1.5" title="Switch Theme (Light / Dark)">
                    <i id="themeToggleIcon" class="fa-solid fa-sun text-amber-400 text-xs"></i>
                    <span class="hidden sm:inline font-mono text-[11px]">Theme</span>
                </button>

                <!-- Notifications -->
                <button class="relative p-1.5 rounded hover:bg-surface-container text-slate-400 hover:text-white transition" title="Security notifications">
                    <i class="fa-solid fa-bell text-sm"></i>
                    <span class="absolute top-1 right-1 w-2 h-2 rounded-full bg-[#ef4444] shadow-[0_0_6px_#ef4444] ring-2 ring-[#0b0f17]"></span>
                </button>

                <!-- User Profile & Sign Out -->
                <div class="flex items-center gap-2.5 pl-1.5 border-l border-[#1e293b]">
                    <div class="w-8 h-8 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/40 flex items-center justify-center font-bold text-xs shrink-0 shadow-[0_0_8px_rgba(0,0,0,0.5)]">
                        <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                    </div>
                    <div class="hidden sm:flex flex-col text-left">
                        <span class="text-xs font-semibold text-white leading-tight truncate max-w-[140px]"><?php echo htmlspecialchars($user_display_name); ?></span>
                        <span class="font-mono text-[10px] text-slate-400 truncate max-w-[140px]"><?php echo htmlspecialchars($current_job_title); ?></span>
                    </div>
                    <a href="logout.php" class="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition ml-1" title="Sign out of enterprise session">
                        <i class="fa-solid fa-arrow-right-from-bracket text-xs"></i>
                    </a>
                </div>
            </div>
        </header>

        <!-- Main Dashboard Viewport -->
        <main class="relative pt-20 w-full min-h-screen bg-[#0f131c] px-6 py-6 text-on-surface">
            <!-- Active Lockdown Banner (if engaged) -->
            <?php if ($is_lockdown_active): ?>
            <div class="bg-red-500/15 border-2 border-red-500/50 text-red-300 p-4 rounded-lg mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xl">
                <div class="flex items-center gap-3">
                    <span class="w-3 h-3 rounded-full bg-red-500 animate-ping shrink-0"></span>
                    <div>
                        <h4 class="font-bold text-white text-sm tracking-wide">ENCLAVE EMERGENCY LOCKDOWN IS CURRENTLY ACTIVE</h4>
                        <p class="text-xs text-red-200 mt-0.5">All non-admin identities have been suspended. Ongoing workforce sessions revoked to prevent unauthorized access.</p>
                    </div>
                </div>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="lift_lockdown">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <button type="submit" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded shadow transition flex items-center gap-1.5 whitespace-nowrap">
                        <i class="fa-solid fa-lock-open"></i> Lift Emergency Lockdown
                    </button>
                </form>
            </div>
            <?php endif; ?>

            <!-- Feedback Alert Banner -->
            <?php if (!empty($feedback_alert)): ?>
                <?php echo $feedback_alert; ?>
            <?php endif; ?>

            <!-- Breadcrumb & Control Bar -->
            <div class="flex flex-col xl:flex-row xl:items-end justify-between gap-4 mb-6">
                <div class="space-y-1">
                    <div class="flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-widest">
                        <span class="inline-block w-2 h-2 rounded-full bg-secondary shadow-[0_0_8px_#10b981] animate-pulse"></span>
                        <span>ZERO-TRUST CRYPTOGRAPHIC ENGINE &bull; CONTINUOUS ATTESTATION ACTIVE</span>
                        <span class="text-outline">/</span>
                        <span class="text-on-surface-variant font-mono">NODE-CLUSTER: US-EAST-09</span>
                    </div>
                    <h1 class="text-2xl sm:text-3xl font-bold text-white tracking-tight">Security Command Center &amp; Posture Intel</h1>
                    <p class="text-sm text-on-surface-variant max-w-3xl">
                        Real-time telemetry across multi-cloud IDPs, FIDO2 authenticators, and automated threat containment pipelines.
                    </p>
                </div>

                <!-- Global SecOps Actions Toolbar -->
                <div class="flex flex-wrap items-center gap-2.5 pt-2 xl:pt-0 font-sans">
                    <!-- Export SOC2 Audit -->
                    <a href="?export=csv" class="flex items-center gap-2 px-3.5 py-2 rounded bg-surface-container hover:bg-surface-container-high text-on-surface text-xs font-semibold transition border border-[#1e293b] shadow-sm">
                        <i class="fa-solid fa-download text-[#38bdf8]"></i>
                        <span>Export SOC2 Audit</span>
                    </a>

                    <!-- Threat Simulation Dropdown (University Defense Mode) -->
                    <div class="relative inline-block text-left" id="simulationDropdownContainer">
                        <button id="simDropdownBtn" type="button" onclick="toggleSimMenu()" class="flex items-center gap-2 px-3.5 py-2 rounded bg-purple-950/40 hover:bg-purple-900/50 text-purple-200 border border-purple-500/40 text-xs font-semibold transition shadow-sm">
                            <i class="fa-solid fa-flask-vial text-purple-400"></i>
                            <span>Simulate Threat (Defense Mode)</span>
                            <i class="fa-solid fa-chevron-down text-[10px] ml-1"></i>
                        </button>
                        <div id="simMenu" class="hidden absolute right-0 mt-2 w-72 bg-slate-950 border border-purple-500/40 rounded-lg shadow-2xl py-2 z-40 text-xs font-sans">
                            <div class="px-3 py-2 border-b border-slate-800 text-[10px] font-mono text-purple-300 uppercase tracking-wider font-bold">
                                Academic SOC Scenarios
                            </div>
                            <form method="POST" action="" class="block">
                                <input type="hidden" name="action" value="simulate_threat">
                                <input type="hidden" name="scenario" value="brute_force">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3 py-2 hover:bg-purple-900/30 text-slate-300 hover:text-white flex items-center">
                                    <i class="fa-solid fa-bolt text-amber-400 mr-2 w-4"></i> Credential Velocity Attack
                                </button>
                            </form>
                            <form method="POST" action="" class="block">
                                <input type="hidden" name="action" value="simulate_threat">
                                <input type="hidden" name="scenario" value="travel">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3 py-2 hover:bg-purple-900/30 text-slate-300 hover:text-white flex items-center">
                                    <i class="fa-solid fa-plane-slash text-red-400 mr-2 w-4"></i> Impossible Travel Anomaly
                                </button>
                            </form>
                            <form method="POST" action="" class="block">
                                <input type="hidden" name="action" value="simulate_threat">
                                <input type="hidden" name="scenario" value="stuffing">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3 py-2 hover:bg-purple-900/30 text-slate-300 hover:text-white flex items-center">
                                    <i class="fa-solid fa-users-slash text-orange-400 mr-2 w-4"></i> Credential Stuffing Vector
                                </button>
                            </form>
                            <form method="POST" action="" class="block">
                                <input type="hidden" name="action" value="simulate_threat">
                                <input type="hidden" name="scenario" value="lateral">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3 py-2 hover:bg-purple-900/30 text-slate-300 hover:text-white flex items-center">
                                    <i class="fa-solid fa-shield-virus text-rose-400 mr-2 w-4"></i> Lateral Privilege Hijack
                                </button>
                            </form>
                            <div class="border-t border-slate-800 my-1"></div>
                            <form method="POST" action="" class="block">
                                <input type="hidden" name="action" value="reset_simulation">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3 py-2 hover:bg-emerald-950/40 text-emerald-400 flex items-center font-bold">
                                    <i class="fa-solid fa-rotate-left mr-2 w-4"></i> Restore Baseline Posture
                                </button>
                            </form>
                        </div>
                    </div>

                    <!-- + Add Identity (Provision) -->
                    <button onclick="document.getElementById('provisionModal').classList.remove('hidden')" class="flex items-center gap-2 px-3.5 py-2 rounded bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition shadow-sm">
                        <i class="fa-solid fa-user-plus text-[13px]"></i>
                        <span>Add Identity</span>
                    </button>

                    <!-- Emergency Lockdown Button -->
                    <?php if (!$is_lockdown_active): ?>
                    <button type="button" onclick="document.getElementById('lockdownModal').classList.remove('hidden')" class="flex items-center gap-2 px-3.5 py-2 rounded bg-error-container hover:bg-on-error text-white text-xs font-semibold transition shadow-lg shadow-error-container/20 tracking-wide" title="Immediately isolate all non-admin workforce accounts">
                        <i class="fa-solid fa-triangle-exclamation animate-pulse"></i>
                        <span>Emergency Lockdown</span>
                    </button>
                    <?php else: ?>
                    <form method="POST" action="" class="inline">
                        <input type="hidden" name="action" value="lift_lockdown">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <button type="submit" class="flex items-center gap-2 px-3.5 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition shadow-lg shadow-emerald-600/20">
                            <i class="fa-solid fa-lock-open"></i> Lift Lockdown
                        </button>
                    </form>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Telemetry Overview (4 Key Metrics) -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <!-- 1. Active Identities -->
                <div class="p-4 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-md relative overflow-hidden flex flex-col justify-between">
                    <div class="absolute -right-6 -bottom-6 w-28 h-28 rounded-full bg-primary/5 blur-2xl pointer-events-none"></div>
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-mono text-[11px] text-on-surface-variant uppercase tracking-wider font-bold">Identities Evaluated</span>
                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-secondary-container/20 text-secondary font-bold">+3.2% 7d</span>
                    </div>
                    <div>
                        <div class="flex items-baseline gap-2">
                            <span class="text-3xl font-extrabold text-white tracking-tight font-mono"><?php echo $total_users; ?></span>
                            <span class="font-mono text-xs text-on-surface-variant font-medium">Active</span>
                        </div>
                        <div class="mt-3 pt-2 bg-surface-container-lowest/60 rounded px-2.5 py-1.5 space-y-1 border border-[#1e293b]/60">
                            <div class="flex justify-between items-center font-mono text-[11px] text-on-surface-variant">
                                <span>Employees</span>
                                <span class="text-white font-medium"><?php echo max(1, $total_users - $suspended_count); ?></span>
                            </div>
                            <div class="flex justify-between items-center font-mono text-[11px] text-on-surface-variant">
                                <span>Suspended</span>
                                <span class="<?php echo $suspended_count > 0 ? 'text-error font-bold' : 'text-slate-400'; ?> font-medium"><?php echo $suspended_count; ?></span>
                            </div>
                            <div class="flex justify-between items-center font-mono text-[11px] text-on-surface-variant">
                                <span>Service Bots (Non-Human)</span>
                                <span class="text-primary font-medium">570</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 2. MFA Enforcement -->
                <div class="p-4 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-md relative overflow-hidden flex flex-col justify-between">
                    <div class="absolute -right-6 -bottom-6 w-28 h-28 rounded-full bg-secondary/5 blur-2xl pointer-events-none"></div>
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-mono text-[11px] text-on-surface-variant uppercase tracking-wider font-bold">MFA Attestation Rate</span>
                        <span class="font-mono text-[10px] text-secondary font-bold">TARGET 100%</span>
                    </div>
                    <div>
                        <div class="flex items-baseline gap-2">
                            <span class="text-3xl font-extrabold text-white tracking-tight font-mono"><?php echo $mfa_rate; ?>%</span>
                            <span class="font-mono text-xs text-secondary font-medium">Phish-Resistant</span>
                        </div>
                        <div class="mt-3 w-full bg-surface-container rounded-full h-1.5 overflow-hidden border border-[#1e293b]">
                            <div class="bg-secondary h-full rounded-full transition-all duration-500" style="width: <?php echo max(5, $mfa_rate); ?>%;"></div>
                        </div>
                        <div class="mt-3 flex justify-between font-mono text-[11px] text-on-surface-variant">
                            <span>Compliant: <span class="text-white font-medium"><?php echo $mfa_enabled; ?></span></span>
                            <span class="text-tertiary font-bold"><?php echo ($total_users - $mfa_enabled); ?> Pending Key</span>
                        </div>
                    </div>
                </div>

                <!-- 3. Posture Score -->
                <div class="p-4 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-md relative overflow-hidden flex flex-col justify-between">
                    <div class="absolute -right-6 -bottom-6 w-28 h-28 rounded-full bg-primary/10 blur-2xl pointer-events-none"></div>
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-mono text-[11px] text-on-surface-variant uppercase tracking-wider font-bold">Zero-Trust Posture</span>
                        <span class="font-mono text-[10px] px-2 py-0.5 rounded <?php echo $active_theme['bg']; ?> <?php echo $active_theme['text']; ?> border <?php echo $active_theme['border']; ?> font-bold tracking-wider">
                            <?php echo $threat_level; ?>
                        </span>
                    </div>
                    <div>
                        <div class="flex items-baseline gap-1.5">
                            <span class="text-3xl font-extrabold text-white tracking-tight font-mono"><?php echo max(5, 100 - $threat_score); ?></span>
                            <span class="text-sm text-on-surface-variant font-medium">/ 100</span>
                        </div>
                        <div class="mt-3 pt-1 flex flex-col gap-1 text-on-surface-variant">
                            <div class="flex items-center gap-1.5 font-mono text-[11px] <?php echo $threat_score >= 40 ? 'text-error' : 'text-secondary'; ?>">
                                <i class="fa-solid <?php echo $threat_score >= 40 ? 'fa-triangle-exclamation' : 'fa-circle-check'; ?> text-[12px]"></i>
                                <span class="font-semibold"><?php echo $threat_score >= 40 ? 'Active Compromise Detected' : 'Zero Active Compromises Detected'; ?></span>
                            </div>
                            <span class="font-mono text-[10px] text-outline">4.2M Sign-in Signals Evaluated (24H)</span>
                        </div>
                    </div>
                </div>

                <!-- 4. Threat Interceptions -->
                <div class="p-4 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-md relative overflow-hidden flex flex-col justify-between">
                    <div class="absolute -right-6 -bottom-6 w-28 h-28 rounded-full bg-error/10 blur-2xl pointer-events-none"></div>
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-mono text-[11px] text-on-surface-variant uppercase tracking-wider font-bold">Threat Interceptions (24H)</span>
                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-error-container/20 text-error font-bold">AUTONOMOUS</span>
                    </div>
                    <div>
                        <div class="flex items-baseline gap-2">
                            <span class="text-3xl font-extrabold text-error tracking-tight font-mono"><?php echo max(1, $total_logs_24h * 12); ?></span>
                            <span class="font-mono text-xs text-on-surface-variant font-medium">Neutralized</span>
                        </div>
                        <div class="mt-3 pt-1 grid grid-cols-3 gap-1 bg-surface-container-lowest/60 rounded p-1 text-center font-mono text-[11px] border border-[#1e293b]/60">
                            <div>
                                <div class="text-white font-medium">42</div>
                                <div class="text-on-surface-variant text-[9px] uppercase tracking-tighter">Stuffing</div>
                            </div>
                            <div>
                                <div class="text-tertiary font-medium">9</div>
                                <div class="text-on-surface-variant text-[9px] uppercase tracking-tighter">Travel</div>
                            </div>
                            <div>
                                <div class="text-error font-medium"><?php echo max(12, $total_logs_24h * 10); ?></div>
                                <div class="text-on-surface-variant text-[9px] uppercase tracking-tighter">Bot Sprays</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Primary Intelligence Layout (12 Columns: 8 Left, 4 Right) -->
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

                <!-- ========================================================= -->
                <!-- LEFT MAIN COLUMN (8 Columns)                              -->
                <!-- ========================================================= -->
                <div class="lg:col-span-8 space-y-6">

                    <!-- 1. Adaptive Authentication Telemetry & Waveform Card -->
                    <div id="telemetrySection" class="p-6 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl">
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                            <div class="space-y-0.5">
                                <div class="flex items-center gap-2">
                                    <i class="fa-solid fa-key text-[16px] text-primary"></i>
                                    <h2 class="text-base sm:text-lg text-white font-semibold">Adaptive Authentication Telemetry</h2>
                                </div>
                                <p class="text-xs text-on-surface-variant">FIDO2 WebAuthn cryptographic attestation distribution &amp; token evaluation latency</p>
                            </div>
                            <div class="flex items-center gap-2 font-mono text-xs bg-surface-container-lowest px-3 py-1 rounded text-primary border border-[#1e293b]">
                                <span>P99 LATENCY:</span>
                                <span class="font-bold text-white">18.4ms</span>
                            </div>
                        </div>

                        <!-- Latency Waveform Visual (Inline SVG) -->
                        <div class="relative bg-surface-container-lowest rounded p-3 overflow-hidden mb-4 border border-[#1e293b]">
                            <div class="flex items-center justify-between text-on-surface-variant font-mono text-[10px] mb-1 px-1">
                                <span>JWT / HMAC EVALUATION STABILITY</span>
                                <span class="text-secondary font-bold">0.00% Packet Loss</span>
                            </div>
                            <svg class="w-full h-16 text-primary" fill="none" preserveAspectRatio="none" viewBox="0 0 800 64">
                                <defs>
                                    <linearGradient id="waveGradient" x1="0" x2="0" y1="0" y2="1">
                                        <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.35"></stop>
                                        <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.0"></stop>
                                    </linearGradient>
                                </defs>
                                <path d="M0,45 Q20,40 40,43 T80,36 T120,44 T160,32 T200,38 T240,24 T280,28 T320,18 T360,22 T400,16 T440,28 T480,20 T520,34 T560,30 T600,15 T640,22 T680,18 T720,24 T760,20 L800,22 L800,64 L0,64 Z" fill="url(#waveGradient)"></path>
                                <path d="M0,45 Q20,40 40,43 T80,36 T120,44 T160,32 T200,38 T240,24 T280,28 T320,18 T360,22 T400,16 T440,28 T480,20 T520,34 T560,30 T600,15 T640,22 T680,18 T720,24 T760,20 L800,22" stroke="#38bdf8" stroke-linecap="round" stroke-width="1.8"></path>
                            </svg>
                        </div>

                        <!-- Auth Method Breakdown -->
                        <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
                            <div class="p-3 rounded bg-surface-container border border-[#1e293b]">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="font-mono text-[10px] text-on-surface-variant font-bold">FIDO2 / PASSKEY</span>
                                    <span class="w-2 h-2 rounded-full bg-secondary"></span>
                                </div>
                                <div class="text-lg font-bold text-white font-mono">62.0%</div>
                                <div class="text-xs text-secondary font-mono mt-0.5">Hardware Bound</div>
                            </div>
                            <div class="p-3 rounded bg-surface-container border border-[#1e293b]">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="font-mono text-[10px] text-on-surface-variant font-bold">MOBILE PUSH</span>
                                    <span class="w-2 h-2 rounded-full bg-primary"></span>
                                </div>
                                <div class="text-lg font-bold text-white font-mono">29.0%</div>
                                <div class="text-xs text-primary font-mono mt-0.5">Biometric Match</div>
                            </div>
                            <div class="p-3 rounded bg-surface-container border border-[#1e293b]">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="font-mono text-[10px] text-on-surface-variant font-bold">TOTP APP</span>
                                    <span class="w-2 h-2 rounded-full bg-tertiary"></span>
                                </div>
                                <div class="text-lg font-bold text-white font-mono">8.5%</div>
                                <div class="text-xs text-on-surface-variant font-mono mt-0.5">Legacy RFC 6238</div>
                            </div>
                            <div class="p-3 rounded bg-surface-container border border-[#1e293b]">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="font-mono text-[10px] text-on-surface-variant font-bold">SMS / UNTRUSTED</span>
                                    <span class="w-2 h-2 rounded-full bg-error"></span>
                                </div>
                                <div class="text-lg font-bold text-error font-mono">0.5%</div>
                                <div class="text-xs text-error font-mono mt-0.5">433 Blocked Auto</div>
                            </div>
                        </div>
                    </div>

                    <!-- 2. Identities Directory & RBAC Control Matrix -->
                    <div id="directorySection" class="p-6 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl">
                        <div class="flex justify-between items-center mb-5 pb-3 border-b border-[#1e293b]">
                            <div>
                                <h3 class="text-base font-bold text-white flex items-center gap-2">
                                    <i class="fa-solid fa-users-gear text-[#38bdf8]"></i> Identities &amp; Directory (RBAC Control Matrix)
                                </h3>
                                <p class="text-xs text-on-surface-variant mt-0.5">Enforce Zero-Trust least privilege and trigger instant identity kill-switch locks.</p>
                            </div>
                            <span class="text-xs font-mono text-[#38bdf8] bg-sky-950/60 px-3 py-1 rounded border border-sky-500/30 font-bold">
                                <?php echo count($users); ?> IDENTITIES REGISTERED
                            </span>
                        </div>

                        <!-- Table -->
                        <div class="overflow-x-auto custom-scrollbar">
                            <table class="w-full text-left text-xs font-sans">
                                <thead class="text-slate-400 font-mono text-[11px] uppercase tracking-wider bg-surface-container-lowest/80 border-b border-[#1e293b]">
                                    <tr>
                                        <th class="px-4 py-3">UID</th>
                                        <th class="px-4 py-3">Account / Identity</th>
                                        <th class="px-4 py-3">Role</th>
                                        <th class="px-4 py-3">Clearance</th>
                                        <th class="px-4 py-3">MFA Status</th>
                                        <th class="px-4 py-3">Status</th>
                                        <th class="px-4 py-3 text-right">SOC Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-[#1e293b]">
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
                                            stripos($user_clearance_val, 'Tier 3') !== false => 'bg-purple-500/15 text-purple-300 border-purple-500/40',
                                            stripos($user_clearance_val, 'Tier 2') !== false => 'bg-sky-500/15 text-sky-300 border-sky-500/40',
                                            default => 'bg-amber-500/15 text-amber-300 border-amber-500/40',
                                        };
                                    ?>
                                    <tr class="hover:bg-surface-container/60 transition <?php echo !$is_active ? 'bg-red-950/15' : ''; ?>">
                                        <!-- UID -->
                                        <td class="px-4 py-3.5 font-mono text-[11px] text-slate-400">
                                            UID-<?php echo str_pad($uid, 4, '0', STR_PAD_LEFT); ?>
                                        </td>

                                        <!-- Account Email -->
                                        <td class="px-4 py-3.5">
                                            <div class="flex items-center gap-2.5">
                                                <div class="w-8 h-8 rounded <?php echo $is_active ? 'bg-surface-container text-slate-200 border border-[#334155]' : 'bg-red-950/50 text-red-400 border border-red-500/30'; ?> flex items-center justify-center font-bold text-xs shrink-0">
                                                    <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                                                </div>
                                                <div class="min-w-0">
                                                    <div class="text-white font-medium text-xs flex items-center gap-1.5">
                                                        <span class="truncate"><?php echo $user_email; ?></span>
                                                        <?php if ($is_self): ?>
                                                            <span class="text-[9px] font-mono bg-sky-500/20 text-sky-400 border border-sky-500/30 px-1 py-0.2 rounded font-bold">YOU</span>
                                                        <?php endif; ?>
                                                    </div>
                                                    <div class="text-[10px] text-slate-400 font-mono truncate">
                                                        <?php echo htmlspecialchars(trim(($u['first_name'] ?? '') . ' ' . ($u['last_name'] ?? ''))); ?> &bull; <?php echo htmlspecialchars($user_dept_val); ?>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>

                                        <!-- Role -->
                                        <td class="px-4 py-3.5">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border <?php echo $role_badge; ?>">
                                                <i class="fa-solid fa-shield mr-1 text-[9px]"></i> <?php echo $user_functional_role; ?>
                                            </span>
                                        </td>

                                        <!-- Clearance -->
                                        <td class="px-4 py-3.5">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold border <?php echo $clearance_badge; ?>">
                                                <i class="fa-solid fa-gem mr-1 text-[9px]"></i> <?php echo htmlspecialchars($user_clearance_val); ?>
                                            </span>
                                        </td>

                                        <!-- MFA Status -->
                                        <td class="px-4 py-3.5">
                                            <?php if (!empty($u['mfa_secret'])): ?>
                                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                    <i class="fa-solid fa-circle-check mr-1 text-[10px]"></i> ENFORCED
                                                </span>
                                            <?php else: ?>
                                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                                    <i class="fa-solid fa-triangle-exclamation mr-1 text-[10px]"></i> UNPROTECTED
                                                </span>
                                            <?php endif; ?>
                                        </td>

                                        <!-- Status -->
                                        <td class="px-4 py-3.5">
                                            <?php if ($is_active): ?>
                                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                    <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                                </span>
                                            <?php else: ?>
                                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
                                                    <span class="h-1.5 w-1.5 rounded-full bg-red-400 mr-1.5"></span> SUSPENDED
                                                </span>
                                            <?php endif; ?>
                                        </td>

                                        <!-- Actions -->
                                        <td class="px-4 py-3.5 text-right whitespace-nowrap">
                                            <div class="inline-flex items-center gap-1">
                                                <?php if ($is_self): ?>
                                                    <span class="p-1.5 text-slate-600 text-xs" title="Self-suspension locked by security policy">
                                                        <i class="fa-solid fa-lock"></i>
                                                    </span>
                                                <?php else: ?>
                                                    <!-- Toggle Status Form -->
                                                    <form method="POST" action="" class="inline" onsubmit="return confirm('<?php echo $is_active ? 'Are you sure you want to SUSPEND UID-' . $uid . ' (' . $user_email . ')?' : 'Reactivate account UID-' . $uid . ' (' . $user_email . ')?'; ?>');">
                                                        <input type="hidden" name="action" value="toggle_status">
                                                        <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                        <input type="hidden" name="new_status" value="<?php echo $is_active ? 0 : 1; ?>">
                                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                        <?php if ($is_active): ?>
                                                            <button type="submit" class="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition" title="Suspend Identity">
                                                                <i class="fa-solid fa-user-slash text-xs"></i>
                                                            </button>
                                                        <?php else: ?>
                                                            <button type="submit" class="p-1.5 text-red-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded transition" title="Reactivate Identity">
                                                                <i class="fa-solid fa-user-check text-xs"></i>
                                                            </button>
                                                        <?php endif; ?>
                                                    </form>
                                                <?php endif; ?>

                                                <!-- Edit Role Modal Trigger -->
                                                <button onclick="openRoleModal(<?php echo $uid; ?>, '<?php echo addslashes($user_email); ?>', <?php echo $user_role_id; ?>, '<?php echo addslashes($user_functional_role); ?>', '<?php echo addslashes($user_clearance_val); ?>')" class="p-1.5 text-slate-400 hover:text-[#38bdf8] hover:bg-sky-500/10 rounded transition" title="Modify RBAC Role &amp; Clearance">
                                                    <i class="fa-solid fa-user-gear text-xs"></i>
                                                </button>

                                                <?php if (!$is_self): ?>
                                                    <!-- Purge Form -->
                                                    <form method="POST" action="" class="inline" onsubmit="return confirm('PERMANENT ACTION: Purge UID-<?php echo $uid; ?> (<?php echo $user_email; ?>) permanently from database?');">
                                                        <input type="hidden" name="action" value="delete_user">
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

                    <!-- 3. Real-Time Threat & Anomaly Triage Feed -->
                    <div id="triageSection" class="p-6 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl space-y-4">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-triangle-exclamation text-[16px] text-error"></i>
                                <h2 class="text-base sm:text-lg text-white font-semibold">Active Threat &amp; Anomaly Triage</h2>
                            </div>
                            <span class="font-mono text-[10px] px-2 py-0.5 rounded bg-error/10 text-error font-bold">3 ACTIVE CONFLICTS</span>
                        </div>

                        <!-- Triage Items List -->
                        <div class="space-y-3">
                            <!-- Item 1: Critical Impossible Travel -->
                            <div class="p-4 rounded bg-surface-container hover:bg-surface-container-high transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 border border-[#1e293b]">
                                <div class="space-y-1">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-error-container text-white font-bold">CRITICAL</span>
                                        <span class="text-xs font-semibold text-white">Impossible Travel Velocity Violation</span>
                                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface-container-lowest text-secondary border border-secondary/30">AUTO-QUARANTINED</span>
                                    </div>
                                    <p class="text-xs text-on-surface-variant">
                                        User <span class="font-mono text-white font-medium">marcus.chen@corp.com</span> authenticated from <span class="text-white">Frankfurt, DE (10:14 UTC)</span> and <span class="text-white">Tokyo, JP (10:28 UTC)</span>. Apparent ground speed: <span class="font-mono text-error font-semibold">~9,200 km/h</span>.
                                    </p>
                                    <div class="font-mono text-[10px] text-outline flex items-center gap-2 pt-0.5">
                                        <span>SESSION_ID: a9f8e-77d-c20</span>
                                        <span>&bull;</span>
                                        <span>RULE: ZT-SEC-GEO-VELOCITY</span>
                                        <span>&bull;</span>
                                        <span>12m ago</span>
                                    </div>
                                </div>
                                <div class="flex items-center gap-2 shrink-0">
                                    <button onclick="alert('Session Telemetry Context:\n&bull; User: marcus.chen@corp.com\n&bull; Origin 1: 194.12.44.8 (DE)\n&bull; Origin 2: 133.242.18.9 (JP)\n&bull; Action: Access Token Invalidated\n&bull; Defense: Automated Quarantined');" class="px-3 py-1.5 rounded bg-surface-container-lowest hover:bg-surface-dim text-on-surface text-xs font-medium border border-[#334155] transition">
                                        Inspect Context
                                    </button>
                                    <button onclick="alert('Credential purge triggered. Refreshing token revocation list.');" class="px-3 py-1.5 rounded bg-error-container hover:bg-on-error text-white text-xs font-semibold transition">
                                        Purge Credential
                                    </button>
                                </div>
                            </div>

                            <!-- Item 2: Medium PIM Elevation -->
                            <div class="p-4 rounded bg-surface-container hover:bg-surface-container-high transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 border border-[#1e293b]">
                                <div class="space-y-1">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-tertiary-container text-on-tertiary-container font-bold">MEDIUM RISK</span>
                                        <span class="text-xs font-semibold text-white">Privileged Access Management (PIM) Elevation Active</span>
                                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface-container-lowest text-primary border border-primary/30">JIT APPROVED</span>
                                    </div>
                                    <p class="text-xs text-on-surface-variant">
                                        User <span class="font-mono text-white font-medium">devops-lead@corp.com</span> acquired temporary Root cluster-admin on <span class="text-white">Kubernetes US-West Production</span>. TTL remaining: <span class="font-mono text-tertiary font-semibold">42m 18s</span>.
                                    </p>
                                    <div class="font-mono text-[10px] text-outline flex items-center gap-2 pt-0.5">
                                        <span>TICKET: SEC-8891 (Prod Incident)</span>
                                        <span>&bull;</span>
                                        <span>JUSTIFICATION: Node drain failover</span>
                                    </div>
                                </div>
                                <div class="flex items-center gap-2 shrink-0">
                                    <a href="audit_report.php" class="px-3 py-1.5 rounded bg-surface-container-lowest hover:bg-surface-dim text-on-surface text-xs font-medium border border-[#334155] transition">
                                        Live Audit
                                    </a>
                                    <button onclick="alert('PIM session revoked successfully.');" class="px-3 py-1.5 rounded bg-surface-container-high hover:bg-surface-bright text-tertiary text-xs font-semibold transition border border-tertiary/40">
                                        Revoke Early
                                    </button>
                                </div>
                            </div>

                            <!-- Item 3: Low MDM Restriction -->
                            <div class="p-4 rounded bg-surface-container hover:bg-surface-container-high transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 border border-[#1e293b]">
                                <div class="space-y-1">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface font-semibold">LOW ADVISORY</span>
                                        <span class="text-xs font-semibold text-white">Unenrolled Device Enrollment Restriction</span>
                                    </div>
                                    <p class="text-xs text-on-surface-variant">
                                        Device <span class="font-mono text-white">MacBookPro21,1 (macOS 14.5)</span> attempted access to Github Enterprise without MDM certificate profiles. Step-up challenge passed, device blocked.
                                    </p>
                                    <div class="font-mono text-[10px] text-outline flex items-center gap-2 pt-0.5">
                                        <span>IDENTITY: alexandra.v@corp.com</span>
                                        <span>&bull;</span>
                                        <span>ENCLAVE: Intune Pending</span>
                                        <span>&bull;</span>
                                        <span>28m ago</span>
                                    </div>
                                </div>
                                <div class="flex items-center gap-2 shrink-0">
                                    <button onclick="alert('MDM enrollment invitation dispatched to alexandra.v@corp.com');" class="px-3 py-1.5 rounded bg-primary-container text-on-primary-container hover:bg-primary text-xs font-bold transition">
                                        Send MDM Invite
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ========================================================= -->
                <!-- RIGHT SIDEBAR COLUMN (4 Columns)                          -->
                <!-- ========================================================= -->
                <div class="lg:col-span-4 space-y-6">

                    <!-- 1. AI Sentinel Engine Heuristic Terminal -->
                    <div class="p-5 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl">
                        <div class="flex items-center justify-between pb-3 border-b border-[#1e293b] mb-3">
                            <div class="flex items-center gap-2">
                                <div class="flex space-x-1.5 mr-1">
                                    <div class="w-2.5 h-2.5 rounded-full bg-red-500/90"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-amber-500/90"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-emerald-500/90"></div>
                                </div>
                                <h3 class="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                                    <i class="fa-solid fa-microchip text-[#38bdf8]"></i> AI Sentinel Heuristic Engine
                                </h3>
                            </div>
                            <span class="text-[10px] font-mono <?php echo $active_theme['text']; ?> border <?php echo $active_theme['border']; ?> px-2 py-0.5 rounded <?php echo $active_theme['bg']; ?> font-bold">
                                <?php echo $threat_level; ?>
                            </span>
                        </div>

                        <!-- Terminal Output Window -->
                        <div id="sentinelTerminalConsole" class="terminal-window p-3.5 font-mono text-xs text-slate-400 space-y-2 h-72 overflow-y-auto custom-scrollbar bg-slate-950 rounded border border-[#1e293b]">
                            <?php foreach ($terminal_logs as $tlog): 
                                $badge_color = match($tlog['type']) {
                                    'SYSTEM' => 'text-sky-400 font-bold',
                                    'CRITICAL' => 'text-red-400 font-bold',
                                    'WARN' => 'text-amber-400 font-bold',
                                    'OK' => 'text-emerald-400 font-bold',
                                    'SUMMARY' => 'text-purple-400 font-bold',
                                    default => 'text-slate-400'
                                };
                            ?>
                            <div class="flex items-start space-x-1.5 leading-relaxed">
                                <span class="text-slate-600 select-none">[<?php echo $tlog['time']; ?>]</span>
                                <span class="<?php echo $badge_color; ?> select-none">[<?php echo $tlog['badge']; ?>]</span>
                                <span class="<?php echo ($tlog['type'] === 'CRITICAL') ? 'text-red-300 font-medium' : 'text-slate-300'; ?>">
                                    <?php echo htmlspecialchars($tlog['msg']); ?>
                                </span>
                            </div>
                            <?php endforeach; ?>
                            
                            <div class="pt-2 flex items-center space-x-2 text-slate-500">
                                <span class="text-[#38bdf8] font-bold">&gt;</span>
                                <span class="text-[11px] text-[#38bdf8]/80 font-mono">Sentinel heuristic engine scanning audit streams in real-time...</span>
                            </div>
                        </div>
                    </div>

                    <!-- 2. Ingress Telemetry & Edge Anycast Card -->
                    <div class="p-5 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl space-y-4">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-globe text-[16px] text-primary"></i>
                                <h2 class="text-sm font-semibold text-white">Ingress Telemetry</h2>
                            </div>
                            <span class="font-mono text-[10px] text-secondary font-bold">EDGE: ANYCAST</span>
                        </div>

                        <!-- Attack Surface Map Container -->
                        <div class="relative w-full h-36 rounded overflow-hidden bg-surface-container-lowest border border-[#1e293b] flex items-center justify-center">
                            <div class="absolute inset-0 bg-cover bg-center opacity-40" style="background-image: radial-gradient(circle at center, rgba(56, 189, 248, 0.25) 0, transparent 70%);"></div>
                            <div class="z-10 text-center font-mono space-y-1">
                                <i class="fa-solid fa-network-wired text-primary text-2xl animate-pulse"></i>
                                <div class="text-[11px] text-slate-300 font-bold">24-NODE ENCLAVE MESH</div>
                                <div class="text-[10px] text-secondary font-bold">100% End-to-End Encrypted</div>
                            </div>
                            <div class="absolute bottom-2 left-2 right-2 flex justify-between items-center text-on-surface font-mono text-[10px] bg-surface-dim/90 backdrop-blur-md px-2.5 py-1 rounded border border-[#1e293b]">
                                <span>TOR &amp; PROXIES:</span>
                                <span class="text-secondary font-bold">1,378 Drops (100% Mitigated)</span>
                            </div>
                        </div>

                        <!-- Top Verification Origins -->
                        <div class="space-y-1.5 pt-1">
                            <div class="font-mono text-[10px] text-on-surface-variant uppercase tracking-wider font-bold">Top Verification Origins</div>
                            <div class="flex items-center justify-between p-2 rounded bg-surface-container border border-[#1e293b] text-xs">
                                <div class="flex items-center gap-2 min-w-0">
                                    <span class="font-mono text-outline font-bold">01</span>
                                    <span class="font-medium text-white truncate">United States (East)</span>
                                </div>
                                <div class="font-mono text-[11px] text-right shrink-0">
                                    <span class="text-white">54,120</span>
                                    <span class="text-secondary ml-1 font-bold">9.2ms</span>
                                </div>
                            </div>
                            <div class="flex items-center justify-between p-2 rounded bg-surface-container border border-[#1e293b] text-xs">
                                <div class="flex items-center gap-2 min-w-0">
                                    <span class="font-mono text-outline font-bold">02</span>
                                    <span class="font-medium text-white truncate">Germany (Frankfurt)</span>
                                </div>
                                <div class="font-mono text-[11px] text-right shrink-0">
                                    <span class="text-white">22,890</span>
                                    <span class="text-secondary ml-1 font-bold">14.1ms</span>
                                </div>
                            </div>
                            <div class="flex items-center justify-between p-2 rounded bg-surface-container border border-[#1e293b] text-xs">
                                <div class="flex items-center gap-2 min-w-0">
                                    <span class="font-mono text-outline font-bold">03</span>
                                    <span class="font-medium text-white truncate">Japan (Tokyo)</span>
                                </div>
                                <div class="font-mono text-[11px] text-right shrink-0">
                                    <span class="text-white">8,912</span>
                                    <span class="text-secondary ml-1 font-bold">21.8ms</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 3. Cryptographic HSM & Root Key Attestation -->
                    <div id="hsmSection" class="p-5 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl space-y-4">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-microchip text-[16px] text-secondary"></i>
                                <h2 class="text-sm font-semibold text-white">Cryptographic HSM</h2>
                            </div>
                            <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-secondary/10 text-secondary font-bold">FIPS 140-3 L4</span>
                        </div>
                        <div class="space-y-3 bg-surface-container rounded p-3 border border-[#1e293b]">
                            <div>
                                <div class="flex justify-between items-center text-on-surface-variant font-mono text-[10px] mb-1">
                                    <span>ROOT KEY ROTATION</span>
                                    <span class="text-white font-bold">14d remaining (90d cycle)</span>
                                </div>
                                <div class="w-full bg-surface-container-lowest rounded-full h-1.5 overflow-hidden border border-[#1e293b]">
                                    <div class="bg-primary h-full rounded-full" style="width: 84%;"></div>
                                </div>
                            </div>
                            <div class="pt-1 space-y-1 font-mono text-[11px]">
                                <div class="flex justify-between">
                                    <span class="text-on-surface-variant">Signature Standard:</span>
                                    <span class="text-white font-bold">Ed25519 / Dilithium-3 PQ</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-on-surface-variant">Attestation Engine:</span>
                                    <span class="text-secondary font-bold">AWS CloudHSM Cluster-4</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-on-surface-variant">Entropy Level:</span>
                                    <span class="text-secondary font-bold">Quantum RNG (99.99%)</span>
                                </div>
                            </div>
                        </div>

                        <!-- Duty Officer Attested Profile -->
                        <div class="p-3 rounded bg-surface-container-lowest flex items-center justify-between border border-[#1e293b]">
                            <div class="flex items-center gap-2.5 min-w-0">
                                <div class="w-9 h-9 rounded-full bg-secondary/20 text-secondary border border-secondary/40 flex items-center justify-center font-bold text-xs shrink-0">
                                    <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                                </div>
                                <div class="min-w-0">
                                    <div class="text-xs font-semibold text-white truncate"><?php echo htmlspecialchars($user_display_name); ?></div>
                                    <div class="font-mono text-[10px] text-secondary truncate flex items-center gap-1">
                                        <i class="fa-solid fa-fingerprint text-[11px]"></i>
                                        <span>YubiKey 5C NFC Attested</span>
                                    </div>
                                </div>
                            </div>
                            <span class="font-mono text-[10px] px-2 py-0.5 rounded bg-secondary/15 text-secondary shrink-0 font-bold">DUTY</span>
                        </div>
                    </div>

                    <!-- 4. Live Cryptographic Audit Stream -->
                    <div id="auditStreamSection" class="p-5 rounded-lg bg-surface-container-low border border-[#1e293b] shadow-xl">
                        <div class="flex justify-between items-center pb-3 border-b border-[#1e293b] mb-3">
                            <h3 class="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                                <i class="fa-solid fa-server text-[#38bdf8]"></i> Live Audit Stream
                            </h3>
                            <span class="text-[10px] font-mono text-emerald-400 flex items-center font-bold">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span> LIVE INGEST
                            </span>
                        </div>
                        <div class="bg-surface-container-lowest rounded border border-[#1e293b]">
                            <ul class="divide-y divide-[#1e293b] max-h-80 overflow-y-auto custom-scrollbar font-mono text-xs">
                                <?php if (count($audit_logs) > 0): ?>
                                    <?php foreach ($audit_logs as $log): 
                                        $action_type = strtoupper($log['action_type'] ?? 'EVENT');
                                        $action_text = $log['action_description'] ?? 'System Event Logged';
                                        $ip = $log['ip_address'] ?? '127.0.0.1';
                                        $time = $log['created_at'] ?? '';
                                        
                                        $icon_data = match($action_type) {
                                            'LOGIN', 'MFA_AUTH' => ['icon' => 'fa-shield-halved', 'color' => 'text-emerald-400'],
                                            'MFA_FAIL', 'LOGIN_FAIL' => ['icon' => 'fa-triangle-exclamation', 'color' => 'text-red-400'],
                                            'ACCOUNT_SUSPENDED' => ['icon' => 'fa-lock', 'color' => 'text-amber-400'],
                                            'ACCOUNT_ACTIVATED' => ['icon' => 'fa-lock-open', 'color' => 'text-emerald-400'],
                                            'ROLE_UPDATED' => ['icon' => 'fa-user-gear', 'color' => 'text-sky-400'],
                                            'USER_PROVISIONED' => ['icon' => 'fa-user-plus', 'color' => 'text-purple-400'],
                                            'USER_PURGED' => ['icon' => 'fa-trash-can', 'color' => 'text-red-400'],
                                            'LOGOUT' => ['icon' => 'fa-arrow-right-from-bracket', 'color' => 'text-slate-400'],
                                            'SUSPENDED_LOGIN_ATTEMPT' => ['icon' => 'fa-ban', 'color' => 'text-red-500'],
                                            'EMERGENCY_LOCKDOWN_TRIGGERED' => ['icon' => 'fa-power-off', 'color' => 'text-red-400'],
                                            'EMERGENCY_LOCKDOWN_LIFTED' => ['icon' => 'fa-lock-open', 'color' => 'text-emerald-400'],
                                            'BASELINE_RESET' => ['icon' => 'fa-rotate-left', 'color' => 'text-emerald-400'],
                                            default => ['icon' => 'fa-shield', 'color' => 'text-slate-400']
                                        };
                                    ?>
                                    <li class="p-3 hover:bg-surface-container/60 transition group">
                                        <div class="flex space-x-2.5">
                                            <div class="shrink-0 mt-0.5">
                                                <i class="fa-solid <?php echo $icon_data['icon']; ?> <?php echo $icon_data['color']; ?> text-xs"></i>
                                            </div>
                                            <div class="min-w-0 flex-1">
                                                <p class="text-xs text-slate-300 font-medium break-words leading-snug"><?php echo htmlspecialchars($action_text); ?></p>
                                                <div class="flex items-center text-[10px] text-slate-500 mt-1 flex-wrap gap-x-2 font-mono">
                                                    <span>IP: <code class="text-primary font-bold"><?php echo htmlspecialchars($ip); ?></code></span>
                                                    <span>|</span>
                                                    <span class="text-slate-400">UID-<?php echo htmlspecialchars($log['user_id'] ? str_pad($log['user_id'], 4, '0', STR_PAD_LEFT) : 'SYS'); ?></span>
                                                    <span>|</span>
                                                    <span><?php echo htmlspecialchars($time); ?></span>
                                                </div>
                                            </div>
                                        </div>
                                    </li>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <li class="p-6 text-center text-xs text-slate-500 font-mono">
                                        Audit stream is currently empty.
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    </div>

                </div>
            </div>

            <!-- Footer -->
            <div class="mt-12 text-center border-t border-[#1e293b] pt-6 text-xs text-slate-500 font-mono">
                <i class="fa-solid fa-shield-halved text-[#38bdf8] mr-1"></i>
                ENTERPRISE ZERO-TRUST IAM PORTAL &bull; AIR-GAPPED SECURE ENCLAVE &bull; iam.secure-defense.internal
            </div>
        </main>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 1: PROVISION IDENTITY                                               -->
    <!-- ========================================================================= -->
    <div id="provisionModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-surface-container-low border border-[#1e293b] w-full max-w-xl rounded-xl p-6 shadow-2xl relative overflow-hidden">
            <div class="flex justify-between items-center border-b border-[#1e293b] pb-3 mb-4">
                <div class="flex items-center space-x-2 text-sky-400">
                    <i class="fa-solid fa-user-plus text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Provision New Workforce Identity</h3>
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
                        <input type="text" name="first_name" placeholder="John" required class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Last Name</label>
                        <input type="text" name="last_name" placeholder="Doe" required class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Enterprise Email Address</label>
                        <input type="email" name="new_email" placeholder="j.doe@organization.com" required class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Initial Temporary Password</label>
                        <input type="password" name="new_password" required placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Department</label>
                        <input type="text" name="department" placeholder="Cloud Infrastructure" value="General Operations" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Job Title</label>
                        <input type="text" name="job_title" placeholder="DevOps Engineer" value="Staff Analyst" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Functional RBAC Role</label>
                        <select name="role" id="provRoleSelect" onchange="syncProvisioningDefaults()" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                            <option value="Staff">Staff (Standard Least-Privilege)</option>
                            <option value="Auditor">Auditor (Compliance &amp; Logs)</option>
                            <option value="Admin">Admin (Full Enclave Management)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-mono text-slate-400 mb-1">Security Clearance Enclave</label>
                        <select name="security_clearance" id="provClearanceSelect" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                            <option value="Tier 1">Tier 1 &mdash; General Workspace</option>
                            <option value="Tier 2">Tier 2 &mdash; Sensitive Logs &amp; PII</option>
                            <option value="Tier 3">Tier 3 &mdash; Root Credentials &amp; Vault</option>
                        </select>
                    </div>
                </div>
                <input type="hidden" name="role_id" id="provRoleIdHidden" value="4">

                <div class="flex space-x-3 pt-3">
                    <button type="button" onclick="document.getElementById('provisionModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#334155] hover:bg-surface-container text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white shadow transition">
                        Provision Identity
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 2: EDIT ROLE & CLEARANCE (RBAC)                                     -->
    <!-- ========================================================================= -->
    <div id="roleModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-surface-container-low border border-[#1e293b] w-full max-w-md rounded-xl p-6 shadow-2xl relative">
            <div class="flex justify-between items-center border-b border-[#1e293b] pb-3 mb-4">
                <div class="flex items-center space-x-2 text-sky-400">
                    <i class="fa-solid fa-user-gear text-base"></i>
                    <h3 class="font-sans font-bold text-white text-base">Modify RBAC Policy</h3>
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
                    <div id="roleModalEmail" class="text-xs font-bold text-sky-400 bg-surface-container px-3 py-2 rounded border border-[#1e293b] font-mono"></div>
                </div>

                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Functional Access Role</label>
                    <select name="new_functional_role" id="roleModalFuncRole" onchange="syncRoleModalDefaults()" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                        <option value="Staff">Staff (Standard Least-Privilege)</option>
                        <option value="Auditor">Auditor (Compliance &amp; Logs)</option>
                        <option value="Admin">Admin (Full Enclave Management)</option>
                    </select>
                </div>

                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Security Clearance Level</label>
                    <select name="new_clearance" id="roleModalClearance" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                        <option value="Tier 1">Tier 1 &mdash; General Workspace</option>
                        <option value="Tier 2">Tier 2 &mdash; Sensitive Logs &amp; PII</option>
                        <option value="Tier 3">Tier 3 &mdash; Root Credentials &amp; Vault</option>
                    </select>
                </div>

                <div>
                    <label class="block text-xs font-mono text-slate-400 mb-1">Underlying Permission Matrix</label>
                    <select name="new_role_id" id="roleModalSelect" class="w-full px-3 py-2 rounded bg-surface-container border border-[#1e293b] text-white text-xs focus:border-sky-400 focus:outline-hidden">
                        <?php foreach ($roles as $r): ?>
                            <option value="<?php echo $r['role_id']; ?>"><?php echo htmlspecialchars($r['role_name']); ?> (Matrix Level <?php echo $r['role_id']; ?>)</option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="flex space-x-3 pt-3">
                    <button type="button" onclick="document.getElementById('roleModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#334155] hover:bg-surface-container text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white shadow transition">
                        Apply Policy
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 3: EMERGENCY LOCKDOWN CONFIRMATION MODAL                            -->
    <!-- ========================================================================= -->
    <div id="lockdownModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="bg-surface-container-low border border-red-500/50 w-full max-w-md rounded-xl p-6 shadow-2xl relative space-y-4">
            <div class="flex items-center space-x-3 text-red-500">
                <i class="fa-solid fa-triangle-exclamation text-2xl"></i>
                <h3 class="font-sans font-bold text-white text-lg">Confirm Emergency Lockdown</h3>
            </div>
            
            <p class="text-xs text-slate-300 leading-relaxed font-sans">
                You are about to engage the <strong>Enclave Emergency Lockdown</strong> protocol. 
                This action will instantly:
            </p>
            
            <ul class="text-xs text-red-200 list-disc list-inside space-y-1 font-mono bg-red-950/40 p-3 rounded border border-red-500/30">
                <li>Suspend all non-administrator user accounts</li>
                <li>Terminate active session cookies immediately</li>
                <li>Block lateral credential movement in the enclave</li>
                <li>Generate an immutable critical SOC audit log entry</li>
            </ul>

            <form method="POST" action="" class="flex space-x-3 pt-2">
                <input type="hidden" name="action" value="emergency_lockdown">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <button type="button" onclick="document.getElementById('lockdownModal').classList.add('hidden')" class="w-1/2 py-2 rounded text-xs font-semibold border border-[#334155] hover:bg-surface-container text-slate-300 transition">
                    Abort
                </button>
                <button type="submit" class="w-1/2 py-2 rounded text-xs font-bold bg-red-600 hover:bg-red-700 text-white shadow transition flex items-center justify-center gap-1.5">
                    <i class="fa-solid fa-power-off"></i> Engage Lockdown
                </button>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 4: BIOMETRIC WELCOME HUD (Cleaned Up & Professional)                 -->
    <!-- ========================================================================= -->
    <div id="cyberWelcomeHUD" class="<?php echo $show_welcome_hud ? '' : 'hidden'; ?> fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-xs flex items-center justify-center p-4">
        <div class="bg-surface-container-low border border-[#1e293b] rounded-xl max-w-lg w-full p-6 sm:p-8 shadow-2xl space-y-5 text-center relative">
            <div class="w-14 h-14 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto text-emerald-400">
                <i class="fa-solid fa-fingerprint text-2xl"></i>
            </div>
            
            <div class="space-y-1">
                <h3 class="font-sans font-bold text-white text-lg">Identity Clearance Attested</h3>
                <p class="font-mono text-xs text-emerald-400 font-semibold">Zero-Trust Access Granted &bull; TLS 1.3 Verified</p>
            </div>
            
            <div class="grid grid-cols-2 gap-3 text-left font-mono text-xs">
                <div class="bg-surface-container p-2.5 rounded border border-[#1e293b]">
                    <span class="text-slate-500 text-[10px] uppercase">Identity:</span>
                    <p class="text-white font-medium truncate"><?php echo htmlspecialchars($current_user['email']); ?></p>
                </div>
                <div class="bg-surface-container p-2.5 rounded border border-[#1e293b]">
                    <span class="text-slate-500 text-[10px] uppercase">RBAC Role:</span>
                    <p class="text-sky-400 font-medium"><?php echo htmlspecialchars($current_functional_role); ?></p>
                </div>
                <div class="bg-surface-container p-2.5 rounded border border-[#1e293b]">
                    <span class="text-slate-500 text-[10px] uppercase">Clearance:</span>
                    <p class="text-purple-400 font-medium"><?php echo htmlspecialchars($current_clearance); ?></p>
                </div>
                <div class="bg-surface-container p-2.5 rounded border border-[#1e293b]">
                    <span class="text-slate-500 text-[10px] uppercase">Node Enclave:</span>
                    <p class="text-emerald-400 font-medium">iam.secure-defense.internal</p>
                </div>
            </div>

            <button onclick="dismissCyberWelcomeHUD()" class="w-full py-2.5 rounded bg-sky-600 hover:bg-sky-500 text-white font-sans text-xs font-bold transition shadow">
                Enter SOC Command Center
            </button>
            <p id="welcomeHudTimer" class="font-mono text-[10px] text-slate-500">Entering command center in 3s...</p>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- INTERACTIVE JAVASCRIPT CONTROLLERS                                        -->
    <!-- ========================================================================= -->
    <script>
        // Threat Simulation Menu Toggle
        function toggleSimMenu() {
            const menu = document.getElementById('simMenu');
            if (menu) {
                menu.classList.toggle('hidden');
            }
        }

        // Close dropdown when clicked outside
        document.addEventListener('click', function(e) {
            const container = document.getElementById('simulationDropdownContainer');
            const menu = document.getElementById('simMenu');
            if (container && menu && !container.contains(e.target)) {
                menu.classList.add('hidden');
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
                    timerText.innerText = 'Entering command center in ' + secs + 's...';
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

