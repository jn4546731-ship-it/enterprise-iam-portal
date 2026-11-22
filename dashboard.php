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
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Enterprise Zero-Trust SOC Command Center — Aegis IAM</title>

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

    <!-- Offline Air-Gapped Local Tailwind Engine -->
    <script src="assets/js/tailwind.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: {
                            DEFAULT: '#38bdf8',
                            hover: '#0284c7'
                        }
                    },
                    fontFamily: {
                        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
                        mono: ['JetBrains Mono', 'Share Tech Mono', 'monospace'],
                    }
                }
            }
        };
    </script>

    <!-- Local Offline FontAwesome Icons & Cyber Theme Tokens -->
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css?v=<?php echo time(); ?>" rel="stylesheet">
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="cyber-bg cyber-grid-overlay text-slate-300 font-sans min-h-screen flex flex-col antialiased selection:bg-sky-500/30 transition-colors duration-200">

    <!-- ========================================================================= -->
    <!-- TOP NAVIGATION BAR (Enterprise Okta Standard)                             -->
    <!-- ========================================================================= -->
    <nav class="border-b px-4 sm:px-6 py-2.5 flex justify-between items-center sticky top-0 z-30">
        <div class="flex items-center space-x-3">
            <button id="mobileSidebarToggle" onclick="toggleSidebar()" class="lg:hidden p-2 text-slate-400 hover:text-sky-400 rounded-lg hover:bg-slate-800 transition" aria-label="Toggle navigation drawer">
                <i class="fa-solid fa-bars text-sm"></i>
            </button>
            <div class="flex items-center space-x-2.5">
                <div class="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
                    <i class="fa-solid fa-shield-halved text-sm"></i>
                </div>
                <div>
                    <div class="flex items-center space-x-2">
                        <span class="font-sans font-bold text-sm tracking-tight text-white">SECURE·DEFENSE</span>
                        <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/25 font-semibold">ZERO-TRUST IAM</span>
                    </div>
                    <p class="text-[10px] text-slate-400 font-sans">Enterprise Identity &amp; Access Governance</p>
                </div>
            </div>
        </div>

        <!-- Center: Security Scope Pill -->
        <div class="hidden xl:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-700/50 text-xs text-slate-400">
            <span class="inline-flex h-2 w-2 rounded-full bg-emerald-400"></span>
            <span class="font-mono text-emerald-400 font-medium">iam.secure-defense.internal</span>
            <span class="text-slate-600">•</span>
            <span class="text-slate-400">Air-Gapped Production Enclave</span>
        </div>

        <!-- Right: Telemetry, Theme Switcher & Profile -->
        <div class="flex items-center space-x-2.5 text-xs">
            <!-- Sentinel Health Status -->
            <div class="hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-700/50">
                <span class="inline-flex h-1.5 w-1.5 rounded-full <?php echo $active_theme['ping']; ?>"></span>
                <span class="text-slate-400 text-[11px]">AI Sentinel:</span>
                <span class="<?php echo $active_theme['text']; ?> font-semibold text-[11px]"><?php echo $active_theme['badge']; ?></span>
            </div>

            <!-- Theme Toggle Button (Light / Dark Mode) -->
            <button onclick="toggleTheme()" id="themeToggleBtn" class="p-1.5 px-2.5 rounded-md bg-slate-900 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white transition flex items-center gap-1.5" title="Switch Theme (Light / Dark)">
                <i id="themeToggleIcon" class="fa-solid fa-sun text-xs text-amber-400"></i>
                <span class="hidden md:inline font-mono text-[11px]">Theme</span>
            </button>

            <!-- Clearance Badge -->
            <span class="hidden md:inline-flex items-center px-2 py-1 rounded-md text-[11px] font-mono font-bold bg-purple-500/10 text-purple-300 border border-purple-500/30">
                <i class="fa-solid fa-gem mr-1 text-[10px] text-purple-400"></i> <?php echo htmlspecialchars($current_clearance); ?>
            </span>

            <!-- User Identity Badge -->
            <div class="flex items-center space-x-2 bg-slate-900/90 pl-1 pr-3 py-1 rounded-full border border-slate-700/50">
                <div class="w-6 h-6 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/40 flex items-center justify-center font-bold text-[11px]">
                    <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                </div>
                <span class="text-slate-200 font-medium text-xs hidden sm:inline"><?php echo htmlspecialchars($current_user['email'] ?? 'admin@organization.com'); ?></span>
            </div>

            <!-- Sign Out -->
            <a href="logout.php" class="px-2.5 py-1 rounded-md text-xs font-semibold text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition flex items-center" title="Sign out of enterprise session">
                <i class="fa-solid fa-arrow-right-from-bracket mr-1.5 text-xs"></i>
                <span class="hidden sm:inline">Sign out</span>
            </a>
        </div>
    </nav>

    <!-- ========================================================================= -->
    <!-- MAIN WORKSPACE WITH UNIFIED PERSISTENT SIDEBAR                            -->
    <!-- ========================================================================= -->
    <div class="flex-1 flex overflow-hidden">

        <!-- Sidebar Navigation Drawer (Okta Standard) -->
        <aside id="appSidebar" class="fixed inset-y-0 left-0 z-40 w-64 border-r flex flex-col transition-transform duration-300 -translate-x-full lg:translate-x-0 lg:static lg:z-auto">
            
            <!-- User Summary Header Card -->
            <div class="p-3.5 border-b border-slate-700/50">
                <div class="p-3 rounded-lg bg-slate-900/60 border border-slate-700/50">
                    <div class="flex items-center space-x-2.5">
                        <div class="w-9 h-9 rounded-md bg-sky-500/15 border border-sky-500/30 flex items-center justify-center text-sky-300 font-bold text-sm">
                            <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                        </div>
                        <div class="overflow-hidden">
                            <h4 class="font-sans text-xs font-semibold text-white truncate"><?php echo htmlspecialchars($user_display_name); ?></h4>
                            <p class="font-mono text-[11px] text-slate-400 truncate"><?php echo htmlspecialchars($current_job_title); ?></p>
                        </div>
                    </div>
                    <div class="flex items-center justify-between text-[11px] font-sans pt-2 mt-2 border-t border-slate-700/40">
                        <span class="text-slate-500">Dept:</span>
                        <span class="text-slate-300 truncate max-w-[130px] font-medium"><?php echo htmlspecialchars($current_dept); ?></span>
                    </div>
                </div>
            </div>

            <!-- Categorized Navigation Links -->
            <nav class="flex-1 p-3 space-y-4 overflow-y-auto custom-scrollbar text-xs">
                
                <!-- Section 1: Directory & Governance -->
                <div>
                    <div class="px-3 mb-1.5 text-[11px] font-sans font-semibold uppercase tracking-wider text-slate-500">
                        Directory &amp; Governance
                    </div>
                    <div class="space-y-0.5">
                        <a href="dashboard.php" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-active transition">
                            <i class="fa-solid fa-users w-4 text-center"></i>
                            <span class="text-xs">User Directory</span>
                        </a>
                        <a href="#sentinelTelemetry" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-inactive transition">
                            <i class="fa-solid fa-chart-line w-4 text-center"></i>
                            <span class="text-xs">AI Risk Telemetry</span>
                        </a>
                    </div>
                </div>

                <!-- Section 2: Security & Authentication -->
                <div>
                    <div class="px-3 mb-1.5 text-[11px] font-sans font-semibold uppercase tracking-wider text-slate-500">
                        Authentication &amp; Policies
                    </div>
                    <div class="space-y-0.5">
                        <a href="setup_mfa.php" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-inactive transition">
                            <i class="fa-solid fa-mobile-screen-button w-4 text-center"></i>
                            <span class="text-xs">Multi-Factor Auth (MFA)</span>
                        </a>
                    </div>
                </div>

                <!-- Section 3: Privileged Access (PAM) -->
                <div>
                    <div class="px-3 mb-1.5 text-[11px] font-sans font-semibold uppercase tracking-wider text-slate-500">
                        Privileged Access (PAM)
                    </div>
                    <div class="space-y-0.5">
                        <a href="vault.php" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-inactive transition">
                            <i class="fa-solid fa-vault w-4 text-center"></i>
                            <span class="text-xs">Crown Jewels Vault</span>
                            <span class="ml-auto text-[10px] font-mono px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30">RBAC</span>
                        </a>
                        <a href="api_management.php" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-inactive transition">
                            <i class="fa-solid fa-key w-4 text-center"></i>
                            <span class="text-xs">API Credentials</span>
                        </a>
                    </div>
                </div>

                <!-- Section 4: Reports & Compliance -->
                <div>
                    <div class="px-3 mb-1.5 text-[11px] font-sans font-semibold uppercase tracking-wider text-slate-500">
                        Reports &amp; Compliance
                    </div>
                    <div class="space-y-0.5">
                        <a href="audit_report.php" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-inactive transition">
                            <i class="fa-solid fa-file-shield w-4 text-center"></i>
                            <span class="text-xs">Executive Audit Report</span>
                            <span class="ml-auto text-[10px] font-mono px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 font-bold border border-sky-500/30">NIST</span>
                        </a>
                        <a href="dashboard.php?export=csv" class="flex items-center space-x-3 px-3 py-2 rounded-md nav-item-inactive transition">
                            <i class="fa-solid fa-file-csv w-4 text-center"></i>
                            <span class="text-xs">Export Audit CSV</span>
                        </a>
                    </div>
                </div>

            </nav>

            <!-- Sidebar Footer Status -->
            <div class="p-3 border-t border-slate-700/50 text-[11px] font-sans text-slate-500">
                <div class="flex items-center space-x-2 text-emerald-400 mb-0.5">
                    <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
                    <span class="font-semibold text-xs">Zero-Trust Active</span>
                </div>
                <div class="text-[10px] text-slate-500 font-mono">TLS 1.3 • SHA-256 HMAC</div>
            </div>
        </aside>

        <!-- Sidebar Backdrop for Mobile -->
        <div id="sidebarBackdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/60 z-30 hidden lg:hidden"></div>

        <!-- Main Workspace Area -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 lg:p-8">

            <!-- Active Emergency Lockdown Banner (When Triggered) -->
            <?php if ($is_lockdown_active): ?>
            <div class="bg-red-500/15 border-2 border-red-500/50 text-red-300 p-4 rounded-xl mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
                <div class="flex items-center gap-3">
                    <span class="w-3 h-3 rounded-full bg-red-500 animate-ping"></span>
                    <div>
                        <h4 class="font-bold text-white text-sm tracking-wide">ENCLAVE EMERGENCY LOCKDOWN IS CURRENTLY ACTIVE</h4>
                        <p class="text-xs text-red-200 mt-0.5">All non-admin identities have been suspended. Ongoing workforce sessions revoked to prevent unauthorized access.</p>
                    </div>
                </div>
                <form method="POST" action="">
                    <input type="hidden" name="action" value="lift_lockdown">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <button type="submit" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-lg shadow transition flex items-center gap-1.5 whitespace-nowrap">
                        <i class="fa-solid fa-lock-open"></i> Lift Emergency Lockdown
                    </button>
                </form>
            </div>
            <?php endif; ?>

            <!-- Feedback Alert Banner -->
            <?php if (!empty($feedback_alert)): ?>
                <?php echo $feedback_alert; ?>
            <?php endif; ?>

            <!-- Header & Action Toolbar -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-8 gap-4 border-b pb-6">
                <div>
                    <div class="flex items-center space-x-2 mb-2">
                        <span class="px-2.5 py-0.5 text-[10px] font-mono font-bold uppercase rounded-md bg-sky-500/20 text-sky-300 border border-sky-500/40">
                            SURVEILLANCE NODE // ACTIVE
                        </span>
                        <span class="text-xs text-slate-500 font-mono">• Real-time Behavioral Telemetry</span>
                    </div>
                    <h2 class="text-2xl sm:text-3xl font-bold text-white tracking-tight mb-1">
                        SOC Telemetry &amp; Access Control
                    </h2>
                    <p class="text-slate-400 text-xs sm:text-sm">Continuous Zero-Trust behavioral assessment, biometric session lifecycle, and automated breach mitigation.</p>
                </div>

                <!-- Clear, Actionable Buttons -->
                <div class="flex flex-wrap items-center gap-2.5 font-sans">
                    
                    <!-- Threat Simulation Dropdown (University Defense Mode) -->
                    <div class="relative inline-block text-left" id="simulationDropdownContainer">
                        <button id="simDropdownBtn" type="button" onclick="toggleSimMenu()" class="px-3.5 py-2.5 rounded-lg text-xs font-semibold transition flex items-center shadow-sm bg-purple-950/40 hover:bg-purple-900/50 text-purple-200 border border-purple-500/40">
                            <i class="fa-solid fa-flask-vial mr-2 text-purple-400"></i>
                            <span>Simulate Threat (Defense Mode)</span>
                            <i class="fa-solid fa-chevron-down ml-2 text-[10px]"></i>
                        </button>

                        <div id="simMenu" class="hidden absolute right-0 mt-2 w-72 bg-slate-950 border border-purple-500/40 rounded-xl shadow-2xl py-2 z-40 text-xs">
                            <div class="px-4 py-2 text-[10px] font-mono text-purple-300 uppercase tracking-widest font-bold border-b border-slate-800 mb-1 flex items-center justify-between">
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
                                <button type="submit" class="w-full text-left px-4 py-2 text-slate-400 hover:text-emerald-400 hover:bg-slate-900 flex items-center transition font-mono">
                                    <i class="fa-solid fa-rotate-left mr-2 text-xs"></i> Reset Baseline Telemetry
                                </button>
                            </form>
                        </div>
                    </div>

                    <!-- ACTIVE EMERGENCY LOCKDOWN BUTTON -->
                    <?php if ($is_lockdown_active): ?>
                        <form method="POST" action="" class="inline">
                            <input type="hidden" name="action" value="lift_lockdown">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <button type="submit" class="px-3.5 py-2.5 rounded-lg text-xs font-bold transition flex items-center shadow-sm bg-emerald-600 hover:bg-emerald-500 text-white">
                                <i class="fa-solid fa-lock-open mr-1.5"></i> Lift Lockdown
                            </button>
                        </form>
                    <?php else: ?>
                        <button type="button" onclick="document.getElementById('lockdownModal').classList.remove('hidden')" class="px-3.5 py-2.5 rounded-lg text-xs font-bold transition flex items-center shadow-sm bg-red-600 hover:bg-red-700 text-white" title="Immediately isolate all non-admin workforce accounts">
                            <i class="fa-solid fa-power-off mr-1.5"></i> Emergency Lockdown
                        </button>
                    <?php endif; ?>

                    <!-- Export CSV Button -->
                    <a id="exportCsvBtn" href="?export=csv" class="px-3.5 py-2.5 rounded-lg text-xs font-semibold transition border border-slate-700 hover:border-slate-500 bg-slate-900/80 hover:bg-slate-800 text-slate-200 flex items-center shadow-sm">
                        <i class="fa-solid fa-download mr-1.5 text-sky-400"></i> Export Audit Logs
                    </a>

                    <!-- Provision User Button -->
                    <button onclick="document.getElementById('provisionModal').classList.remove('hidden')" class="px-4 py-2.5 rounded-lg text-xs font-bold transition shadow-sm bg-sky-600 hover:bg-sky-500 text-white flex items-center">
                        <i class="fa-solid fa-user-plus mr-1.5"></i> Provision Identity
                    </button>
                </div>
            </div>

            <!-- Telemetry Cards Data Grid (Clean, Focused 4 Cards) -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
                <!-- Total Identities -->
                <div class="kpi-card p-5 rounded-xl border relative overflow-hidden group bg-slate-900/60 border-slate-700/50">
                    <div class="flex justify-between items-start mb-2">
                        <span class="kpi-label text-xs font-mono uppercase tracking-wider text-slate-400 dark:text-sky-300 font-bold">TOTAL IDENTITIES</span>
                        <span class="icon-box-sky w-8 h-8 rounded-lg bg-sky-950/80 border border-sky-500/40 text-sky-400 flex items-center justify-center text-sm"><i class="fa-solid fa-users"></i></span>
                    </div>
                    <div class="flex items-baseline space-x-2">
                        <p class="kpi-number text-3xl font-extrabold text-white font-mono"><?php echo $total_users; ?></p>
                        <?php if ($suspended_count > 0): ?>
                            <span class="text-xs font-mono text-red-500 font-bold">(<?php echo $suspended_count; ?> Suspended)</span>
                        <?php else: ?>
                            <span class="text-xs font-mono text-emerald-600 dark:text-emerald-400 font-bold">(100% Active)</span>
                        <?php endif; ?>
                    </div>
                    <div class="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between border-t border-slate-800 pt-2">
                        <span>Directory Sync</span>
                        <span class="text-sky-700 dark:text-sky-400 font-mono font-bold">RBAC ONLINE</span>
                    </div>
                </div>
                
                <!-- MFA Enforcement -->
                <div class="kpi-card p-5 rounded-xl border relative overflow-hidden group bg-slate-900/60 border-slate-700/50">
                    <div class="flex justify-between items-start mb-2">
                        <span class="kpi-label text-xs font-mono uppercase tracking-wider text-slate-400 dark:text-emerald-300 font-bold">MFA ENFORCEMENT</span>
                        <span class="icon-box-emerald w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 flex items-center justify-center text-sm"><i class="fa-solid fa-shield-halved"></i></span>
                    </div>
                    <div class="flex items-baseline space-x-2">
                        <p class="kpi-number text-3xl font-extrabold text-emerald-600 dark:text-emerald-400 font-mono"><?php echo $mfa_rate; ?>%</p>
                        <span class="text-xs font-mono text-slate-500 dark:text-slate-400"><?php echo $mfa_enabled; ?>/<?php echo $total_users; ?> enrolled</span>
                    </div>
                    <div class="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between border-t border-slate-800 pt-2">
                        <span>Protocol</span>
                        <span class="text-emerald-700 dark:text-emerald-400 font-mono font-bold">RFC 6238 TOTP</span>
                    </div>
                </div>

                <!-- 24h Audit Events -->
                <div class="kpi-card p-5 rounded-xl border relative overflow-hidden group bg-slate-900/60 border-slate-700/50">
                    <div class="flex justify-between items-start mb-2">
                        <span class="kpi-label text-xs font-mono uppercase tracking-wider text-slate-400 dark:text-sky-300 font-bold">24H AUDIT EVENTS</span>
                        <span class="icon-box-blue w-8 h-8 rounded-lg bg-blue-950/80 border border-blue-500/40 text-blue-400 flex items-center justify-center text-sm"><i class="fa-solid fa-list-check"></i></span>
                    </div>
                    <div class="flex items-baseline space-x-2">
                        <p class="kpi-number text-3xl font-extrabold text-white font-mono"><?php echo $total_logs_24h; ?></p>
                        <span class="text-xs font-mono text-sky-700 dark:text-sky-400 font-bold">Live Telemetry</span>
                    </div>
                    <div class="mt-3 text-[10px] font-mono text-slate-500 flex items-center justify-between border-t border-slate-800 pt-2">
                        <span>Storage Integrity</span>
                        <span class="text-sky-700 dark:text-sky-400 font-mono font-bold">IMMUTABLE LOGS</span>
                    </div>
                </div>

                <!-- AI Threat Posture -->
                <div class="kpi-card p-5 rounded-xl border relative overflow-hidden bg-slate-900/60 border-slate-700/50">
                    <div class="flex justify-between items-center mb-2">
                        <span class="kpi-label text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">AI THREAT POSTURE</span>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded <?php echo $active_theme['bg']; ?> <?php echo $active_theme['text']; ?> font-bold border <?php echo $active_theme['border']; ?>">
                            ATS: <?php echo $threat_score; ?>/100
                        </span>
                    </div>
                    <div class="flex items-center space-x-2.5">
                        <span class="w-2.5 h-2.5 rounded-full <?php echo $active_theme['ping']; ?>"></span>
                        <p class="text-base sm:text-lg font-bold <?php echo $active_theme['text']; ?> tracking-tight font-sans"><?php echo $threat_level; ?></p>
                    </div>
                    <!-- Risk Meter Bar -->
                    <div class="w-full bg-slate-950 rounded-full h-2 mt-3 overflow-hidden border border-slate-800">
                        <div class="bg-gradient-to-r <?php echo $active_theme['bar']; ?> h-2 rounded-full transition-all duration-500" style="width: <?php echo max(5, $threat_score); ?>%"></div>
                    </div>
                </div>
            </div>

            <!-- ================================================================= -->
            <!-- MAIN 2-COLUMN SECTION: DIRECTORY & THREAT TELEMETRY               -->
            <!-- ================================================================= -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                <!-- Left Column (2/3 width): Workforce User Directory & RBAC -->
                <div class="lg:col-span-2 space-y-8" id="directorySection">
                    
                    <div class="table-container rounded-xl border overflow-hidden shadow-sm bg-slate-900/60 border-slate-700/50">
                        <div class="table-header-bar border-b p-5 flex justify-between items-center bg-slate-950/60">
                            <div>
                                <h3 class="text-sm sm:text-base font-bold text-white flex items-center">
                                    <i class="fa-solid fa-users-gear text-sky-400 mr-2.5"></i> Identity &amp; Role-Based Access Control (RBAC)
                                </h3>
                                <p class="text-xs text-slate-400 mt-0.5">Enforce Zero-Trust least privilege and trigger instant identity kill-switch locks.</p>
                            </div>
                            <span class="table-counter-badge text-xs font-mono text-sky-300 bg-sky-950/60 px-3 py-1 rounded-lg border border-sky-500/30 font-bold">
                                <?php echo count($users); ?> IDENTITIES REGISTERED
                            </span>
                        </div>

                        <div class="overflow-x-auto custom-scrollbar">
                            <table class="w-full text-left text-sm">
                                <thead class="text-slate-400 text-xs uppercase tracking-wider font-semibold">
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
                                <tbody class="divide-y divide-slate-700/40">
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

                                        <!-- Account Email & Dept/Title -->
                                        <td class="px-5 py-4">
                                            <div class="flex items-center">
                                                <div class="h-9 w-9 rounded-lg <?php echo $is_active ? 'bg-slate-700 text-slate-300' : 'bg-red-950/50 text-red-400 border border-red-500/30'; ?> flex items-center justify-center mr-3 font-semibold text-xs border border-slate-600 shrink-0">
                                                    <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                                                </div>
                                                <div>
                                                    <div class="text-white font-medium text-xs sm:text-sm flex items-center">
                                                        <?php echo $user_email; ?>
                                                        <?php if ($is_self): ?>
                                                            <span class="ml-2 text-[10px] font-mono bg-sky-500/20 text-sky-400 border border-sky-500/30 px-1.5 py-0.2 rounded font-semibold">YOU</span>
                                                        <?php endif; ?>
                                                    </div>
                                                    <div class="text-[11px] text-slate-400 font-mono mt-0.5">
                                                        <span><?php echo htmlspecialchars(trim(($u['first_name'] ?? '') . ' ' . ($u['last_name'] ?? ''))); ?></span>
                                                        <span class="text-slate-600">•</span>
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

                                        <!-- Security Clearance -->
                                        <td class="px-5 py-4">
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-bold border <?php echo $clearance_badge; ?>">
                                                <i class="fa-solid <?php echo $clearance_icon; ?> mr-1 text-[10px]"></i> <?php echo htmlspecialchars($user_clearance_val); ?>
                                            </span>
                                        </td>

                                        <!-- MFA Status -->
                                        <td class="px-5 py-4">
                                            <?php if (!empty($u['mfa_secret'])): ?>
                                                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                    <i class="fa-solid fa-shield-halved mr-1.5"></i> ENFORCED
                                                </span>
                                            <?php else: ?>
                                                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                                    <i class="fa-solid fa-triangle-exclamation mr-1.5"></i> UNPROTECTED
                                                </span>
                                            <?php endif; ?>
                                        </td>

                                        <!-- Status -->
                                        <td class="px-5 py-4">
                                            <?php if ($is_active): ?>
                                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                    <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                                </span>
                                            <?php else: ?>
                                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
                                                    <span class="h-1.5 w-1.5 rounded-full bg-red-400 mr-1.5"></span> SUSPENDED
                                                </span>
                                            <?php endif; ?>
                                        </td>

                                        <!-- Action Buttons -->
                                        <td class="px-5 py-4 text-right whitespace-nowrap">
                                            <div class="inline-flex items-center space-x-1">
                                                <?php if ($is_self): ?>
                                                    <span class="p-2 text-slate-600 cursor-not-allowed text-xs" title="Self-suspension locked by security policy">
                                                        <i class="fa-solid fa-lock"></i>
                                                    </span>
                                                <?php else: ?>
                                                    <!-- Toggle Suspend / Reactivate Form Button -->
                                                    <form method="POST" action="" class="inline" onsubmit="return confirm('<?php echo $is_active ? 'Are you sure you want to SUSPEND UID-' . $uid . ' (' . $user_email . ')?' : 'Reactivate account UID-' . $uid . ' (' . $user_email . ')?'; ?>');">
                                                        <input type="hidden" name="action" value="toggle_status">
                                                        <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                        <input type="hidden" name="new_status" value="<?php echo $is_active ? 0 : 1; ?>">
                                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                        
                                                        <?php if ($is_active): ?>
                                                            <button type="submit" class="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition" title="Suspend Identity">
                                                                <i class="fa-solid fa-user-slash"></i>
                                                            </button>
                                                        <?php else: ?>
                                                            <button type="submit" class="p-2 text-red-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded-lg transition" title="Reactivate Identity">
                                                                <i class="fa-solid fa-user-check"></i>
                                                            </button>
                                                        <?php endif; ?>
                                                    </form>
                                                <?php endif; ?>

                                                <!-- Edit Role & Clearance Modal Trigger -->
                                                <button onclick="openRoleModal(<?php echo $uid; ?>, '<?php echo addslashes($user_email); ?>', <?php echo $user_role_id; ?>, '<?php echo addslashes($user_functional_role); ?>', '<?php echo addslashes($user_clearance_val); ?>')" class="p-2 text-slate-400 hover:text-sky-400 hover:bg-sky-500/10 rounded-lg transition" title="Modify RBAC Role &amp; Clearance">
                                                    <i class="fa-solid fa-user-gear"></i>
                                                </button>

                                                <?php if (!$is_self): ?>
                                                    <!-- Purge Identity Form (CRUD Delete) -->
                                                    <form method="POST" action="" class="inline" onsubmit="return confirm('PERMANENT ACTION: Purge UID-<?php echo $uid; ?> (<?php echo $user_email; ?>) permanently from database?');">
                                                        <input type="hidden" name="action" value="delete_user">
                                                        <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                        <button type="submit" class="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition" title="Purge Identity">
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

                    <!-- AI Sentinel Flagged Threat Incidents (Only Displayed When Anomalies Exist) -->
                    <?php if (!empty($anomalies)): ?>
                    <div class="bg-red-950/20 rounded-xl border border-red-500/40 p-5 shadow-sm">
                        <div class="flex items-center justify-between mb-4">
                            <div class="flex items-center space-x-2 text-red-400">
                                <i class="fa-solid fa-shield-virus text-xl"></i>
                                <h3 class="font-bold text-sm tracking-wide uppercase">AI Sentinel Flagged Threat Incident(s)</h3>
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
                                        <span class="text-slate-500 text-xs">•</span>
                                        <span class="text-xs font-mono text-slate-400">Confidence: <?php echo $anom['confidence']; ?>%</span>
                                    </div>
                                    <p class="text-xs text-slate-300"><?php echo htmlspecialchars($anom['description']); ?></p>
                                    <div class="text-[11px] font-mono text-slate-400 flex items-center space-x-3 pt-1">
                                        <span><i class="fa-solid fa-user-secret mr-1 text-slate-500"></i> Target: <span class="text-sky-400"><?php echo htmlspecialchars($anom['target_user']); ?></span></span>
                                        <span><i class="fa-solid fa-network-wired mr-1 text-slate-500"></i> Source: <span class="text-amber-400"><?php echo htmlspecialchars($anom['ip_address']); ?></span></span>
                                    </div>
                                </div>
                                
                                <?php if (!empty($anom['target_uid']) && (int) $anom['target_uid'] !== $current_user_id): ?>
                                <div class="shrink-0">
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

                <!-- Right Column (1/3 width): Terminal Console & Audit Stream -->
                <div class="space-y-8" id="sentinelTelemetry">
                    
                    <!-- AI Sentinel Engine Heuristic Terminal -->
                    <div class="rounded-xl border shadow-sm overflow-hidden bg-slate-900/60 border-slate-700/50">
                        <div id="sentinelTerminalHeader" class="border-b px-4 py-3 flex justify-between items-center bg-slate-950/80">
                            <div class="flex items-center space-x-2">
                                <div class="flex space-x-1.5 mr-2">
                                    <div class="w-2.5 h-2.5 rounded-full bg-red-500/90"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-amber-500/90"></div>
                                    <div class="w-2.5 h-2.5 rounded-full bg-emerald-500/90"></div>
                                </div>
                                <h3 class="text-xs font-mono font-bold text-white flex items-center">
                                    <i class="fa-solid fa-microchip text-sky-400 mr-2"></i> AI Sentinel Heuristic Engine
                                </h3>
                            </div>
                            <span class="text-[10px] <?php echo $active_theme['text']; ?> font-mono tracking-wider border <?php echo $active_theme['border']; ?> px-2 py-0.5 rounded <?php echo $active_theme['bg']; ?> font-bold">
                                <?php echo $threat_level; ?>
                            </span>
                        </div>

                        <!-- Terminal Output Window -->
                        <div id="sentinelTerminalConsole" class="terminal-window p-4 font-mono text-xs text-slate-400 space-y-2 h-72 overflow-y-auto custom-scrollbar bg-slate-950">
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
                            <div class="flex items-start space-x-2 leading-relaxed">
                                <span class="text-slate-600 select-none">[<?php echo $tlog['time']; ?>]</span>
                                <span class="<?php echo $badge_color; ?> select-none">[<?php echo $tlog['badge']; ?>]</span>
                                <span class="<?php echo ($tlog['type'] === 'CRITICAL') ? 'text-red-300 font-medium' : 'text-slate-300'; ?>">
                                    <?php echo htmlspecialchars($tlog['msg']); ?>
                                </span>
                            </div>
                            <?php endforeach; ?>
                            
                            <div class="pt-2 flex items-center space-x-2 text-slate-500">
                                <span class="text-sky-400 font-bold">&gt;</span>
                                <span class="text-[11px] text-sky-300/70 font-mono">Sentinel heuristic engine scanning audit streams in real-time...</span>
                            </div>
                        </div>
                    </div>

                    <!-- Live Audit Stream -->
                    <div class="audit-stream-card rounded-xl border shadow-sm overflow-hidden bg-slate-900/60 border-slate-700/50">
                        <div class="audit-stream-header border-b p-4 bg-slate-950/80 flex justify-between items-center">
                            <h3 class="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center">
                                <i class="fa-solid fa-server text-sky-400 mr-2"></i> Live Audit Stream
                            </h3>
                            <span class="text-[10px] font-mono text-emerald-400 flex items-center font-bold">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 mr-1.5"></span> LIVE INGEST
                            </span>
                        </div>
                        <div class="bg-slate-950/40">
                            <ul class="audit-stream-list divide-y divide-slate-800/60 max-h-80 overflow-y-auto custom-scrollbar font-mono text-xs">
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
                                            'LOGOUT' => ['icon' => 'fa-arrow-right-from-bracket', 'color' => 'text-slate-400'],
                                            'SUSPENDED_LOGIN_ATTEMPT' => ['icon' => 'fa-ban', 'color' => 'text-red-500'],
                                            'EMERGENCY_LOCKDOWN_TRIGGERED' => ['icon' => 'fa-power-off', 'color' => 'text-red-400'],
                                            'EMERGENCY_LOCKDOWN_LIFTED' => ['icon' => 'fa-lock-open', 'color' => 'text-emerald-400'],
                                            'BASELINE_RESET' => ['icon' => 'fa-rotate-left', 'color' => 'text-emerald-400'],
                                            default => ['icon' => 'fa-shield', 'color' => 'text-slate-400']
                                        };
                                    ?>
                                    <li class="p-3.5 hover:bg-slate-900/60 transition group">
                                        <div class="flex space-x-3">
                                            <div class="shrink-0 mt-0.5">
                                                <i class="fa-solid <?php echo $icon_data['icon']; ?> <?php echo $icon_data['color']; ?> text-xs"></i>
                                            </div>
                                            <div class="min-w-0 flex-1">
                                                <p class="text-xs text-slate-300 font-medium break-words leading-snug"><?php echo htmlspecialchars($action_text); ?></p>
                                                <div class="flex items-center text-[10px] text-slate-500 mt-1 flex-wrap gap-x-2">
                                                    <span>IP: <code class="text-sky-400"><?php echo htmlspecialchars($ip); ?></code></span>
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
                                    <li class="p-8 text-center text-xs text-slate-500 font-mono">
                                        Audit stream is currently empty.
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    </div>

                </div>
            </div>

            <!-- Academic & Enterprise Portal Footer -->
            <div class="mt-12 text-center border-t pt-6 text-xs text-slate-500 font-mono">
                <i class="fa-solid fa-shield-halved text-sky-500/70 mr-1"></i>
                ENTERPRISE ZERO-TRUST IAM PORTAL • AIR-GAPPED SECURE ENCLAVE • iam.secure-defense.internal
            </div>

        </main>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 1: PROVISION IDENTITY                                               -->
    <!-- ========================================================================= -->
    <div id="provisionModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="p-6 rounded-xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto custom-scrollbar bg-slate-900 border border-slate-700">
            <div class="flex justify-between items-center mb-5 border-b border-slate-700/60 pb-3">
                <div class="flex items-center space-x-2 text-white">
                    <div class="h-8 w-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
                        <i class="fa-solid fa-user-plus text-sm"></i>
                    </div>
                    <h2 class="text-base font-bold">Provision Enterprise Identity</h2>
                </div>
                <button onclick="document.getElementById('provisionModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>
            
            <?php if (isset($provision_msg)) echo $provision_msg; ?>

            <form method="POST" action="">
                <input type="hidden" name="action" value="provision_user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="grid grid-cols-2 gap-3 mb-3.5">
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">First Name</label>
                        <input type="text" name="first_name" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g. Jane">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Last Name</label>
                        <input type="text" name="last_name" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g. Doe">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3.5">
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Enterprise Email <span class="text-red-400">*</span></label>
                        <input type="email" name="new_email" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="user@organization.com" required>
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Temporary Password <span class="text-red-400">*</span></label>
                        <input type="password" name="new_password" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="••••••••••••" required>
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3.5">
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Department</label>
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
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Job Title</label>
                        <input type="text" name="job_title" class="cyber-input w-full px-3 py-2 rounded-lg text-xs" placeholder="e.g. SOC Security Analyst" value="Staff Analyst">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-5">
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Functional Role (RBAC)</label>
                        <select name="role" id="provRoleSelect" onchange="syncProvisioningDefaults()" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Staff" selected>Staff (Standard Employee)</option>
                            <option value="Auditor">Auditor (Compliance Officer)</option>
                            <option value="Admin">Admin (SOC Administrator)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Security Clearance</label>
                        <select name="security_clearance" id="provClearanceSelect" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Tier 1" selected>Tier 1 // Restricted</option>
                            <option value="Tier 2">Tier 2 // Confidential</option>
                            <option value="Tier 3">Tier 3 // Top Secret</option>
                        </select>
                    </div>
                </div>

                <input type="hidden" name="role_id" id="provRoleIdHidden" value="4">

                <div class="flex space-x-3 pt-3 border-t border-slate-700/60">
                    <button type="button" onclick="document.getElementById('provisionModal').classList.add('hidden')" class="w-1/2 py-2.5 rounded-lg text-xs font-semibold border border-slate-700 hover:bg-slate-800 text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2.5 rounded-lg text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white transition shadow-sm">
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
        <div class="p-6 rounded-xl shadow-2xl w-full max-w-md bg-slate-900 border border-slate-700">
            <div class="flex justify-between items-center mb-5 border-b border-slate-700/60 pb-3">
                <div class="flex items-center space-x-2 text-white">
                    <div class="h-8 w-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
                        <i class="fa-solid fa-user-gear text-sm"></i>
                    </div>
                    <h2 class="text-base font-bold">Modify RBAC Permissions</h2>
                </div>
                <button onclick="document.getElementById('roleModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-lg"></i>
                </button>
            </div>

            <form method="POST" action="">
                <input type="hidden" name="action" value="update_role">
                <input type="hidden" name="target_user_id" id="roleModalUserId">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="mb-4">
                    <label class="block text-xs text-slate-400 mb-1 font-mono">Target Account</label>
                    <div id="roleModalEmail" class="text-xs font-bold text-sky-400 bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 font-mono"></div>
                </div>

                <div class="grid grid-cols-2 gap-3 mb-4">
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Functional Role</label>
                        <select name="new_functional_role" id="roleModalFuncRole" onchange="syncRoleModalDefaults()" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Staff">Staff</option>
                            <option value="Auditor">Auditor</option>
                            <option value="Admin">Admin</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Clearance Tier</label>
                        <select name="new_clearance" id="roleModalClearance" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                            <option value="Tier 1">Tier 1 (Restricted)</option>
                            <option value="Tier 2">Tier 2 (Confidential)</option>
                            <option value="Tier 3">Tier 3 (Top Secret)</option>
                        </select>
                    </div>
                </div>

                <div class="mb-5">
                    <label class="block text-xs text-slate-400 uppercase font-mono mb-1">Database Role Group</label>
                    <select name="new_role_id" id="roleModalSelect" class="cyber-input w-full px-3 py-2 rounded-lg text-xs">
                        <?php foreach ($roles as $r): ?>
                            <option value="<?php echo (int) $r['role_id']; ?>">
                                <?php echo htmlspecialchars($r['role_name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="flex space-x-3 pt-3 border-t border-slate-700/60">
                    <button type="button" onclick="document.getElementById('roleModal').classList.add('hidden')" class="w-1/2 py-2.5 rounded-lg text-xs font-semibold border border-slate-700 hover:bg-slate-800 text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2.5 rounded-lg text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white transition shadow-sm">
                        Apply Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 3: EMERGENCY LOCKDOWN CONFIRMATION MODAL                            -->
    <!-- ========================================================================= -->
    <div id="lockdownModal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="p-6 rounded-xl shadow-2xl w-full max-w-md bg-slate-900 border-2 border-red-500/50">
            <div class="flex items-center space-x-3 text-red-400 mb-4 pb-3 border-b border-red-500/30">
                <div class="w-10 h-10 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 text-lg">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                </div>
                <div>
                    <h3 class="text-base font-bold text-white">CONFIRM EMERGENCY LOCKDOWN</h3>
                    <p class="text-xs text-red-300 font-mono">SOC Kill-Switch Procedure</p>
                </div>
            </div>

            <div class="text-xs text-slate-300 space-y-2 mb-6">
                <p>Executing an <strong>Emergency Enclave Lockdown</strong> will instantly:</p>
                <ul class="list-disc list-inside space-y-1 text-slate-400 pl-2 font-mono text-[11px]">
                    <li>Suspend all non-admin workforce accounts</li>
                    <li>Immediately revoke active authentication sessions</li>
                    <li>Lock down internal directories and API bearer endpoints</li>
                    <li>Record an immutable forensic audit log with your Administrator UID</li>
                </ul>
                <p class="text-[11px] text-amber-300 pt-1">You (as Administrator) will retain session access and can lift the lockdown at any time.</p>
            </div>

            <form method="POST" action="" class="flex space-x-3">
                <input type="hidden" name="action" value="emergency_lockdown">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <button type="button" onclick="document.getElementById('lockdownModal').classList.add('hidden')" class="w-1/2 py-2.5 rounded-lg text-xs font-semibold border border-slate-700 hover:bg-slate-800 text-slate-300 transition">
                    Cancel
                </button>
                <button type="submit" class="w-1/2 py-2.5 rounded-lg text-xs font-bold bg-red-600 hover:bg-red-700 text-white transition shadow flex items-center justify-center gap-1.5">
                    <i class="fa-solid fa-power-off"></i> Engage Lockdown
                </button>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 4: BIOMETRIC WELCOME HUD (Cleaned Up & Professional)                 -->
    <!-- ========================================================================= -->
    <div id="cyberWelcomeHUD" class="<?php echo $show_welcome_hud ? '' : 'hidden'; ?> fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-xs flex items-center justify-center p-4">
        <div class="relative w-full max-w-2xl bg-slate-900 border border-sky-500/40 rounded-xl p-6 sm:p-8 overflow-hidden text-slate-200 shadow-2xl">
            
            <div class="flex justify-between items-center border-b border-slate-700/60 pb-3 mb-6">
                <div class="flex items-center space-x-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-sky-400"></span>
                    <span class="font-mono text-xs text-sky-400 uppercase tracking-widest font-bold">
                        // ZERO-TRUST IDENTITY ENCLAVE ACCESSED
                    </span>
                </div>
                <div class="flex items-center space-x-3 text-xs font-mono">
                    <span class="text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                        <i class="fa-solid fa-lock mr-1 text-[10px]"></i> TLS 1.3 SECURED
                    </span>
                </div>
            </div>

            <div class="flex flex-col sm:flex-row items-center gap-6 mb-6">
                <div class="w-20 h-20 rounded-full bg-sky-950/40 border border-sky-500/40 flex items-center justify-center shrink-0">
                    <i class="fa-solid fa-fingerprint text-3xl text-sky-400"></i>
                </div>

                <div class="text-center sm:text-left flex-1 space-y-1">
                    <p class="text-xs font-mono text-slate-400 uppercase tracking-wider">
                        IDENTITY CONFIRMED • ACCESS GRANTED
                    </p>
                    <h2 class="text-2xl font-bold text-white tracking-tight">
                        Welcome, <span class="text-sky-400"><?php echo htmlspecialchars($user_display_name); ?></span>
                    </h2>
                    <div class="flex flex-wrap items-center justify-center sm:justify-start gap-2 pt-1 font-mono text-xs">
                        <span class="bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded">
                            UID-<?php echo str_pad($current_user_id, 4, '0', STR_PAD_LEFT); ?>
                        </span>
                        <span class="text-slate-500">•</span>
                        <span class="text-sky-400"><?php echo htmlspecialchars($current_user['email']); ?></span>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs mb-6">
                <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">Clearance</p>
                    <p class="text-purple-400 font-bold truncate mt-0.5"><?php echo $current_role_info['name']; ?></p>
                </div>
                <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">Encryption</p>
                    <p class="text-emerald-400 font-bold truncate mt-0.5">TLS 1.3 / AES-256</p>
                </div>
                <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">MFA Protocol</p>
                    <p class="text-sky-400 font-bold truncate mt-0.5">RFC 6238 PASSED</p>
                </div>
                <div class="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <p class="text-slate-500 text-[10px] uppercase">Ingress</p>
                    <p class="text-slate-300 font-bold truncate mt-0.5"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'); ?></p>
                </div>
            </div>

            <div class="space-y-3">
                <div class="flex items-center justify-between">
                    <span class="text-[11px] font-mono text-slate-500" id="hudTimerText">Entering command center in 4s...</span>
                    <button onclick="dismissCyberWelcomeHUD()" class="bg-sky-600 hover:bg-sky-500 text-white font-medium px-4 py-1.5 rounded-lg text-xs font-mono uppercase tracking-wider transition flex items-center gap-1.5">
                        <span>Access Command Center</span>
                        <i class="fa-solid fa-arrow-right text-[10px]"></i>
                    </button>
                </div>
                <div class="w-full bg-slate-950 rounded-full h-1 overflow-hidden border border-slate-800">
                    <div id="hudProgressBar" class="bg-sky-400 h-1 transition-all duration-100 ease-linear" style="width: 100%;"></div>
                </div>
            </div>

        </div>
    </div>

    <!-- JavaScript Handlers -->
    <script>
        // Sidebar Toggle for Mobile View
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

        // Threat Simulation Dropdown Toggle
        function toggleSimMenu() {
            const menu = document.getElementById('simMenu');
            if (menu) menu.classList.toggle('hidden');
        }

        window.addEventListener('click', function(e) {
            const container = document.getElementById('simulationDropdownContainer');
            if (container && !container.contains(e.target)) {
                const menu = document.getElementById('simMenu');
                if (menu) menu.classList.add('hidden');
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

        // RBAC Sync Handlers
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

        // Welcome HUD Dismissal
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

            const totalDuration = 4000;
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
