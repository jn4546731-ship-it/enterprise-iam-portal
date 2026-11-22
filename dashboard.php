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
    // Current user was deactivated by an administrator or policy
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
// 2. HANDLE RBAC: TOGGLE SUSPEND / ACTIVATE USER
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_status') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2'></i> CSRF validation failed. Action aborted.</div>";
    } else {
        $target_user_id = (int) ($_POST['target_user_id'] ?? 0);
        $new_status = (int) ($_POST['new_status'] ?? 0); // 0 = suspend, 1 = activate
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Security Policy: Prevent self-suspension
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
// 3. HANDLE RBAC: UPDATE ROLE & CLEARANCE ASSIGNMENT
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
// 3B. HANDLE RBAC: PERMANENTLY PURGE IDENTITY (CRUD: Delete)
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
// 4. HANDLE NEW USER PROVISIONING
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
// 5. LIVE DEFENSE SIMULATION TRIGGERS
// -------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'simulate_threat') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $scenario = $_POST['scenario'] ?? 'brute_force';
        AISentinel::injectSimulationThreat($conn, $scenario);
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center'><i class='fa-solid fa-triangle-exclamation mr-2 animate-bounce'></i> <strong>Defense Simulation Injected:</strong> Synthetic threat traffic generated ({$scenario}). Observe AI Sentinel response below!</div>";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reset_simulation') {
    if (isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        AISentinel::resetSimulationTelemetry($conn);
        $feedback_alert = "<div class='p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center'><i class='fa-solid fa-rotate-left mr-2'></i> Simulation telemetry cleared. Threat baseline restored to normal.</div>";
    }
}

// -------------------------------------------------------------
// 6. FETCH SYSTEM METRICS & DIRECTORY DATA
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
// 7. RUN AI SENTINEL BEHAVIORAL THREAT SCAN
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
    <meta name="color-scheme" content="dark">
    <title>Aegis IAM — Enterprise Security Command Center</title>

    <!-- Offline Air-Gapped Local Tailwind Engine -->
    <script src="assets/js/tailwind.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        surface: {
                            DEFAULT: '#0f131c',
                            dim: '#0f131c',
                            bright: '#353942',
                            lowest: '#0a0e16',
                            low: '#181c24',
                            container: '#1c2029',
                            high: '#262a34',
                            highest: '#31353f',
                        },
                        primary: {
                            DEFAULT: '#38bdf8',
                            dim: '#0284c7',
                            container: '#004d69',
                            onContainer: '#bfe8ff'
                        },
                        secondary: {
                            DEFAULT: '#00f0ff',
                            container: '#1b2633',
                        },
                        status: {
                            success: '#10b981',
                            warning: '#f59e0b',
                            critical: '#ef4444',
                            info: '#38bdf8',
                        }
                    },
                    fontFamily: {
                        sans: ['Geist', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
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

    <style>
        body {
            font-family: 'Geist', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: #0a0e16;
            color: #e0e2ed;
        }
        .custom-scrollbar::-webkit-scrollbar {
            width: 4px;
            height: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: #0f131c;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: #262a34;
            border-radius: 4px;
        }
        .glow-cyan {
            box-shadow: 0 0 16px -2px rgba(56, 189, 248, 0.25);
        }
        .glow-red {
            box-shadow: 0 0 16px -2px rgba(239, 68, 68, 0.35);
        }
    </style>
</head>
<body class="min-h-screen bg-[#0a0e16] text-[#e0e2ed] flex flex-col antialiased selection:bg-sky-500/30">

    <!-- ========================================================================= -->
    <!-- TOP NAVIGATION HEADER (Google Stitch Okta-Grade Identity Bar)             -->
    <!-- ========================================================================= -->
    <header class="h-14 border-b border-white/[0.08] bg-[#0f131c] px-4 flex items-center justify-between sticky top-0 z-40">
        <div class="flex items-center gap-4 lg:gap-6">
            <!-- Mobile Sidebar Toggle -->
            <button onclick="toggleSidebar()" class="md:hidden p-1.5 text-slate-400 hover:text-white rounded hover:bg-white/[0.06] transition" aria-label="Toggle Navigation">
                <i class="fa-solid fa-bars text-sm"></i>
            </button>

            <!-- Brand Logo -->
            <div class="flex items-center gap-2.5">
                <div class="w-8 h-8 rounded bg-sky-500/10 border border-sky-400/30 flex items-center justify-center text-sky-400">
                    <i class="fa-solid fa-shield-halved text-sm"></i>
                </div>
                <div class="flex items-center gap-2">
                    <span class="font-bold tracking-tight text-white text-base">Aegis IAM</span>
                    <span class="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold">Zero-Trust</span>
                </div>
            </div>

            <!-- Environment Selector Badge -->
            <div class="hidden md:flex items-center gap-2 px-3 py-1 rounded bg-[#181c24] border border-white/[0.08] text-xs text-slate-300">
                <i class="fa-solid fa-cloud text-xs text-sky-400"></i>
                <span>Enterprise Production</span>
                <span class="text-slate-600">•</span>
                <span class="text-slate-400">US-East-1</span>
                <span class="text-[10px] text-emerald-400 font-mono px-1 py-0.2 bg-emerald-500/10 rounded border border-emerald-500/20">FedRAMP High</span>
                <i class="fa-solid fa-chevron-down text-[10px] text-slate-500 ml-1"></i>
            </div>
        </div>

        <!-- Search / Command Palette -->
        <div class="flex-1 max-w-md mx-6 hidden lg:block">
            <div class="relative flex items-center">
                <i class="fa-solid fa-magnifying-glass text-xs text-slate-500 absolute left-3"></i>
                <input 
                    type="text" 
                    placeholder="Search identities, conditional policies, audit logs, CVE signals..." 
                    class="w-full bg-[#181c24] border border-white/[0.08] rounded pl-9 pr-12 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500/50 transition-colors"
                />
                <kbd class="absolute right-2.5 text-[10px] font-mono bg-[#262a34] text-slate-400 px-1.5 py-0.5 rounded border border-white/[0.06]">⌘K</kbd>
            </div>
        </div>

        <!-- Header Actions & Profile -->
        <div class="flex items-center gap-3 lg:gap-4">
            <!-- Dynamic SLA & Sentinel Status Badge -->
            <div class="hidden sm:flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full <?php echo $active_theme['bg']; ?> border <?php echo $active_theme['border']; ?> <?php echo $active_theme['text']; ?> font-mono">
                <span class="w-1.5 h-1.5 rounded-full <?php echo $active_theme['ping']; ?> animate-pulse"></span>
                <span>Systems Normal • 99.999% SLA</span>
            </div>

            <!-- Quick Action Icons -->
            <div class="flex items-center gap-1.5 text-slate-400 border-l border-white/[0.08] pl-3">
                <button onclick="toggleGlobalAudio()" id="navMuteBtn" class="p-1.5 hover:text-white rounded hover:bg-white/[0.04] transition" title="Toggle Audio Telemetry">
                    <i id="navMuteIcon" class="fa-solid fa-volume-high text-xs text-sky-400"></i>
                </button>
                <button onclick="document.getElementById('simMenu').classList.toggle('hidden')" class="p-1.5 hover:text-white rounded hover:bg-white/[0.04] transition relative" title="Defense Simulations">
                    <i class="fa-solid fa-flask-vial text-xs text-purple-400"></i>
                </button>
                <button class="p-1.5 hover:text-white rounded hover:bg-white/[0.04] transition relative" title="Alerts & Telemetry">
                    <i class="fa-solid fa-bell text-xs"></i>
                    <?php if (!empty($anomalies)): ?>
                        <span class="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500"></span>
                    <?php endif; ?>
                </button>
            </div>

            <!-- Identity Attestation Profile -->
            <div class="flex items-center gap-2.5 pl-2">
                <div class="relative">
                    <div class="w-7 h-7 rounded-full bg-gradient-to-br from-sky-500 to-indigo-600 text-white flex items-center justify-center font-bold text-xs ring-1 ring-sky-500/40">
                        <?php echo strtoupper(substr($current_user['email'] ?? 'A', 0, 1)); ?>
                    </div>
                    <span class="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-[#0f131c]"></span>
                </div>
                <div class="hidden xl:block text-left">
                    <div class="text-xs font-medium text-slate-200 leading-tight"><?php echo htmlspecialchars($user_display_name); ?></div>
                    <div class="text-[10px] text-sky-400 font-mono flex items-center gap-1">
                        <i class="fa-solid fa-key text-[9px]"></i>
                        <span><?php echo htmlspecialchars($current_job_title); ?> • FIDO2 Attested</span>
                    </div>
                </div>
            </div>

            <!-- Sign Out Button -->
            <a href="logout.php" class="px-2.5 py-1 rounded bg-[#181c24] hover:bg-red-500/10 border border-white/[0.08] hover:border-red-500/30 text-slate-400 hover:text-red-400 text-xs font-medium transition flex items-center gap-1.5" title="Sign out of enterprise session">
                <i class="fa-solid fa-arrow-right-from-bracket text-xs"></i>
                <span class="hidden sm:inline">Sign out</span>
            </a>
        </div>
    </header>

    <!-- ========================================================================= -->
    <!-- MAIN WORKSPACE: SIDEBAR + DASHBOARD CONTENT                               -->
    <!-- ========================================================================= -->
    <div class="flex-1 flex overflow-hidden">
        
        <!-- LEFT PERSISTENT SIDEBAR NAVIGATION (Google Stitch Okta-Grade) -->
        <aside id="appSidebar" class="w-64 border-r border-white/[0.08] bg-[#0f131c] flex flex-col justify-between hidden md:flex shrink-0 transition-all duration-300">
            <div class="p-3 space-y-6 overflow-y-auto custom-scrollbar">
                
                <!-- Engine Telemetry Status -->
                <div class="p-2.5 rounded bg-[#181c24] border border-white/[0.06] flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                        <span class="text-[11px] font-mono text-slate-300 font-medium">CAE Active Engine</span>
                    </div>
                    <span class="text-[10px] font-mono text-emerald-400 uppercase bg-emerald-500/10 px-1 rounded">SYNCED</span>
                </div>

                <!-- Section 1: Overview -->
                <div>
                    <div class="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 font-semibold">Overview</div>
                    <nav class="space-y-0.5">
                        <a href="dashboard.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium bg-sky-500/10 text-sky-400 border border-sky-500/20">
                            <i class="fa-solid fa-shield-halved text-xs text-sky-400"></i>
                            <span>Security Center</span>
                        </a>
                        <a href="#telemetrySection" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-chart-line text-xs"></i>
                            <span>Identity Posture Intel</span>
                        </a>
                    </nav>
                </div>

                <!-- Section 2: Identity & Directory -->
                <div>
                    <div class="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 font-semibold">Identity & Directory</div>
                    <nav class="space-y-0.5">
                        <a href="#usersDirectory" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-users text-xs"></i>
                            <span>Users & Directory</span>
                        </a>
                        <a href="#usersDirectory" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-user-check text-xs"></i>
                            <span>Groups & Dynamic Teams</span>
                        </a>
                        <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-robot text-xs"></i>
                            <span>Non-Human & Service Bots</span>
                        </a>
                    </nav>
                </div>

                <!-- Section 3: Authentication & MFA -->
                <div>
                    <div class="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 font-semibold">Authentication & MFA</div>
                    <nav class="space-y-0.5">
                        <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-fingerprint text-xs text-sky-400"></i>
                            <span>FIDO2 / FastPass Gateway</span>
                        </a>
                        <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-sliders text-xs"></i>
                            <span>Adaptive MFA Policies</span>
                        </a>
                        <a href="setup_mfa.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-hard-drive text-xs"></i>
                            <span>Authenticator Hardware</span>
                        </a>
                    </nav>
                </div>

                <!-- Section 4: Threat Protection -->
                <div>
                    <div class="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 font-semibold flex items-center justify-between">
                        <span>Threat Protection</span>
                        <?php if (!empty($anomalies)): ?>
                            <span class="px-1.5 py-0.2 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[9px] font-mono font-bold"><?php echo count($anomalies); ?> Alert(s)</span>
                        <?php else: ?>
                            <span class="px-1.5 py-0.2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded text-[9px] font-mono">0 Alerts</span>
                        <?php endif; ?>
                    </div>
                    <nav class="space-y-0.5">
                        <a href="#threatFeed" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-bolt text-xs text-red-400"></i>
                            <span>Identity Threat Protection</span>
                        </a>
                        <a href="#threatFeed" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-globe text-xs"></i>
                            <span>Impossible Velocity Signals</span>
                        </a>
                        <a href="#sentinelTerminal" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-arrows-rotate text-xs"></i>
                            <span>Continuous Access (CAE)</span>
                        </a>
                    </nav>
                </div>

                <!-- Section 5: Access Governance -->
                <div>
                    <div class="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 font-semibold">Access Governance</div>
                    <nav class="space-y-0.5">
                        <a href="vault.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-white hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-lock text-xs text-purple-400"></i>
                            <span>Privileged Access (PIM)</span>
                            <span class="ml-auto text-[9px] font-mono px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30">RBAC</span>
                        </a>
                        <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-white hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-key text-xs text-sky-400"></i>
                            <span>API Credentials & Tokens</span>
                        </a>
                    </nav>
                </div>

                <!-- Section 6: Security & Audit -->
                <div>
                    <div class="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-2 font-semibold">Security & Audit</div>
                    <nav class="space-y-0.5">
                        <a href="#auditStream" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-file-lines text-xs"></i>
                            <span>System Log (SIEM Feed)</span>
                        </a>
                        <a href="audit_report.php" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-award text-xs text-sky-400"></i>
                            <span>SOC2 / FedRAMP Reports</span>
                            <span class="ml-auto text-[9px] font-mono px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300 font-bold border border-sky-500/30">NIST</span>
                        </a>
                        <a href="dashboard.php?export=csv" class="flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition">
                            <i class="fa-solid fa-download text-xs"></i>
                            <span>Export Audit CSV</span>
                        </a>
                    </nav>
                </div>
            </div>

            <!-- Footer Hardware / HSM Status -->
            <div class="p-3 border-t border-white/[0.06] bg-[#0a0e16]/60">
                <div class="flex items-center justify-between text-xs text-slate-400">
                    <div class="flex items-center gap-2">
                        <i class="fa-solid fa-microchip text-xs text-sky-400"></i>
                        <span class="text-[11px] font-medium text-slate-300">Platform Settings & HSM</span>
                    </div>
                    <span class="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1 py-0.5 rounded border border-emerald-500/20">FIPS-L4</span>
                </div>
            </div>
        </aside>

        <!-- MAIN DASHBOARD CONTENT AREA -->
        <main class="flex-1 overflow-y-auto custom-scrollbar p-4 sm:p-6 space-y-6 bg-[#0a0e16]">

            <!-- Feedback Alert Banner -->
            <?php if (!empty($feedback_alert)): ?>
                <div><?php echo $feedback_alert; ?></div>
            <?php endif; ?>

            <!-- HEADER ACTION BAR & CONTEXT -->
            <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-2 border-b border-white/[0.06]">
                <div>
                    <div class="flex items-center gap-2 text-xs font-mono text-sky-400 uppercase tracking-wider mb-1">
                        <span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
                        <span>IDENTITY THREAT PROTECTION • REAL-TIME CAE PIPELINE</span>
                        <span class="text-slate-600">/</span>
                        <span class="text-slate-400">NODE-CLUSTER: US-EAST-09</span>
                    </div>
                    <h1 class="text-xl sm:text-2xl font-bold tracking-tight text-white flex flex-wrap items-center gap-2 sm:gap-3">
                        Security Command Center & Posture Intel
                        <span class="text-xs font-mono px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 font-normal">Okta / Entra Compatible</span>
                    </h1>
                    <p class="text-xs text-slate-400 mt-1 max-w-2xl">
                        Continuous adaptive risk evaluation, phishing-resistant FIDO2 telemetry, and automated containment across multi-cloud workforce identities.
                    </p>
                </div>

                <!-- Action Controls Toolbar -->
                <div class="flex flex-wrap items-center gap-2 sm:gap-2.5">
                    
                    <!-- Threat Simulation Dropdown (University Defense Mode) -->
                    <div class="relative inline-block text-left" id="simulationDropdownContainer">
                        <button type="button" onclick="toggleSimMenu()" class="px-3 py-1.5 rounded bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-xs font-medium text-purple-300 flex items-center gap-1.5 transition">
                            <i class="fa-solid fa-flask-vial text-xs text-purple-400"></i>
                            <span>Simulate Threat (Defense Mode)</span>
                            <i class="fa-solid fa-chevron-down text-[10px] ml-1"></i>
                        </button>
                        
                        <div id="simMenu" class="hidden absolute right-0 mt-2 w-72 bg-[#0f131c] border border-white/[0.12] rounded-lg shadow-2xl py-2 z-50 text-xs custom-scrollbar">
                            <div class="px-3.5 py-1.5 text-[10px] font-mono text-purple-400 uppercase tracking-wider font-semibold border-b border-white/[0.06] mb-1 flex items-center justify-between">
                                <span>ATTACK VECTORS</span>
                                <span class="text-[9px] bg-purple-950 px-1.5 py-0.5 rounded text-purple-300">DEMO</span>
                            </div>
                            <form method="POST" action="">
                                <input type="hidden" name="action" value="simulate_threat">
                                <input type="hidden" name="scenario" value="brute_force">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3.5 py-2 text-slate-300 hover:bg-white/[0.06] hover:text-white flex items-center gap-2.5 transition">
                                    <i class="fa-solid fa-burst text-red-400 text-sm"></i>
                                    <div>
                                        <p class="font-semibold text-xs text-white">1. Rapid MFA Brute-Force</p>
                                        <p class="text-[10px] text-slate-400">5 bursts of failed MFA challenges</p>
                                    </div>
                                </button>
                            </form>
                            <form method="POST" action="">
                                <input type="hidden" name="action" value="simulate_threat">
                                <input type="hidden" name="scenario" value="ip_divergence">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3.5 py-2 text-slate-300 hover:bg-white/[0.06] hover:text-white flex items-center gap-2.5 transition">
                                    <i class="fa-solid fa-globe text-amber-400 text-sm"></i>
                                    <div>
                                        <p class="font-semibold text-xs text-white">2. Identity IP Divergence</p>
                                        <p class="text-[10px] text-slate-400">Impossible travel across 2 distinct IPs</p>
                                    </div>
                                </button>
                            </form>
                            <div class="border-t border-white/[0.06] my-1"></div>
                            <form method="POST" action="">
                                <input type="hidden" name="action" value="reset_simulation">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <button type="submit" class="w-full text-left px-3.5 py-2 text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/10 flex items-center gap-2 transition font-mono">
                                    <i class="fa-solid fa-rotate-left text-xs"></i>
                                    <span>Reset Baseline Telemetry</span>
                                </button>
                            </form>
                        </div>
                    </div>

                    <!-- Export SOC2 / SIEM CSV -->
                    <a href="?export=csv" class="px-3 py-1.5 rounded bg-[#181c24] hover:bg-[#262a34] border border-white/[0.08] text-xs font-medium text-slate-300 flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-download text-xs text-slate-400"></i>
                        <span>Export SOC2 / SIEM</span>
                    </a>

                    <!-- Provision Identity Button -->
                    <button onclick="document.getElementById('provisionModal').classList.remove('hidden')" class="px-3 py-1.5 rounded bg-sky-500/15 hover:bg-sky-500/25 border border-sky-400/30 text-xs font-medium text-sky-300 flex items-center gap-1.5 transition">
                        <i class="fa-solid fa-user-plus text-xs"></i>
                        <span>Provision Identity</span>
                    </button>

                    <!-- Emergency Lockdown / Revoke Sessions Trigger -->
                    <button onclick="document.getElementById('simMenu').classList.toggle('hidden')" class="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-xs font-medium text-white flex items-center gap-1.5 shadow-lg shadow-red-900/30 transition">
                        <i class="fa-solid fa-power-off text-xs"></i>
                        <span>Emergency Lockdown</span>
                    </button>
                </div>
            </div>

            <!-- ===================================================================== -->
            <!-- TOP ROW: FLEET TELEMETRY & POSTURE METRICS (4 CARDS)                  -->
            <!-- ===================================================================== -->
            <div id="telemetrySection" class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                
                <!-- CARD 1: Identity Posture Score / ATS -->
                <div class="p-4 rounded-lg bg-[#0f131c] border border-white/[0.08] relative overflow-hidden flex flex-col justify-between">
                    <div class="flex items-center justify-between text-xs text-slate-400">
                        <span class="font-mono uppercase text-[11px] tracking-wider">Identity Posture Score</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono <?php echo $active_theme['badge_bg']; ?> font-bold">
                            <?php echo $active_theme['badge']; ?>
                        </span>
                    </div>
                    <div class="my-3 flex items-baseline gap-3">
                        <div class="text-3xl font-extrabold font-mono text-white tracking-tight"><?php echo $threat_score; ?></div>
                        <div class="text-xs text-slate-400 font-mono">/ 100 ATS</div>
                        <div class="text-xs <?php echo $active_theme['text']; ?> flex items-center gap-1 font-mono ml-auto">
                            <span class="w-2 h-2 rounded-full <?php echo $active_theme['ping']; ?> animate-pulse"></span>
                            <span><?php echo $threat_level; ?></span>
                        </div>
                    </div>
                    <!-- Meter Bar -->
                    <div class="w-full bg-[#181c24] h-1.5 rounded-full overflow-hidden mb-2">
                        <div class="bg-gradient-to-r <?php echo $active_theme['bar']; ?> h-full rounded-full transition-all duration-700" style="width: <?php echo max(5, $threat_score); ?>%"></div>
                    </div>
                    <div class="text-[11px] text-slate-400 leading-snug">
                        <?php echo empty($anomalies) ? 'Zero active credential breaches detected.' : count($anomalies) . ' active heuristic threat(s) flagged.'; ?>
                    </div>
                    <div class="mt-3 pt-2.5 border-t border-white/[0.06] flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span>Peer Benchmark: <strong class="text-slate-200">Top 3%</strong></span>
                        <span class="text-sky-400"><?php echo count($audit_logs); ?> Signals Ingested</span>
                    </div>
                </div>

                <!-- CARD 2: Phish-Resistant MFA Coverage -->
                <div class="p-4 rounded-lg bg-[#0f131c] border border-white/[0.08] relative overflow-hidden flex flex-col justify-between">
                    <div class="flex items-center justify-between text-xs text-slate-400">
                        <span class="font-mono uppercase text-[11px] tracking-wider">Phish-Resistant MFA Coverage</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold">TARGET 100%</span>
                    </div>
                    <div class="my-3 flex items-baseline gap-2">
                        <div class="text-3xl font-extrabold font-mono text-white tracking-tight"><?php echo $mfa_rate; ?>%</div>
                        <div class="text-[11px] text-emerald-400 font-mono">Hardware FIDO2 / TOTP</div>
                    </div>
                    <!-- Progress Bar -->
                    <div class="w-full bg-[#181c24] h-1.5 rounded-full overflow-hidden">
                        <div class="bg-gradient-to-r from-sky-400 to-emerald-400 h-full rounded-full transition-all duration-500" style="width: <?php echo max(5, $mfa_rate); ?>%"></div>
                    </div>
                    <div class="mt-3 pt-2.5 border-t border-white/[0.06] flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span>Compliant: <strong class="text-slate-200"><?php echo $mfa_enabled; ?></strong></span>
                        <span class="text-amber-400"><?php echo max(0, $total_users - $mfa_enabled); ?> Pending Key</span>
                    </div>
                </div>

                <!-- CARD 3: Identity Threat Events (24h) -->
                <div class="p-4 rounded-lg bg-[#0f131c] border border-white/[0.08] relative overflow-hidden flex flex-col justify-between">
                    <div class="flex items-center justify-between text-xs text-slate-400">
                        <span class="font-mono uppercase text-[11px] tracking-wider">Identity Threat Events (24h)</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/20 font-bold">99.8% REMEDIATED</span>
                    </div>
                    <div class="my-3 flex items-baseline gap-2">
                        <div class="text-3xl font-extrabold font-mono text-white tracking-tight"><?php echo $total_logs_24h; ?></div>
                        <div class="text-xs text-slate-400 font-mono">Autonomous Neutralized</div>
                    </div>
                    <div class="grid grid-cols-3 gap-1 text-[10px] font-mono text-center">
                        <div class="bg-[#181c24] py-1 rounded">
                            <div class="text-slate-200 font-bold"><?php echo count($anomalies); ?></div>
                            <div class="text-[9px] text-slate-500 uppercase">Stuffing</div>
                        </div>
                        <div class="bg-[#181c24] py-1 rounded">
                            <div class="text-amber-400 font-bold"><?php echo ($threat_score > 25) ? '1' : '0'; ?></div>
                            <div class="text-[9px] text-slate-500 uppercase">Velocity</div>
                        </div>
                        <div class="bg-[#181c24] py-1 rounded">
                            <div class="text-emerald-400 font-bold"><?php echo max(12, $total_logs_24h); ?></div>
                            <div class="text-[9px] text-slate-500 uppercase">Bot Spray</div>
                        </div>
                    </div>
                </div>

                <!-- CARD 4: Privileged JIT Elevation Sessions -->
                <div class="p-4 rounded-lg bg-[#0f131c] border border-white/[0.08] relative overflow-hidden flex flex-col justify-between">
                    <div class="flex items-center justify-between text-xs text-slate-400">
                        <span class="font-mono uppercase text-[11px] tracking-wider">Privileged JIT Sessions</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold">PIM ENFORCED</span>
                    </div>
                    <div class="my-3 flex items-baseline gap-2">
                        <div class="text-3xl font-extrabold font-mono text-white tracking-tight"><?php echo $total_users; ?></div>
                        <div class="text-xs text-slate-400">Identities Registered</div>
                    </div>
                    <div class="text-[11px] text-slate-400 leading-snug">
                        All sessions cryptographically recorded & bounded.
                    </div>
                    <div class="mt-3 pt-2.5 border-t border-white/[0.06] flex items-center justify-between text-[10px] font-mono text-slate-400">
                        <span>Root/K8s Max TTL: <strong class="text-slate-200">58m left</strong></span>
                        <span class="text-emerald-400 flex items-center gap-1">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Live Audit
                        </span>
                    </div>
                </div>
            </div>

            <!-- ===================================================================== -->
            <!-- MIDDLE ROW: REAL-TIME ANOMALIES + TELEMETRY MAP & HSM STATUS          -->
            <!-- ===================================================================== -->
            <div id="threatFeed" class="grid grid-cols-1 lg:grid-cols-12 gap-6">

                <!-- REAL-TIME THREAT DETECTION & AUTO-REMEDIATION FEED (8 COLS) -->
                <div class="lg:col-span-8 space-y-6">
                    <div class="p-5 rounded-lg bg-[#0f131c] border border-white/[0.08] space-y-4">
                        <div class="flex items-center justify-between pb-3 border-b border-white/[0.06]">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-shield-virus text-sm <?php echo !empty($anomalies) ? 'text-red-400 animate-pulse' : 'text-emerald-400'; ?>"></i>
                                <h2 class="text-sm font-semibold text-white">Real-Time Threat Detection & Auto-Remediation Feed</h2>
                            </div>
                            <div class="flex items-center gap-3">
                                <?php if (!empty($anomalies)): ?>
                                    <span class="text-[11px] font-mono text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20 font-bold">
                                        <?php echo count($anomalies); ?> UNRESOLVED CONFLICTS
                                    </span>
                                <?php else: ?>
                                    <span class="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-semibold">
                                        OPTIMAL • 0 CONFLICTS
                                    </span>
                                <?php endif; ?>
                                <a href="#sentinelTerminal" class="text-xs text-sky-400 hover:text-sky-300 font-medium">Terminal Logs →</a>
                            </div>
                        </div>

                        <?php if (!empty($anomalies)): ?>
                            <!-- DYNAMIC LIVE DETECTED ANOMALIES -->
                            <?php foreach ($anomalies as $anom): 
                                $is_crit = ($anom['severity'] === 'CRITICAL');
                                $border_cls = $is_crit ? 'border-red-500/30' : 'border-amber-500/30';
                                $badge_cls = $is_crit ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-amber-500/20 text-amber-400 border-amber-500/30';
                                $status_lbl = $is_crit ? 'AUTO-QUARANTINED' : 'STEP-UP PROMPTED';
                                $status_badge_cls = $is_crit ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400';
                            ?>
                            <div class="p-4 rounded-md bg-[#181c24] border <?php echo $border_cls; ?> relative space-y-3">
                                <div class="flex items-start justify-between gap-4">
                                    <div class="flex items-center gap-2 flex-wrap">
                                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold <?php echo $badge_cls; ?> uppercase">
                                            <?php echo htmlspecialchars($anom['severity']); ?>
                                        </span>
                                        <span class="text-xs font-semibold text-white"><?php echo htmlspecialchars($anom['title']); ?></span>
                                        <span class="text-[10px] font-mono <?php echo $status_badge_cls; ?> px-1.5 py-0.2 rounded font-semibold">
                                            <?php echo $status_lbl; ?>
                                        </span>
                                    </div>
                                    <span class="text-[11px] font-mono text-slate-400">Just Now</span>
                                </div>

                                <p class="text-xs text-slate-300">
                                    Target Identity <code class="text-sky-400 font-mono"><?php echo htmlspecialchars($anom['target_user']); ?></code>: <?php echo htmlspecialchars($anom['description']); ?>
                                </p>

                                <div class="flex flex-col sm:flex-row sm:items-center justify-between text-[11px] font-mono text-slate-400 pt-1 gap-2">
                                    <div>Endpoint: <span class="text-slate-300"><?php echo htmlspecialchars($anom['ip_address']); ?></span> • Confidence: <span class="text-sky-400"><?php echo $anom['confidence']; ?>%</span></div>
                                    <div class="flex items-center gap-2">
                                        <a href="#sentinelTerminal" class="px-2.5 py-1 rounded bg-[#262a34] hover:bg-[#31353f] text-slate-200 text-xs transition">Investigate Context</a>
                                        <?php if (!empty($anom['target_uid']) && (int) $anom['target_uid'] !== $current_user_id): ?>
                                            <form method="POST" action="" class="inline" onsubmit="return confirm('Immediately suspend identity to mitigate risk?');">
                                                <input type="hidden" name="action" value="toggle_status">
                                                <input type="hidden" name="target_user_id" value="<?php echo (int) $anom['target_uid']; ?>">
                                                <input type="hidden" name="new_status" value="0">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <button type="submit" class="px-2.5 py-1 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-medium transition">Purge & Revoke</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            <?php endforeach; ?>

                        <?php else: ?>
                            <!-- OPTIMAL BASELINE STATE -->
                            <div class="p-4 rounded-md bg-[#181c24]/50 border border-white/[0.06] flex items-center justify-between">
                                <div class="flex items-center gap-3">
                                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                                    <div>
                                        <div class="text-xs font-medium text-slate-200">
                                            <strong class="text-emerald-400">Automated Bot Credential Spray Mitigated</strong>
                                            <span class="text-[10px] font-mono text-slate-500 ml-2">WAF RATE-LIMIT</span>
                                        </div>
                                        <div class="text-[11px] text-slate-400 mt-0.5">
                                            1,378 brute-force token exchanges from Autonomous System AS-14061 dropped via Cloudflare Edge Worker.
                                        </div>
                                    </div>
                                </div>
                                <span class="text-[11px] font-mono text-emerald-400 font-semibold shrink-0">0 Impacted Users</span>
                            </div>

                            <div class="p-3.5 rounded-md bg-[#181c24]/30 border border-white/[0.04] text-xs text-slate-400 flex items-center justify-between">
                                <span class="flex items-center gap-2">
                                    <i class="fa-solid fa-circle-check text-xs text-emerald-400"></i>
                                    Continuous Zero-Trust behavioral heuristics report optimal posture across all enrolled identity nodes.
                                </span>
                                <span class="text-[10px] font-mono text-slate-500">BASELINE CALIBRATED</span>
                            </div>
                        <?php endif; ?>

                    </div>

                    <!-- AI SENTINEL HEURISTIC TERMINAL CONSOLE -->
                    <div id="sentinelTerminal" class="rounded-lg bg-[#0f131c] border border-white/[0.08] overflow-hidden">
                        <div class="border-b border-white/[0.06] px-4 py-2.5 flex items-center justify-between bg-[#181c24]/80">
                            <div class="flex items-center gap-2">
                                <div class="flex gap-1.5 mr-2">
                                    <span class="w-2.5 h-2.5 rounded-full bg-red-500/80"></span>
                                    <span class="w-2.5 h-2.5 rounded-full bg-amber-500/80"></span>
                                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></span>
                                </div>
                                <i class="fa-solid fa-microchip text-xs text-sky-400"></i>
                                <span class="text-xs font-semibold text-white">AI Sentinel Heuristic Engine Readout</span>
                            </div>
                            <span class="text-[10px] font-mono <?php echo $active_theme['badge_bg']; ?> px-2 py-0.5 rounded font-bold">
                                ATS: <?php echo $threat_score; ?>/100 • <?php echo $threat_level; ?>
                            </span>
                        </div>

                        <div class="p-4 font-mono text-xs text-slate-400 space-y-1.5 h-64 overflow-y-auto custom-scrollbar bg-[#0a0e16]">
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
                            <div class="flex items-start gap-2 leading-relaxed">
                                <span class="text-slate-600 select-none">[<?php echo $tlog['time']; ?>]</span>
                                <span class="<?php echo $badge_color; ?> select-none">[<?php echo $tlog['badge']; ?>]</span>
                                <span class="<?php echo ($tlog['type'] === 'CRITICAL') ? 'text-red-300 font-medium' : 'text-slate-300'; ?>">
                                    <?php echo htmlspecialchars($tlog['msg']); ?>
                                </span>
                            </div>
                            <?php endforeach; ?>

                            <div class="pt-2 flex items-center gap-2 text-slate-500">
                                <span class="animate-pulse text-sky-400 font-bold">&gt;</span>
                                <span class="text-[11px] text-sky-400/70 font-mono">Sentinel heuristic engine scanning audit streams in real-time...</span>
                            </div>
                        </div>
                    </div>

                </div>

                <!-- RIGHT TELEMETRY COLUMN (4 COLS): MAP + CRYPTO HSM -->
                <div class="lg:col-span-4 space-y-6">
                    
                    <!-- GLOBAL INGRESS TELEMETRY -->
                    <div class="p-4 rounded-lg bg-[#0f131c] border border-white/[0.08] space-y-3">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-globe text-xs text-sky-400"></i>
                                <h3 class="text-xs font-semibold text-white">Global Ingress Telemetry</h3>
                            </div>
                            <span class="text-[10px] font-mono text-slate-400 bg-[#181c24] px-1.5 py-0.5 rounded border border-white/[0.06]">ANYCAST EDGE</span>
                        </div>

                        <!-- Visual Edge Simulation Box -->
                        <div class="h-28 rounded bg-[#181c24] border border-white/[0.06] p-2 flex flex-col justify-between relative overflow-hidden">
                            <div class="text-[10px] font-mono text-slate-400 flex items-center justify-between">
                                <span>Active Edge Proxies: <strong>72 / 72</strong></span>
                                <span class="text-emerald-400">P99: 14.2ms</span>
                            </div>
                            <div class="flex items-center justify-center my-auto">
                                <div class="text-center">
                                    <div class="text-base font-bold font-mono text-white tracking-tight">1,378 Drops</div>
                                    <div class="text-[10px] font-mono text-emerald-400 uppercase">100% Anonymous Proxies Mitigated</div>
                                </div>
                            </div>
                            <div class="text-[9px] font-mono text-slate-500 flex justify-between">
                                <span>Frankfurt (FRA-01)</span>
                                <span>Tokyo (TYO-03)</span>
                                <span>Ashburn (IAD-02)</span>
                            </div>
                        </div>

                        <!-- Origin Breakdown -->
                        <div class="space-y-1.5 text-xs">
                            <div class="flex items-center justify-between text-slate-300">
                                <span class="flex items-center gap-2 text-slate-400">
                                    <span class="text-[10px] font-mono">01</span>
                                    <span>United States (East / West)</span>
                                </span>
                                <span class="font-mono text-white font-semibold">54,120</span>
                            </div>
                            <div class="flex items-center justify-between text-slate-300">
                                <span class="flex items-center gap-2 text-slate-400">
                                    <span class="text-[10px] font-mono">02</span>
                                    <span>European Union (Frankfurt)</span>
                                </span>
                                <span class="font-mono text-white font-semibold">22,890</span>
                            </div>
                            <div class="flex items-center justify-between text-slate-300">
                                <span class="flex items-center gap-2 text-slate-400">
                                    <span class="text-[10px] font-mono">03</span>
                                    <span>Asia Pacific (Tokyo / Singapore)</span>
                                </span>
                                <span class="font-mono text-white font-semibold">8,912</span>
                            </div>
                        </div>
                    </div>

                    <!-- CRYPTOGRAPHIC HSM ENGINE -->
                    <div class="p-4 rounded-lg bg-[#0f131c] border border-white/[0.08] space-y-3">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-microchip text-xs text-emerald-400"></i>
                                <h3 class="text-xs font-semibold text-white">Cryptographic HSM Engine</h3>
                            </div>
                            <span class="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">FIPS 140-3 LEVEL 4</span>
                        </div>

                        <div class="space-y-2 text-xs">
                            <div>
                                <div class="flex justify-between text-[11px] font-mono text-slate-400 mb-1">
                                    <span>ROOT KEY ROTATION LIFECYCLE</span>
                                    <span class="text-sky-400">14d remaining (90d cycle)</span>
                                </div>
                                <div class="w-full bg-[#181c24] h-1.5 rounded-full overflow-hidden">
                                    <div class="bg-sky-400 h-full rounded-full" style="width: 84%"></div>
                                </div>
                            </div>

                            <div class="pt-2 border-t border-white/[0.06] grid grid-cols-2 gap-2 text-[11px] font-mono">
                                <div>
                                    <span class="text-slate-500 text-[10px] uppercase block">Signature Std</span>
                                    <span class="text-slate-200">Ed25519 / Dilithium-3 PQ</span>
                                </div>
                                <div>
                                    <span class="text-slate-500 text-[10px] uppercase block">Cluster Enclave</span>
                                    <span class="text-emerald-400">AWS CloudHSM v2 (Dual-AZ)</span>
                                </div>
                                <div>
                                    <span class="text-slate-500 text-[10px] uppercase block">Entropy Source</span>
                                    <span class="text-sky-400">Quantum TRNG (99.99%)</span>
                                </div>
                                <div>
                                    <span class="text-slate-500 text-[10px] uppercase block">Attestation Officer</span>
                                    <span class="text-slate-200"><?php echo htmlspecialchars($user_display_name); ?></span>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>

            </div>

            <!-- ===================================================================== -->
            <!-- WORKFORCE DIRECTORY & RBAC ACCESS GOVERNANCE TABLE                    -->
            <!-- ===================================================================== -->
            <div id="usersDirectory" class="p-5 rounded-lg bg-[#0f131c] border border-white/[0.08] space-y-4">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-white/[0.06]">
                    <div>
                        <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                            <i class="fa-solid fa-users text-sky-400 text-xs"></i>
                            Workforce Identity Directory & Access Governance (RBAC)
                        </h3>
                        <p class="text-xs text-slate-400 mt-0.5">Enforce Zero-Trust least privilege and trigger instant identity kill-switch locks.</p>
                    </div>
                    <span class="text-xs font-mono text-sky-400 bg-sky-500/10 px-2.5 py-1 rounded border border-sky-500/20 font-semibold self-start sm:self-auto">
                        <?php echo count($users); ?> IDENTITIES REGISTERED
                    </span>
                </div>

                <div class="overflow-x-auto custom-scrollbar">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-[#181c24] text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                            <tr>
                                <th class="px-4 py-3">UID</th>
                                <th class="px-4 py-3">Identity / Account</th>
                                <th class="px-4 py-3">Role</th>
                                <th class="px-4 py-3">Security Clearance</th>
                                <th class="px-4 py-3">MFA Status</th>
                                <th class="px-4 py-3">Status</th>
                                <th class="px-4 py-3 text-right">SOC Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/[0.04]">
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
                                    1 => 'bg-purple-500/10 text-purple-400 border-purple-500/20',
                                    2 => 'bg-sky-500/10 text-sky-400 border-sky-500/20',
                                    3 => 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
                                    default => 'bg-slate-500/10 text-slate-400 border-slate-500/20',
                                };

                                $clearance_badge = match(true) {
                                    stripos($user_clearance_val, 'Tier 3') !== false => 'bg-purple-500/15 text-purple-300 border-purple-500/30',
                                    stripos($user_clearance_val, 'Tier 2') !== false => 'bg-sky-500/15 text-sky-300 border-sky-500/30',
                                    default => 'bg-amber-500/15 text-amber-300 border-amber-500/30',
                                };
                                $clearance_icon = match(true) {
                                    stripos($user_clearance_val, 'Tier 3') !== false => 'fa-gem',
                                    stripos($user_clearance_val, 'Tier 2') !== false => 'fa-file-shield',
                                    default => 'fa-id-badge',
                                };
                            ?>
                            <tr class="hover:bg-white/[0.02] transition <?php echo !$is_active ? 'bg-red-950/10' : ''; ?>">
                                <!-- User ID -->
                                <td class="px-4 py-3 font-mono text-[11px] text-slate-400">
                                    UID-<?php echo str_pad($uid, 4, '0', STR_PAD_LEFT); ?>
                                </td>

                                <!-- Identity Account -->
                                <td class="px-4 py-3">
                                    <div class="flex items-center gap-3">
                                        <div class="w-8 h-8 rounded-full <?php echo $is_active ? 'bg-[#181c24] text-sky-400 border border-white/[0.08]' : 'bg-red-950/40 text-red-400 border border-red-500/30'; ?> flex items-center justify-center font-bold text-xs shrink-0">
                                            <?php echo strtoupper(substr($user_email, 0, 1)); ?>
                                        </div>
                                        <div>
                                            <div class="text-white font-medium flex items-center gap-2">
                                                <?php echo $user_email; ?>
                                                <?php if ($is_self): ?>
                                                    <span class="text-[9px] font-mono bg-sky-500/20 text-sky-400 border border-sky-500/30 px-1 py-0.2 rounded font-semibold">YOU</span>
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

                                <!-- Role -->
                                <td class="px-4 py-3">
                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono border <?php echo $role_badge; ?>">
                                        <?php echo $user_functional_role; ?>
                                    </span>
                                </td>

                                <!-- Clearance -->
                                <td class="px-4 py-3">
                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold border <?php echo $clearance_badge; ?>">
                                        <i class="fa-solid <?php echo $clearance_icon; ?> mr-1 text-[10px]"></i> <?php echo htmlspecialchars($user_clearance_val); ?>
                                    </span>
                                </td>

                                <!-- MFA -->
                                <td class="px-4 py-3">
                                    <?php if (!empty($u['mfa_secret'])): ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                                            <i class="fa-solid fa-shield-halved mr-1 text-[9px]"></i> ENFORCED
                                        </span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/20 font-semibold">
                                            <i class="fa-solid fa-triangle-exclamation mr-1 text-[9px]"></i> UNPROTECTED
                                        </span>
                                    <?php endif; ?>
                                </td>

                                <!-- Status -->
                                <td class="px-4 py-3">
                                    <?php if ($is_active): ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span> Active
                                        </span>
                                    <?php else: ?>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/30 animate-pulse font-bold">
                                            <span class="w-1.5 h-1.5 rounded-full bg-red-400 mr-1.5"></span> SUSPENDED
                                        </span>
                                    <?php endif; ?>
                                </td>

                                <!-- Actions -->
                                <td class="px-4 py-3 text-right whitespace-nowrap">
                                    <div class="inline-flex items-center gap-1">
                                        <?php if ($is_self): ?>
                                            <span class="p-1.5 text-slate-600 cursor-not-allowed text-xs" title="Self-suspension locked by security policy">
                                                <i class="fa-solid fa-lock"></i>
                                            </span>
                                        <?php else: ?>
                                            <form method="POST" action="" class="inline" onsubmit="return confirm('<?php echo $is_active ? 'CRITICAL SOC ACTION: Are you sure you want to SUSPEND UID-' . $uid . ' (' . $user_email . ')?' : 'Re-activate account access for UID-' . $uid . ' (' . $user_email . ')?'; ?>');">
                                                <input type="hidden" name="action" value="toggle_status">
                                                <input type="hidden" name="target_user_id" value="<?php echo $uid; ?>">
                                                <input type="hidden" name="new_status" value="<?php echo $is_active ? 0 : 1; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                
                                                <?php if ($is_active): ?>
                                                    <button type="submit" class="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded transition" title="Suspend Identity (Kill-Switch)">
                                                        <i class="fa-solid fa-user-slash"></i>
                                                    </button>
                                                <?php else: ?>
                                                    <button type="submit" class="p-1.5 text-red-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded transition" title="Reactivate Account">
                                                        <i class="fa-solid fa-user-check"></i>
                                                    </button>
                                                <?php endif; ?>
                                            </form>
                                        <?php endif; ?>

                                        <!-- Edit Role & Clearance Modal Trigger -->
                                        <button onclick="openRoleModal(<?php echo $uid; ?>, '<?php echo addslashes($user_email); ?>', <?php echo $user_role_id; ?>, '<?php echo addslashes($user_functional_role); ?>', '<?php echo addslashes($user_clearance_val); ?>')" class="p-1.5 text-slate-400 hover:text-sky-400 hover:bg-sky-500/10 rounded transition" title="Modify RBAC Role & Clearance">
                                            <i class="fa-solid fa-user-gear"></i>
                                        </button>

                                        <?php if (!$is_self): ?>
                                            <!-- Purge / Delete Identity Form -->
                                            <form method="POST" action="" class="inline" onsubmit="return confirm('PERMANENT ACTION: Purge UID-<?php echo $uid; ?> (<?php echo $user_email; ?>) permanently?');">
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

            <!-- ===================================================================== -->
            <!-- LIVE SIEM & AUDIT STREAM FEED                                         -->
            <!-- ===================================================================== -->
            <div id="auditStream" class="p-5 rounded-lg bg-[#0f131c] border border-white/[0.08] space-y-4">
                <div class="flex items-center justify-between pb-3 border-b border-white/[0.06]">
                    <div class="flex items-center gap-2">
                        <i class="fa-solid fa-server text-xs text-sky-400"></i>
                        <h3 class="text-xs font-semibold text-white uppercase font-mono tracking-wider">Live System Log (SIEM Feed)</h3>
                    </div>
                    <span class="text-[10px] font-mono text-emerald-400 flex items-center gap-1.5">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                        LIVE INGEST • IMMUTABLE
                    </span>
                </div>

                <div class="divide-y divide-white/[0.04] max-h-72 overflow-y-auto custom-scrollbar font-mono text-xs">
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
                                'BASELINE_RESET' => ['icon' => 'fa-rotate-left', 'color' => 'text-emerald-400'],
                                default => ['icon' => 'fa-shield', 'color' => 'text-slate-400']
                            };
                        ?>
                        <div class="py-2.5 px-2 hover:bg-white/[0.02] transition flex items-start gap-3">
                            <i class="fa-solid <?php echo $icon_data['icon']; ?> <?php echo $icon_data['color']; ?> text-xs mt-1 shrink-0"></i>
                            <div class="min-w-0 flex-1">
                                <p class="text-xs text-slate-300 leading-snug break-words"><?php echo htmlspecialchars($action_text); ?></p>
                                <div class="flex items-center gap-3 text-[10px] text-slate-500 mt-0.5">
                                    <span>IP: <code class="text-sky-400/80"><?php echo htmlspecialchars($ip); ?></code></span>
                                    <span>•</span>
                                    <span>UID-<?php echo htmlspecialchars($log['user_id'] ? str_pad($log['user_id'], 4, '0', STR_PAD_LEFT) : 'SYS'); ?></span>
                                    <span>•</span>
                                    <span><?php echo htmlspecialchars($time); ?></span>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="py-8 text-center text-xs text-slate-500 font-mono">
                            SIEM audit stream is currently empty.
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- ===================================================================== -->
            <!-- BOTTOM ROW: AUTHENTICATION FACTOR TELEMETRY & LATENCY                 -->
            <!-- ===================================================================== -->
            <div class="p-5 rounded-lg bg-[#0f131c] border border-white/[0.08] space-y-4">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 border-b border-white/[0.06]">
                    <div>
                        <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                            <i class="fa-solid fa-fingerprint text-xs text-sky-400"></i>
                            Authentication Factor Telemetry & Latency Health
                        </h3>
                        <p class="text-xs text-slate-400 mt-0.5">Continuous cryptographic verification distribution & token evaluation latency.</p>
                    </div>
                    <div class="flex items-center gap-4 text-xs font-mono">
                        <div class="text-right">
                            <div class="text-[10px] text-slate-500">P99 LATENCY</div>
                            <div class="text-emerald-400 font-bold">18.4ms</div>
                        </div>
                        <div class="text-right">
                            <div class="text-[10px] text-slate-500">CACHE HIT</div>
                            <div class="text-sky-400 font-bold">99.8%</div>
                        </div>
                    </div>
                </div>

                <!-- Latency Waveform Visual -->
                <div class="h-16 w-full bg-[#181c24] rounded border border-white/[0.06] p-2 flex items-end gap-1 relative overflow-hidden">
                    <div class="absolute top-2 left-3 text-[10px] font-mono text-slate-500">REAL-TIME TOKEN ISSUANCE (RS256 / ED25519)</div>
                    <div class="absolute top-2 right-3 text-[10px] font-mono text-emerald-400">0.00% Packet Jitter • 100% Attested</div>
                    <!-- Waveform SVG Simulation -->
                    <svg class="w-full h-10 text-sky-400/80" fill="none" viewBox="0 0 1000 40" preserveAspectRatio="none">
                        <path d="M0 20 Q 25 5, 50 20 T 100 20 T 150 5 T 200 35 T 250 15 T 300 25 T 350 5 T 400 30 T 450 20 T 500 10 T 550 30 T 600 15 T 650 25 T 700 5 T 750 35 T 800 20 T 850 10 T 900 30 T 950 15 T 1000 20" stroke="currentColor" stroke-width="1.5" />
                    </svg>
                </div>

                <!-- 4 Factors Breakdown Cards -->
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div class="p-3 rounded bg-[#181c24] border border-white/[0.06]">
                        <div class="flex justify-between items-center text-xs">
                            <span class="text-slate-400 font-medium">FIDO2 / FastPass</span>
                            <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                        </div>
                        <div class="text-xl font-bold font-mono text-white mt-1">62.0%</div>
                        <div class="text-[10px] text-emerald-400 font-mono mt-0.5">Phishing-Resistant</div>
                    </div>

                    <div class="p-3 rounded bg-[#181c24] border border-white/[0.06]">
                        <div class="flex justify-between items-center text-xs">
                            <span class="text-slate-400 font-medium">Mobile Push</span>
                            <span class="w-2 h-2 rounded-full bg-sky-400"></span>
                        </div>
                        <div class="text-xl font-bold font-mono text-white mt-1">29.0%</div>
                        <div class="text-[10px] text-sky-400 font-mono mt-0.5">Number Matching</div>
                    </div>

                    <div class="p-3 rounded bg-[#181c24] border border-white/[0.06]">
                        <div class="flex justify-between items-center text-xs">
                            <span class="text-slate-400 font-medium">TOTP App</span>
                            <span class="w-2 h-2 rounded-full bg-amber-400"></span>
                        </div>
                        <div class="text-xl font-bold font-mono text-white mt-1"><?php echo $mfa_rate; ?>%</div>
                        <div class="text-[10px] text-amber-400 font-mono mt-0.5">RFC 6238 Standard</div>
                    </div>

                    <div class="p-3 rounded bg-[#181c24] border border-white/[0.06]">
                        <div class="flex justify-between items-center text-xs">
                            <span class="text-slate-400 font-medium">SMS / Voice</span>
                            <span class="w-2 h-2 rounded-full bg-red-400"></span>
                        </div>
                        <div class="text-xl font-bold font-mono text-white mt-1">0.0%</div>
                        <div class="text-[10px] text-red-400 font-mono mt-0.5">Blocked by Policy</div>
                    </div>
                </div>

                <div class="pt-2 text-[11px] text-slate-400 flex items-center justify-between">
                    <span class="flex items-center gap-1.5">
                        <span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span>
                        Continuous Access Evaluation (CAE): Evaluating 1,420 token refreshes/min. Revocation latency &lt;300ms.
                    </span>
                    <a href="audit_report.php" class="text-sky-400 hover:text-sky-300 font-medium">View NIST Compliance →</a>
                </div>
            </div>

            <!-- Footer Compliance Tag -->
            <div class="pt-6 border-t border-white/[0.06] text-center text-xs font-mono text-slate-500">
                <span>Aegis Enterprise IAM Portal • Zero-Trust Security Command Center • NIST SP 800-63B &amp; FedRAMP High Ready</span>
            </div>

        </main>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 1: PROVISION IDENTITY                                               -->
    <!-- ========================================================================= -->
    <div id="provisionModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-xs flex justify-center items-center z-50 p-4">
        <div class="p-6 rounded-lg bg-[#0f131c] border border-white/[0.12] shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto custom-scrollbar">
            <div class="flex justify-between items-center mb-5 border-b border-white/[0.06] pb-3">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded bg-sky-500/10 border border-sky-400/30 flex items-center justify-center text-sky-400">
                        <i class="fa-solid fa-user-plus text-xs"></i>
                    </div>
                    <h2 class="text-sm font-semibold text-white">Provision Enterprise Identity</h2>
                </div>
                <button onclick="document.getElementById('provisionModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <?php if (isset($provision_msg)) echo $provision_msg; ?>

            <form method="POST" action="" class="space-y-4">
                <input type="hidden" name="action" value="provision_user">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">First Name</label>
                        <input type="text" name="first_name" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50" placeholder="Jane">
                    </div>
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Last Name</label>
                        <input type="text" name="last_name" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50" placeholder="Doe">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Enterprise Email <span class="text-red-400">*</span></label>
                        <input type="email" name="new_email" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50" placeholder="user@organization.com" required>
                    </div>
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Temporary Password <span class="text-red-400">*</span></label>
                        <input type="password" name="new_password" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50" placeholder="••••••••••••" required>
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Department</label>
                        <select name="department" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50">
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
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Job Title</label>
                        <input type="text" name="job_title" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50" value="Staff Analyst">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Functional Role (RBAC)</label>
                        <select name="role" id="provRoleSelect" onchange="syncProvisioningDefaults()" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50">
                            <option value="Staff" selected>Staff (Standard Employee)</option>
                            <option value="Auditor">Auditor (Compliance Officer)</option>
                            <option value="Admin">Admin (SOC Administrator)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Security Clearance</label>
                        <select name="security_clearance" id="provClearanceSelect" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50">
                            <option value="Tier 1" selected>Tier 1 // Restricted</option>
                            <option value="Tier 2">Tier 2 // Confidential</option>
                            <option value="Tier 3">Tier 3 // Top Secret</option>
                        </select>
                    </div>
                </div>

                <input type="hidden" name="role_id" id="provRoleIdHidden" value="4">

                <div class="flex gap-3 pt-3 border-t border-white/[0.06]">
                    <button type="button" onclick="document.getElementById('provisionModal').classList.add('hidden')" class="w-1/2 py-2 rounded bg-[#181c24] hover:bg-[#262a34] text-xs font-medium text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white transition shadow">
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
        <div class="p-6 rounded-lg bg-[#0f131c] border border-white/[0.12] shadow-2xl w-full max-w-md">
            <div class="flex justify-between items-center mb-5 border-b border-white/[0.06] pb-3">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded bg-sky-500/10 border border-sky-400/30 flex items-center justify-center text-sky-400">
                        <i class="fa-solid fa-user-gear text-xs"></i>
                    </div>
                    <h2 class="text-sm font-semibold text-white">Modify RBAC Permissions</h2>
                </div>
                <button onclick="document.getElementById('roleModal').classList.add('hidden')" class="text-slate-400 hover:text-white transition">
                    <i class="fa-solid fa-xmark text-sm"></i>
                </button>
            </div>

            <form method="POST" action="" class="space-y-4">
                <input type="hidden" name="action" value="update_role">
                <input type="hidden" name="target_user_id" id="roleModalUserId">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div>
                    <label class="block text-[11px] font-mono text-slate-400 mb-1">Target Account</label>
                    <div id="roleModalEmail" class="text-xs font-mono text-sky-400 bg-[#181c24] px-3 py-2 rounded border border-white/[0.08]"></div>
                </div>

                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Functional Role</label>
                        <select name="new_functional_role" id="roleModalFuncRole" onchange="syncRoleModalDefaults()" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50">
                            <option value="Staff">Staff</option>
                            <option value="Auditor">Auditor</option>
                            <option value="Admin">Admin</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-[11px] font-mono text-slate-400 mb-1">Clearance Tier</label>
                        <select name="new_clearance" id="roleModalClearance" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50">
                            <option value="Tier 1">Tier 1 (Restricted)</option>
                            <option value="Tier 2">Tier 2 (Confidential)</option>
                            <option value="Tier 3">Tier 3 (Top Secret)</option>
                        </select>
                    </div>
                </div>

                <div>
                    <label class="block text-[11px] font-mono text-slate-400 mb-1">Database Role Group</label>
                    <select name="new_role_id" id="roleModalSelect" class="w-full bg-[#181c24] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500/50">
                        <?php foreach ($roles as $r): ?>
                            <option value="<?php echo (int) $r['role_id']; ?>">
                                <?php echo htmlspecialchars($r['role_name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="flex gap-3 pt-3 border-t border-white/[0.06]">
                    <button type="button" onclick="document.getElementById('roleModal').classList.add('hidden')" class="w-1/2 py-2 rounded bg-[#181c24] hover:bg-[#262a34] text-xs font-medium text-slate-300 transition">
                        Cancel
                    </button>
                    <button type="submit" class="w-1/2 py-2 rounded bg-sky-600 hover:bg-sky-500 text-xs font-medium text-white transition shadow">
                        Apply Changes
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- ========================================================================= -->
    <!-- MODAL 3: ANIMATED CYBERSECURITY BIOMETRIC WELCOME HUD                     -->
    <!-- ========================================================================= -->
    <div id="cyberWelcomeHUD" class="<?php echo $show_welcome_hud ? '' : 'hidden'; ?> fixed inset-0 z-50 bg-[#0a0e16]/90 backdrop-blur-md flex items-center justify-center p-4">
        <div class="relative w-full max-w-2xl bg-[#0f131c] border border-sky-500/40 rounded-xl p-6 sm:p-8 overflow-hidden text-slate-200 shadow-2xl">
            
            <div class="flex justify-between items-center border-b border-white/[0.08] pb-3 mb-6">
                <div class="flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-sky-400 animate-ping"></span>
                    <span class="font-mono text-xs text-sky-400 uppercase tracking-widest font-bold">
                        // ZERO-TRUST IDENTITY ENCLAVE ACCESSED
                    </span>
                </div>
                <div class="flex items-center gap-3 text-xs font-mono">
                    <span class="text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                        <i class="fa-solid fa-lock mr-1 text-[10px]"></i> TLS 1.3 SECURED
                    </span>
                </div>
            </div>

            <div class="flex flex-col sm:flex-row items-center gap-6 mb-6">
                <div class="relative w-24 h-24 flex-shrink-0 flex items-center justify-center">
                    <div class="absolute inset-0 rounded-full border border-dashed border-sky-500/40 animate-spin"></div>
                    <div class="absolute inset-2 rounded-full border border-sky-400/30"></div>
                    <div class="absolute inset-4 rounded-full bg-sky-950/40 border border-sky-500/50 flex items-center justify-center">
                        <i class="fa-solid fa-fingerprint text-3xl text-sky-400 animate-pulse"></i>
                    </div>
                </div>

                <div class="text-center sm:text-left flex-1 space-y-1">
                    <p class="text-xs font-mono text-slate-400 uppercase tracking-wider">
                        IDENTITY CONFIRMED • ACCESS GRANTED
                    </p>
                    <h2 class="text-2xl font-bold text-white tracking-tight">
                        Welcome, <span class="text-sky-400"><?php echo htmlspecialchars($user_display_name); ?></span>
                    </h2>
                    <div class="flex flex-wrap items-center justify-center sm:justify-start gap-2 pt-1 font-mono text-xs">
                        <span class="bg-[#181c24] text-slate-300 border border-white/[0.08] px-2 py-0.5 rounded">
                            UID-<?php echo str_pad($current_user_id, 4, '0', STR_PAD_LEFT); ?>
                        </span>
                        <span class="text-slate-500">•</span>
                        <span class="text-sky-400"><?php echo htmlspecialchars($current_user['email']); ?></span>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 font-mono text-xs mb-6">
                <div class="bg-[#181c24] p-2.5 rounded border border-white/[0.06]">
                    <p class="text-slate-500 text-[10px] uppercase">Clearance</p>
                    <p class="text-purple-400 font-bold truncate mt-0.5"><?php echo $current_role_info['name']; ?></p>
                </div>
                <div class="bg-[#181c24] p-2.5 rounded border border-white/[0.06]">
                    <p class="text-slate-500 text-[10px] uppercase">Encryption</p>
                    <p class="text-emerald-400 font-bold truncate mt-0.5">TLS 1.3 / AES-256</p>
                </div>
                <div class="bg-[#181c24] p-2.5 rounded border border-white/[0.06]">
                    <p class="text-slate-500 text-[10px] uppercase">MFA Protocol</p>
                    <p class="text-sky-400 font-bold truncate mt-0.5">RFC 6238 PASSED</p>
                </div>
                <div class="bg-[#181c24] p-2.5 rounded border border-white/[0.06]">
                    <p class="text-slate-500 text-[10px] uppercase">Ingress</p>
                    <p class="text-slate-300 font-bold truncate mt-0.5"><?php echo htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'); ?></p>
                </div>
            </div>

            <div class="space-y-3">
                <div class="flex items-center justify-between">
                    <span class="text-[11px] font-mono text-slate-500" id="hudTimerText">Auto-entering command center in 6s...</span>
                    <button onclick="dismissCyberWelcomeHUD()" class="bg-sky-600 hover:bg-sky-500 text-white font-medium px-4 py-1.5 rounded text-xs font-mono uppercase tracking-wider transition flex items-center gap-1.5">
                        <span>Access Command Center</span>
                        <i class="fa-solid fa-arrow-right text-[10px]"></i>
                    </button>
                </div>
                <div class="w-full bg-[#181c24] rounded-full h-1 overflow-hidden border border-white/[0.06]">
                    <div id="hudProgressBar" class="bg-sky-400 h-1 transition-all duration-100 ease-linear" style="width: 100%;"></div>
                </div>
            </div>

        </div>
    </div>

    <!-- JavaScript Handlers -->
    <script>
        function toggleSidebar() {
            const sidebar = document.getElementById('appSidebar');
            if (sidebar) {
                sidebar.classList.toggle('hidden');
            }
        }

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

        // =============================================================
        // WELCOME HUD & AUDIO SCRIPT
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
                createBeep(ctx, 520, now, 0.12);
                createBeep(ctx, 660, now + 0.12, 0.12);
                createBeep(ctx, 880, now + 0.24, 0.25);
            } catch (e) {}
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
            audioMuted = !audioMuted;
            const navIcon = document.getElementById('navMuteIcon');
            if (navIcon) {
                navIcon.className = audioMuted ? 'fa-solid fa-volume-xmark text-xs text-red-400' : 'fa-solid fa-volume-high text-xs text-sky-400';
            }
        }

        function dismissCyberWelcomeHUD() {
            if (hudTimerInterval) clearInterval(hudTimerInterval);
            const hud = document.getElementById('cyberWelcomeHUD');
            if (hud) hud.classList.add('hidden');
        }

        function triggerCyberWelcomeHUD() {
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
