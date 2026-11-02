<?php
/**
 * Enterprise Database Connection & HTTPS Enforcement Module
 * Loads credentials dynamically from .env using zero-dependency loader.
 * Enforces TLS/HTTPS, UTF-8 encoding, and resilient error reporting.
 */

require_once __DIR__ . '/env_loader.php';

// Load .env configuration
loadEnv(__DIR__ . '/.env');

// -------------------------------------------------------------
// ENFORCE HTTPS ON CUSTOM DOMAIN
// -------------------------------------------------------------
if (filter_var(env('FORCE_HTTPS', false), FILTER_VALIDATE_BOOLEAN)) {
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || 
                (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) ||
                (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
                
    $host = $_SERVER['HTTP_HOST'] ?? '';
    
    // Automatically redirect HTTP to HTTPS when accessing via enterprise domain
    if (!$is_https && !empty($host) && in_array(strtolower(explode(':', $host)[0]), [
        'iam.secure-defense.internal',
        'auth.enterprise-soc.local'
    ], true)) {
        $clean_host = explode(':', $host)[0];
        $redirect = "https://{$clean_host}" . ($_SERVER['REQUEST_URI'] ?? '/');
        header("Location: {$redirect}", true, 301);
        exit();
    }
}

$db_host = env('DB_HOST', '127.0.0.1');
$db_port = (int) env('DB_PORT', 3306);
$db_user = env('DB_USERNAME', 'root');
$db_pass = env('DB_PASSWORD', '');
$db_name = env('DB_DATABASE', 'iam_secure_portal');
$app_debug = filter_var(env('APP_DEBUG', false), FILTER_VALIDATE_BOOLEAN);

// Enable MySQLi error reporting mode
mysqli_report(MYSQLI_REPORT_OFF);

$conn = @new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);

if ($conn->connect_error) {
    // Log actual error to internal PHP server error log
    error_log("[IAM SOC Security Alert] Database connection failure: " . $conn->connect_error);
    
    if ($app_debug) {
        die("Database Connection Error (Debug Mode): " . htmlspecialchars($conn->connect_error));
    } else {
        http_response_code(500);
        die("<!DOCTYPE html><html><head><title>System Error</title><script src='assets/js/tailwind.js'></script></head><body class='bg-slate-900 text-slate-300 flex items-center justify-center h-screen'><div class='bg-slate-800 p-8 rounded-xl border border-red-500/50 text-center max-w-md'><h2 class='text-xl font-bold text-red-400 mb-2'>Security Alert: Infrastructure Unavailable</h2><p class='text-sm text-slate-400'>The Zero-Trust IAM Database subsystem is currently unreachable. Please check MySQL service status in XAMPP.</p></div></body></html>");
    }
}

// Ensure secure UTF-8 character encoding
$conn->set_charset('utf8mb4');

// -------------------------------------------------------------
// SELF-HEALING RBAC SCHEMA ASSURANCE (Phase 4.2 Enterprise Crown Jewels)
// -------------------------------------------------------------
// Ensure api_keys table exists
@$conn->query("
    CREATE TABLE IF NOT EXISTS `api_keys` (
      `id` INT AUTO_INCREMENT PRIMARY KEY,
      `app_name` VARCHAR(100) NOT NULL,
      `api_key` VARCHAR(128) NOT NULL UNIQUE,
      `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
      `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
");

// Ensure enterprise user attributes exist (department, job_title, role, security_clearance)
$col_check = @$conn->query("SHOW COLUMNS FROM `users` LIKE 'department'");
if ($col_check && $col_check->num_rows === 0) {
    @$conn->query("ALTER TABLE `users` ADD COLUMN `department` VARCHAR(100) NOT NULL DEFAULT 'General Operations' AFTER `last_name`");
    @$conn->query("ALTER TABLE `users` ADD COLUMN `job_title` VARCHAR(100) NOT NULL DEFAULT 'Staff Analyst' AFTER `department`");
    @$conn->query("ALTER TABLE `users` ADD COLUMN `role` VARCHAR(50) NOT NULL DEFAULT 'Staff' AFTER `job_title`");
    @$conn->query("ALTER TABLE `users` ADD COLUMN `security_clearance` VARCHAR(20) NOT NULL DEFAULT 'Tier 1' AFTER `role`");
    
    // Elevate admin user to Tier 3
    @$conn->query("UPDATE `users` SET `role` = 'Admin', `security_clearance` = 'Tier 3', `department` = 'Security Operations Center', `job_title` = 'Chief Information Security Officer (CISO)' WHERE `user_id` = 1 OR `email` = 'admin@organization.com'");
}

