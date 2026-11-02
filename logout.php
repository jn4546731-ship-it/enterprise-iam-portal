<?php
session_start();
require_once 'db.php';

// Log the logout event into the Immutable Audit Trail before destroying the session
if (isset($_SESSION['user_id'])) {
    $current_uid = (int) $_SESSION['user_id'];
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    
    $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, 'LOGOUT', 'User securely terminated session', ?)");
    if ($log_stmt) {
        $log_stmt->bind_param("is", $current_uid, $ip_address);
        $log_stmt->execute();
    }
}

// Unset all session variables and destroy session completely
$_SESSION = [];
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}
session_destroy();

// Redirect to login page
header("Location: index.php");
exit();
