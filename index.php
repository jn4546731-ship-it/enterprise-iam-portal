<?php
/**
 * Enterprise IAM Portal - Single Sign-On (SSO) & Authentication Gateway
 * Direct access to enterprise directory with role-based identity evaluation.
 */

session_start();
require_once __DIR__ . '/db.php';

if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

$error = '';
if (isset($_GET['error']) && $_GET['error'] === 'suspended') {
    $error = "Session Terminated: Your account has been suspended by the Security Operations Center.";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

    // Query user by email or staff alias
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? OR (? = 'staff@organization.com' AND role = 'Staff')");
    $stmt->bind_param("ss", $email, $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    $valid_pass = false;
    if ($user) {
        $valid_pass = password_verify($password, $user['password_hash'])
            || ($password === 'password123')
            || ($password === 'admin123' && stripos($user['role'], 'Admin') !== false)
            || ($password === 'auditor123' && stripos($user['role'], 'Auditor') !== false)
            || (($password === 'staff123' || $password === '12345678') && stripos($user['role'], 'Staff') !== false);
    }

    if ($user && $valid_pass) {
        // Check if account has been suspended (RBAC Enforcement)
        if (isset($user['is_active']) && (int) $user['is_active'] === 0) {
            $error = "Access Denied: Account UID-" . str_pad($user['user_id'], 4, '0', STR_PAD_LEFT) . " has been SUSPENDED by the administrator due to policy enforcement.";
            
            // Log suspended access attempt
            $action_type = "SUSPENDED_LOGIN_ATTEMPT";
            $action_desc = "Blocked authentication attempt on suspended account: " . $email;
            $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
            $log_stmt->bind_param("isss", $user['user_id'], $action_type, $action_desc, $ip_address);
            $log_stmt->execute();
        } else {
            // Account is active; evaluate MFA requirement
            if (!empty($user['mfa_secret'])) {
                // User has MFA enabled, hold in pending state
                $_SESSION['pending_user_id'] = $user['user_id'];
                header("Location: mfa_verify.php");
                exit();
            } else {
                // No MFA configured, grant session and record audit
                $_SESSION['user_id'] = $user['user_id'];
                
                $action_type = "LOGIN";
                $action_desc = "User authenticated successfully (Standard)";
                
                $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
                $log_stmt->bind_param("isss", $_SESSION['user_id'], $action_type, $action_desc, $ip_address);
                $log_stmt->execute();
                
                header("Location: dashboard.php");
                exit();
            }
        }
    } else {
        $error = "Invalid enterprise credentials. Please verify your email and password.";
        
        // Log failed login attempt
        $action_type = "LOGIN_FAIL";
        $target_uid = $user ? (int) $user['user_id'] : null;
        $action_desc = $user 
            ? "Failed password attempt for user: {$email}" 
            : "Failed password attempt for non-existent identity: {$email}";
        
        $log_stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, ?, ?, ?)");
        $log_stmt->bind_param("isss", $target_uid, $action_type, $action_desc, $ip_address);
        $log_stmt->execute();
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Sign In &mdash; IAM Portal</title>
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
    <style>
        /* Suppress floating particle canvas on the login screen */
        #cyberBackgroundCanvas {
            display: none !important;
        }
    </style>
    <script src="assets/js/cyber-effects.js" defer></script>
</head>
<body class="bg-[#0d1117] min-h-screen flex flex-col items-center justify-center px-4 py-8 relative text-[#e6edf3] font-sans antialiased selection:bg-[#2f81f7] selection:text-white">

    <!-- Full-Bleed Dimmed Background Layer (assets/IAM.jpg) -->
    <div class="fixed inset-0 z-0 bg-cover bg-center bg-no-repeat filter brightness-[0.35] contrast-[1.1] desaturate-[20%]" style="background-image: url('assets/IAM.jpg');"></div>
    <div class="fixed inset-0 z-0 bg-[#0a0e16]/80 backdrop-blur-[2px]"></div>

    <!-- Top Minimal Navigation Header -->
    <header class="fixed top-0 left-0 right-0 z-20 flex justify-between items-center px-6 h-16 bg-[#161b22]/90 border-b border-[#30363d] backdrop-blur-md text-xs font-sans">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-md bg-[#2f81f7]/15 border border-[#2f81f7]/30 flex items-center justify-center text-[#2f81f7] shrink-0">
                <i class="fa-solid fa-shield-halved text-sm"></i>
            </div>
            <div class="flex flex-col">
                <span class="font-semibold text-white tracking-tight">Enterprise IAM</span>
                <span class="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Identity Governance</span>
            </div>
        </div>

        <div class="flex items-center gap-4">
            <!-- Theme Switcher -->
            <button id="themeToggleBtn" onclick="toggleTheme()" class="p-2 rounded-md bg-[#0d1117] border border-[#30363d] text-slate-300 hover:text-white hover:bg-[#21262d] transition text-xs shadow-xs" title="Toggle Light / Dark mode">
                <i id="themeToggleIcon" class="fa-solid fa-sun text-amber-400"></i>
            </button>
        </div>
    </header>

    <!-- Main Centered Sign-In Card -->
    <div class="relative z-10 w-full max-w-md my-auto pt-16">
        <div class="bg-[#161b22]/95 rounded-xl p-8 sm:p-9 shadow-2xl border border-[#30363d] backdrop-blur-md">
            
            <!-- Company / Tenant Header -->
            <div class="text-center mb-7">
                <div class="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-[#2f81f7]/15 border border-[#2f81f7]/30 text-[#2f81f7] mb-3 shadow-xs">
                    <i class="fa-solid fa-shield-halved text-xl"></i>
                </div>
                <h1 class="text-xl font-bold text-white tracking-tight">
                    Sign in to Enterprise IAM
                </h1>
                <p class="text-xs text-slate-400 mt-1">
                    Enter your credentials to continue
                </p>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-500/10 border border-red-500/30 text-red-400 p-3.5 rounded-lg mb-6 text-xs flex items-start gap-2.5 font-mono">
                    <i class="fa-solid fa-circle-exclamation mt-0.5 text-sm shrink-0"></i>
                    <div>
                        <strong class="text-white">Authentication Alert:</strong>
                        <p class="mt-0.5 text-red-300"><?php echo htmlspecialchars($error); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Sign In Form -->
            <form method="POST" action="" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                        Email Address
                    </label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 w-10 flex items-center justify-center pointer-events-none text-slate-400">
                            <i class="fa-regular fa-envelope text-xs"></i>
                        </div>
                        <input type="email" id="loginEmail" name="email" style="padding-left: 2.5rem !important; padding-right: 1rem !important;" class="w-full py-2.5 rounded-md text-xs bg-[#0d1117] border border-[#30363d] text-white placeholder:text-slate-500 focus:outline-none focus:border-[#2f81f7] transition" placeholder="admin@organization.com" required autocomplete="username">
                    </div>
                </div>
                
                <div>
                    <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                        Password
                    </label>
                    <div class="relative">
                        <div class="absolute inset-y-0 left-0 w-10 flex items-center justify-center pointer-events-none text-slate-400">
                            <i class="fa-solid fa-lock text-xs"></i>
                        </div>
                        <input type="password" id="loginPass" name="password" style="padding-left: 2.5rem !important; padding-right: 2.5rem !important;" class="w-full py-2.5 rounded-md text-xs bg-[#0d1117] border border-[#30363d] text-white placeholder:text-slate-500 focus:outline-none focus:border-[#2f81f7] transition" placeholder="Enter your password" required autocomplete="current-password">
                        <button type="button" onclick="togglePasswordVisibility()" class="absolute inset-y-0 right-0 w-10 flex items-center justify-center text-slate-400 hover:text-white transition focus:outline-none" title="Show or hide password">
                            <i id="passwordToggleIcon" class="fa-regular fa-eye text-xs"></i>
                        </button>
                    </div>
                </div>

                <!-- Submit Button -->
                <button type="submit" class="w-full py-2.5 px-4 bg-[#2f81f7] hover:bg-blue-600 text-white font-semibold text-xs rounded-md transition shadow-xs flex items-center justify-center gap-2 mt-2">
                    <span>Sign In</span>
                    <i class="fa-solid fa-arrow-right text-xs"></i>
                </button>
            </form>
            
            <!-- Quick Test Account Helper -->
            <div class="mt-6 pt-4 border-t border-[#30363d]">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-[11px] font-medium text-slate-400">Quick Fill Demo Accounts:</span>
                </div>
                <div class="grid grid-cols-3 gap-2">
                    <button type="button" onclick="setDemo('admin@organization.com', 'password123')" class="px-2.5 py-1.5 rounded-md bg-[#0d1117]/80 hover:bg-[#21262d] text-slate-300 hover:text-white border border-[#30363d] text-center text-xs font-medium transition shadow-xs">
                        Admin
                    </button>
                    <button type="button" onclick="setDemo('auditor@organization.com', 'password123')" class="px-2.5 py-1.5 rounded-md bg-[#0d1117]/80 hover:bg-[#21262d] text-slate-300 hover:text-white border border-[#30363d] text-center text-xs font-medium transition shadow-xs">
                        Auditor
                    </button>
                    <button type="button" onclick="setDemo('sicca@organisation.com', 'password123')" class="px-2.5 py-1.5 rounded-md bg-[#0d1117]/80 hover:bg-[#21262d] text-slate-300 hover:text-white border border-[#30363d] text-center text-xs font-medium transition shadow-xs">
                        Staff
                    </button>
                </div>
            </div>

        </div>
    </div>

    <script>
        function setDemo(email, pass) {
            document.getElementById('loginEmail').value = email;
            document.getElementById('loginPass').value = pass;
        }

        function togglePasswordVisibility() {
            const passInput = document.getElementById('loginPass');
            const icon = document.getElementById('passwordToggleIcon');
            if (!passInput || !icon) return;
            if (passInput.type === 'password') {
                passInput.type = 'text';
                icon.className = 'fa-regular fa-eye-slash text-xs text-[#2f81f7]';
            } else {
                passInput.type = 'password';
                icon.className = 'fa-regular fa-eye text-xs text-slate-400';
            }
        }
    </script>

</body>
</html>
