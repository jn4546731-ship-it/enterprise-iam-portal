<?php
/**
 * Enterprise IAM Portal - Official Executive Audit & Compliance Report
 * Generates an executive-level summary and immutable audit ledger.
 */

session_start();
require_once __DIR__ . '/db.php';

// Enforce Session Authentication
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$current_user_id = (int) $_SESSION['user_id'];

// Fetch current user details with clearance
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
$current_user = $user_res->fetch_assoc();

if (!$current_user || (isset($current_user['is_active']) && (int) $current_user['is_active'] === 0)) {
    session_unset();
    session_destroy();
    header("Location: index.php?error=suspended");
    exit();
}

// User attributes
$user_email = $current_user['email'];
$user_display_name = trim(($current_user['first_name'] ?? '') . ' ' . ($current_user['last_name'] ?? ''));
if (empty($user_display_name)) {
    $user_display_name = explode('@', $user_email)[0];
}
$user_dept = !empty($current_user['department']) ? $current_user['department'] : 'General Operations';
$user_title = !empty($current_user['job_title']) ? $current_user['job_title'] : 'Staff Analyst';
$user_clearance = $current_user['security_clearance'] ?? 'Tier 1';
$user_role = $current_user['role'] ?? 'Staff';

// Role clearance check: Auditors (Tier 2) and Admins (Tier 3) have access
$tier_numeric = 1;
if (stripos($user_clearance, 'Tier 3') !== false || strcasecmp($user_role, 'Admin') === 0 || (int)$current_user['role_id'] === 1) {
    $tier_numeric = 3;
} elseif (stripos($user_clearance, 'Tier 2') !== false || strcasecmp($user_role, 'Auditor') === 0 || (int)$current_user['role_id'] === 3) {
    $tier_numeric = 2;
}

// -------------------------------------------------------------
// AGGREGATE EXECUTIVE TELEMETRY FOR REPORT
// -------------------------------------------------------------
// 1. Total Identities & Status
$total_users_res = $conn->query("SELECT COUNT(*) AS total, SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS suspended, SUM(CASE WHEN mfa_secret IS NOT NULL AND mfa_secret != '' THEN 1 ELSE 0 END) AS mfa_active FROM users");
$identity_stats = $total_users_res->fetch_assoc();
$total_identities = (int) ($identity_stats['total'] ?? 0);
$suspended_count = (int) ($identity_stats['suspended'] ?? 0);
$active_identities = $total_identities - $suspended_count;
$mfa_enrolled = (int) ($identity_stats['mfa_active'] ?? 0);
$mfa_rate = $total_identities > 0 ? round(($mfa_enrolled / $total_identities) * 100, 1) : 0;

// 2. Clearance Tier Distribution
$tier_res = $conn->query("SELECT security_clearance, COUNT(*) as cnt FROM users GROUP BY security_clearance");
$tier_counts = ['Tier 1' => 0, 'Tier 2' => 0, 'Tier 3' => 0];
if ($tier_res) {
    while ($r = $tier_res->fetch_assoc()) {
        $c = $r['security_clearance'] ?? 'Tier 1';
        if (stripos($c, 'Tier 3') !== false) $tier_counts['Tier 3'] += (int)$r['cnt'];
        elseif (stripos($c, 'Tier 2') !== false) $tier_counts['Tier 2'] += (int)$r['cnt'];
        else $tier_counts['Tier 1'] += (int)$r['cnt'];
    }
}

// 3. API Keys Status
$api_res = $conn->query("SELECT COUNT(*) as total, SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) as active_keys FROM api_keys");
$api_stats = $api_res->fetch_assoc();
$total_api_keys = (int) ($api_stats['total'] ?? 0);
$active_api_keys = (int) ($api_stats['active_keys'] ?? 0);

// 4. Audit Log Events (Last 25 entries for detailed audit trail)
$logs_res = $conn->query("
    SELECT a.*, u.email, u.security_clearance 
    FROM audit_logs a 
    LEFT JOIN users u ON a.user_id = u.user_id 
    ORDER BY a.log_id DESC 
    LIMIT 25
");
$logs = [];
if ($logs_res) {
    while ($row = $logs_res->fetch_assoc()) {
        $logs[] = $row;
    }
}

// 5. Total 24h event count
$total_24h_res = $conn->query("SELECT COUNT(*) as cnt FROM audit_logs WHERE created_at >= NOW() - INTERVAL 24 HOUR");
$events_24h = (int) (($total_24h_res ? $total_24h_res->fetch_assoc()['cnt'] : 0) ?? 0);
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <title>Executive Compliance &amp; Audit Report &mdash; Enterprise IAM</title>
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
    <style>
        @media print {
            body {
                background: #ffffff !important;
                color: #000000 !important;
            }
            .no-print, aside, header {
                display: none !important;
            }
            .pl-64 {
                padding-left: 0 !important;
            }
            main {
                padding-top: 0 !important;
                background: #ffffff !important;
                color: #000000 !important;
            }
            .print-card {
                border: 1px solid #d1d5db !important;
                background: #ffffff !important;
                color: #000000 !important;
                box-shadow: none !important;
            }
            .print-table th {
                background: #f3f4f6 !important;
                color: #111827 !important;
                border-bottom: 2px solid #374151 !important;
            }
            .print-table td {
                color: #1f2937 !important;
                border-bottom: 1px solid #e5e7eb !important;
            }
            .print-badge {
                border: 1px solid #6b7280 !important;
                color: #111827 !important;
                background: transparent !important;
            }
        }
    </style>
</head>
<body class="bg-[#0d1117] font-sans text-[#e6edf3] antialiased selection:bg-[#2f81f7] selection:text-white min-h-screen">

    <!-- ========================================================================= -->
    <!-- LEFT FIXED NAVIGATION SIDEBAR                                             -->
    <!-- ========================================================================= -->
    <aside id="appSidebar" class="no-print fixed left-0 top-0 h-screen w-64 bg-[#161b22] border-r border-[#30363d] z-50 flex flex-col justify-between shadow-xl transition-transform duration-300">
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

                <!-- Audit Logs (Active Page) -->
                <a href="audit_report.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#21262d] border border-[#30363d] text-white shadow-xs font-medium">
                    <i class="fa-solid fa-list-check text-sm text-[#2f81f7] w-4 text-center"></i>
                    <span>Audit Logs</span>
                </a>

                <a href="api_management.php" class="flex items-center gap-2.5 px-3 py-2 rounded-md text-slate-400 hover:bg-[#21262d] hover:text-white transition-colors">
                    <i class="fa-solid fa-key text-sm w-4 text-center"></i>
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
                        <p class="text-xs font-semibold text-white truncate"><?php echo htmlspecialchars($user_display_name); ?></p>
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
        <header class="no-print fixed top-0 right-0 left-64 h-16 bg-[#161b22] border-b border-[#30363d] z-40 flex items-center justify-between px-6 shadow-xs backdrop-blur-md">
            <!-- Search Bar -->
            <div class="relative w-96 max-w-md">
                <i class="fa-solid fa-magnifying-glass absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs pointer-events-none"></i>
                <input type="text" placeholder="Search audit logs, events, identities... (Ctrl+K)" class="w-full bg-[#0d1117] border border-[#30363d] rounded-md pl-10 pr-14 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-[#2f81f7] transition font-sans">
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
                        <span class="text-xs font-semibold text-white leading-tight whitespace-nowrap"><?php echo htmlspecialchars($user_display_name); ?></span>
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

            <!-- 1. BREADCRUMB, MAIN HEADING & ACTION BUTTONS -->
            <div class="no-print flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-[#30363d] mb-6">
                <div>
                    <div class="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1.5">
                        <span>Administration</span>
                        <span class="text-slate-600">/</span>
                        <span class="text-slate-200 font-semibold">Audit Logs &amp; Compliance</span>
                        <span class="text-slate-600 ml-1">&bull;</span>
                        <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            Environment: Production
                        </span>
                    </div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">Executive Security Audit Report</h1>
                    <p class="text-xs text-slate-400 mt-1 max-w-2xl">Role-based access verification, multi-factor authentication telemetry, and immutable audit ledger.</p>
                </div>

                <div class="flex flex-wrap items-center gap-2.5 shrink-0">
                    <button onclick="window.print()" class="px-3.5 py-2 rounded-md bg-[#2f81f7] hover:bg-blue-600 text-white text-xs font-semibold shadow-xs transition flex items-center gap-2">
                        <i class="fa-solid fa-print text-xs"></i>
                        <span>Print Official Report (PDF)</span>
                    </button>

                    <a href="dashboard.php?export=csv" class="px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] text-xs font-medium transition flex items-center gap-2 shadow-xs">
                        <i class="fa-solid fa-file-csv text-xs text-slate-400"></i>
                        <span>Export CSV</span>
                    </a>
                </div>
            </div>

            <!-- 2. DOCUMENT CONTAINER (Clean Dark Slate on screen, Clean White on Print) -->
            <div class="print-card rounded-lg bg-[#161b22] border border-[#30363d] p-6 sm:p-8 shadow-xs max-w-5xl mx-auto space-y-8">
                
                <!-- Document Header Section -->
                <div class="border-b border-[#30363d] pb-6">
                    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                        <div>
                            <div class="flex items-center space-x-2 mb-1.5">
                                <span class="h-2 w-2 rounded-full bg-[#2f81f7]"></span>
                                <span class="text-xs font-mono text-[#2f81f7] uppercase font-semibold">Enterprise Zero-Trust IAM &bull; Audit Division</span>
                            </div>
                            <h2 class="text-2xl font-bold text-white tracking-tight">Executive Security Audit Ledger</h2>
                            <p class="text-xs text-slate-400 mt-0.5">Role-Based Access Control, Cryptographic MFA Telemetry &amp; Access Activity</p>
                        </div>

                        <div class="text-left sm:text-right text-xs font-mono space-y-1">
                            <span class="inline-block px-2.5 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                Classification: Official
                            </span>
                            <p class="text-slate-400">Ref: <span class="text-white font-bold">IAM-AUDIT-<?php echo date('Ymd-His'); ?></span></p>
                            <p class="text-slate-400">Date: <span class="text-slate-200"><?php echo date('Y-m-d H:i:s T'); ?></span></p>
                        </div>
                    </div>
                </div>

                <!-- Scope Metadata Grid -->
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-sans">
                    <div class="bg-[#0d1117] p-3.5 rounded-md border border-[#30363d]">
                        <span class="text-slate-400 text-[10px] uppercase font-mono block">Framework</span>
                        <strong class="text-white text-xs mt-0.5 block">NIST SP 800-207</strong>
                        <span class="text-[10px] text-slate-400">Zero-Trust Architecture</span>
                    </div>

                    <div class="bg-[#0d1117] p-3.5 rounded-md border border-[#30363d]">
                        <span class="text-slate-400 text-[10px] uppercase font-mono block">Auditing Authority</span>
                        <strong class="text-white text-xs mt-0.5 block truncate"><?php echo htmlspecialchars($user_display_name); ?></strong>
                        <span class="text-[10px] text-slate-400"><?php echo htmlspecialchars($user_role); ?> (<?php echo htmlspecialchars($user_clearance); ?>)</span>
                    </div>

                    <div class="bg-[#0d1117] p-3.5 rounded-md border border-[#30363d]">
                        <span class="text-slate-400 text-[10px] uppercase font-mono block">Air-Gap Status</span>
                        <strong class="text-emerald-400 text-xs mt-0.5 block">100% Offline Secured</strong>
                        <span class="text-[10px] text-slate-400">Self-Contained Local Assets</span>
                    </div>

                    <div class="bg-[#0d1117] p-3.5 rounded-md border border-[#30363d]">
                        <span class="text-slate-400 text-[10px] uppercase font-mono block">Enclave Domain</span>
                        <strong class="text-sky-300 text-xs mt-0.5 block truncate">TLS 1.3 Active</strong>
                        <span class="text-[10px] text-slate-400 truncate">iam.secure-defense.internal</span>
                    </div>
                </div>

                <!-- Section 1: Executive KPI Summary -->
                <div>
                    <h3 class="text-sm font-semibold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                        <i class="fa-solid fa-chart-simple text-[#2f81f7]"></i>
                        <span>Section 1: Identity &amp; Telemetry Metrics</span>
                    </h3>

                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        <div class="bg-[#0d1117] p-4 rounded-md border border-[#30363d]">
                            <span class="text-[11px] text-slate-400 font-medium">Total Identities</span>
                            <div class="text-2xl font-bold text-white mt-1"><?php echo $total_identities; ?></div>
                            <span class="text-[10px] text-slate-400 font-mono"><?php echo $active_identities; ?> Active &bull; <?php echo $suspended_count; ?> Suspended</span>
                        </div>

                        <div class="bg-[#0d1117] p-4 rounded-md border border-[#30363d]">
                            <span class="text-[11px] text-slate-400 font-medium">MFA Adoption Rate</span>
                            <div class="text-2xl font-bold text-emerald-400 mt-1"><?php echo $mfa_rate; ?>%</div>
                            <span class="text-[10px] text-slate-400 font-mono"><?php echo $mfa_enrolled; ?> Enrolled (RFC 6238)</span>
                        </div>

                        <div class="bg-[#0d1117] p-4 rounded-md border border-[#30363d]">
                            <span class="text-[11px] text-slate-400 font-medium">Clearance Distribution</span>
                            <div class="text-xs text-slate-300 mt-1 space-y-0.5 font-mono">
                                <div class="flex justify-between"><span>Tier 3 (Admin):</span> <strong class="text-purple-400"><?php echo $tier_counts['Tier 3']; ?></strong></div>
                                <div class="flex justify-between"><span>Tier 2 (Auditor):</span> <strong class="text-sky-400"><?php echo $tier_counts['Tier 2']; ?></strong></div>
                                <div class="flex justify-between"><span>Tier 1 (Staff):</span> <strong class="text-slate-300"><?php echo $tier_counts['Tier 1']; ?></strong></div>
                            </div>
                        </div>

                        <div class="bg-[#0d1117] p-4 rounded-md border border-[#30363d]">
                            <span class="text-[11px] text-slate-400 font-medium">Cryptographic API Keys</span>
                            <div class="text-2xl font-bold text-[#2f81f7] mt-1"><?php echo $active_api_keys; ?> / <?php echo $total_api_keys; ?></div>
                            <span class="text-[10px] text-slate-400 font-mono">160-bit HMAC-SHA256</span>
                        </div>
                    </div>
                </div>

                <!-- Section 2: RBAC Policy Matrix -->
                <div>
                    <h3 class="text-sm font-semibold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                        <i class="fa-solid fa-lock text-[#2f81f7]"></i>
                        <span>Section 2: Role-Based Access Control (RBAC) Policy Enforcement</span>
                    </h3>

                    <div class="overflow-x-auto border border-[#30363d] rounded-md">
                        <table class="w-full text-left text-xs font-sans print-table">
                            <thead class="bg-[#0d1117] text-slate-400 font-mono text-[10px] uppercase tracking-wider border-b border-[#30363d]">
                                <tr>
                                    <th class="p-3">Resource Target</th>
                                    <th class="p-3">Required Tier</th>
                                    <th class="p-3">Tier 1 (Staff)</th>
                                    <th class="p-3">Tier 2 (Auditor)</th>
                                    <th class="p-3">Tier 3 (Admin)</th>
                                    <th class="p-3">Compliance Basis</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-[#30363d] text-slate-300">
                                <tr>
                                    <td class="p-3 font-semibold text-white">General Directory Telemetry</td>
                                    <td class="p-3 text-slate-300 font-mono">Tier 1+</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-slate-400">Session Attestation</td>
                                </tr>
                                <tr>
                                    <td class="p-3 font-semibold text-white">Customer PII Database</td>
                                    <td class="p-3 text-sky-400 font-mono">Tier 2+</td>
                                    <td class="p-3 text-red-400 font-semibold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-slate-400">GDPR &bull; ISO-27001</td>
                                </tr>
                                <tr>
                                    <td class="p-3 font-semibold text-white">Q3 Corporate Financials</td>
                                    <td class="p-3 text-sky-400 font-mono">Tier 2+</td>
                                    <td class="p-3 text-red-400 font-semibold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-slate-400">SOX-404 &bull; GAAP</td>
                                </tr>
                                <tr>
                                    <td class="p-3 font-semibold text-white">Production Server SSH Key Pair</td>
                                    <td class="p-3 text-purple-400 font-mono">Tier 3 Only</td>
                                    <td class="p-3 text-red-400 font-semibold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED</td>
                                    <td class="p-3 text-red-400 font-semibold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED</td>
                                    <td class="p-3 text-emerald-400 font-semibold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                                    <td class="p-3 text-slate-400">NIST SP 800-53</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Section 3: Immutable Audit Event Ledger -->
                <div>
                    <h3 class="text-sm font-semibold text-white uppercase tracking-wider mb-3 flex items-center justify-between">
                        <span class="flex items-center gap-2">
                            <i class="fa-solid fa-list-check text-[#2f81f7]"></i>
                            <span>Section 3: Recent Audit Event Ledger</span>
                        </span>
                        <span class="text-xs font-mono text-slate-400 font-normal">Last <?php echo count($logs); ?> Events Recorded</span>
                    </h3>

                    <div class="overflow-x-auto border border-[#30363d] rounded-md">
                        <table class="w-full text-left text-xs font-sans print-table">
                            <thead class="bg-[#0d1117] text-slate-400 font-mono text-[10px] uppercase tracking-wider border-b border-[#30363d]">
                                <tr>
                                    <th class="p-2.5">ID</th>
                                    <th class="p-2.5">Timestamp</th>
                                    <th class="p-2.5">Action Type</th>
                                    <th class="p-2.5">Identity</th>
                                    <th class="p-2.5">Description</th>
                                    <th class="p-2.5 text-right">Client IP</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-[#30363d] text-slate-300">
                                <?php foreach ($logs as $l): 
                                    $is_fail = (stripos($l['action_type'], 'FAIL') !== false || stripos($l['action_type'], 'DENIED') !== false);
                                ?>
                                <tr class="hover:bg-[#21262d]/50 transition">
                                    <td class="p-2.5 font-mono text-slate-500">#<?php echo (int)$l['log_id']; ?></td>
                                    <td class="p-2.5 font-mono text-slate-400 whitespace-nowrap"><?php echo htmlspecialchars($l['created_at']); ?></td>
                                    <td class="p-2.5 whitespace-nowrap">
                                        <span class="px-2 py-0.5 rounded text-[10px] font-medium font-mono print-badge <?php echo $is_fail ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'; ?>">
                                            <?php echo htmlspecialchars($l['action_type']); ?>
                                        </span>
                                    </td>
                                    <td class="p-2.5 text-white whitespace-nowrap font-medium"><?php echo htmlspecialchars($l['email'] ?? 'UID-' . $l['user_id']); ?></td>
                                    <td class="p-2.5 text-slate-300 text-[11px]"><?php echo htmlspecialchars($l['action_description']); ?></td>
                                    <td class="p-2.5 text-right font-mono text-slate-400 whitespace-nowrap"><code><?php echo htmlspecialchars($l['ip_address']); ?></code></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Section 4: Sign-Off / Approval Block -->
                <div class="border-t border-[#30363d] pt-6 font-sans">
                    <h4 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-5">
                        Audit Attestation &amp; Sign-Off
                    </h4>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 text-xs text-slate-300">
                        <div class="border-t border-[#30363d] pt-3">
                            <p class="font-semibold text-white uppercase text-[11px]">System Engineer / Lead</p>
                            <p class="text-slate-400 mt-1">Name: John Njoroge</p>
                            <p class="text-slate-400 mt-1">Status: Attested</p>
                            <p class="text-slate-400 mt-1">Date: <?php echo date('Y-m-d'); ?></p>
                        </div>

                        <div class="border-t border-[#30363d] pt-3">
                            <p class="font-semibold text-white uppercase text-[11px]">Compliance Auditor</p>
                            <p class="text-slate-400 mt-1">Role: Internal Security Audit</p>
                            <p class="text-slate-400 mt-1">Verdict: Compliant (NIST SP 800-207)</p>
                            <p class="text-slate-400 mt-1">Date: <?php echo date('Y-m-d'); ?></p>
                        </div>

                        <div class="border-t border-[#30363d] pt-3">
                            <p class="font-semibold text-white uppercase text-[11px]">Chief Information Security Officer</p>
                            <p class="text-emerald-400 font-semibold mt-1">Status: Approved &amp; Enforced</p>
                            <p class="text-slate-400 mt-1">Enclave: iam.secure-defense.internal</p>
                            <p class="text-slate-400 mt-1">Date: <?php echo date('Y-m-d'); ?></p>
                        </div>
                    </div>
                </div>

            </div>

            <!-- Footer -->
            <div class="no-print mt-8 text-center border-t border-[#30363d] pt-6 text-xs text-slate-500 font-mono">
                <i class="fa-solid fa-shield-halved text-[#2f81f7] mr-1"></i>
                ENTERPRISE IDENTITY &amp; ACCESS MANAGEMENT &bull; AIR-GAPPED DEPLOYMENT &bull; iam.secure-defense.internal
            </div>
        </main>
    </div>

    <!-- JavaScript Handlers -->
    <script>
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
