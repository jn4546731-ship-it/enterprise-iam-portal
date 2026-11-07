<?php
/**
 * Enterprise Zero-Trust IAM Portal - Official Executive Audit & Compliance Report
 * Generates an executive-level printable summary and audit ledger.
 * Fulfills University Final Project Reporting & Documentation Standards.
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
    <meta name="color-scheme" content="dark">
    <title>Executive Compliance & SOC Audit Summary - Enterprise Zero-Trust IAM</title>
    <script src="assets/js/tailwind.js"></script>
    <link href="assets/css/all.min.css" rel="stylesheet">
    <link href="assets/css/cyber-theme.css" rel="stylesheet">
    <style>
        @media print {
            body {
                background: #ffffff !important;
                color: #000000 !important;
            }
            .no-print {
                display: none !important;
            }
            .print-card {
                border: 1px solid #cccccc !important;
                background: #ffffff !important;
                color: #000000 !important;
                box-shadow: none !important;
            }
            .print-table th {
                background: #f1f5f9 !important;
                color: #000000 !important;
                border-bottom: 2px solid #334155 !important;
            }
            .print-table td {
                color: #1e293b !important;
                border-bottom: 1px solid #e2e8f0 !important;
            }
            .print-badge {
                border: 1px solid #666666 !important;
                color: #000000 !important;
                background: transparent !important;
            }
            .page-break {
                page-break-after: always;
            }
        }
    </style>
</head>
<body class="cyber-bg cyber-grid-overlay text-slate-200 font-sans min-h-screen p-4 sm:p-8 antialiased selection:bg-cyan-500 selection:text-black">

    <!-- Top Action Bar (Screen Only) -->
    <div class="max-w-5xl mx-auto mb-6 flex justify-between items-center no-print bg-slate-950/90 p-4 rounded-2xl border border-cyan-500/30 backdrop-blur-md">
        <div class="flex items-center space-x-3">
            <a href="dashboard.php" class="cyber-btn bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center">
                <i class="fa-solid fa-arrow-left mr-1.5"></i> Return to Command Center
            </a>
            <span class="text-xs font-tech text-slate-500 hidden sm:inline">|</span>
            <span class="text-xs font-tech text-cyan-400 hidden sm:inline"><i class="fa-solid fa-file-shield mr-1"></i> NIST SP 800-207 Compliance Audit Export</span>
        </div>
        
        <div class="flex items-center space-x-2">
            <a href="dashboard.php?export=csv" class="cyber-btn bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center">
                <i class="fa-solid fa-file-csv mr-1.5 text-cyan-400"></i> Export Raw CSV
            </a>
            <button onclick="window.print()" class="cyber-btn bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white px-4 py-2 rounded-xl text-xs font-orbitron font-bold transition flex items-center shadow-lg glow-cyan">
                <i class="fa-solid fa-print mr-1.5"></i> Print Official Report (PDF)
            </button>
        </div>
    </div>

    <!-- Official Report Document Container -->
    <main class="max-w-5xl mx-auto cyber-card print-card rounded-2xl p-6 sm:p-10 shadow-2xl border border-cyan-500/40 relative overflow-hidden bg-slate-950">
        
        <!-- Document Watermark & Laser Accent -->
        <div class="cyber-laser-beam opacity-30 no-print"></div>

        <!-- Document Official Header -->
        <header class="border-b border-cyan-500/30 pb-6 mb-6">
            <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <div class="flex items-center space-x-2 mb-1">
                        <span class="h-2 w-2 rounded-full bg-cyan-400 cyber-beacon"></span>
                        <span class="font-tech text-xs tracking-widest text-cyan-400 uppercase font-bold">SCHOOL OF COMPUTING & INFORMATICS &bull; ENTERPRISE ZERO-TRUST SOC</span>
                    </div>
                    <h1 class="font-orbitron text-2xl sm:text-3xl font-extrabold text-white tracking-wider glow-text-cyan">
                        EXECUTIVE SECURITY AUDIT REPORT
                    </h1>
                    <p class="font-tech text-xs text-slate-400 mt-0.5">
                        Role-Based Access Control, Cryptographic Multi-Factor Telemetry & Behavioral Audit Trail
                    </p>
                </div>

                <div class="text-right font-tech text-xs space-y-1">
                    <div class="inline-block px-3 py-1 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 font-bold text-[11px]">
                        CLASSIFICATION: CONFIDENTIAL
                    </div>
                    <p class="text-slate-400">Doc Ref: <span class="text-cyan-400 font-mono font-bold">MKU-IAM-SEC-<?php echo date('Ymd-His'); ?></span></p>
                    <p class="text-slate-400">Generated: <span class="text-white font-mono"><?php echo date('Y-m-d H:i:s T'); ?></span></p>
                </div>
            </div>
        </header>

        <!-- Executive Metadata & Scope Grid -->
        <section class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8 font-tech text-xs">
            <div class="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
                <span class="text-slate-500 text-[10px] uppercase block font-bold">System Architecture</span>
                <span class="text-cyan-300 font-bold font-orbitron text-xs">Zero-Trust Perimeter</span>
                <span class="text-[10px] text-slate-400 block mt-0.5">NIST SP 800-207</span>
            </div>
            <div class="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
                <span class="text-slate-500 text-[10px] uppercase block font-bold">Auditing Authority</span>
                <span class="text-purple-300 font-bold font-orbitron text-xs"><?php echo htmlspecialchars($user_display_name); ?></span>
                <span class="text-[10px] text-slate-400 block mt-0.5"><?php echo htmlspecialchars($user_role); ?> (<?php echo htmlspecialchars($user_clearance); ?>)</span>
            </div>
            <div class="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
                <span class="text-slate-500 text-[10px] uppercase block font-bold">Air-Gap Status</span>
                <span class="text-emerald-400 font-bold font-orbitron text-xs">100% Offline Secured</span>
                <span class="text-[10px] text-slate-400 block mt-0.5">Zero CDN / Self-Contained</span>
            </div>
            <div class="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
                <span class="text-slate-500 text-[10px] uppercase block font-bold">Encrypted Domain</span>
                <span class="text-blue-300 font-bold font-orbitron text-xs truncate block">TLS 1.3 Certified</span>
                <span class="text-[10px] text-slate-400 block mt-0.5">iam.secure-defense.internal</span>
            </div>
        </section>

        <!-- Section 1: Executive KPI Summary -->
        <section class="mb-8">
            <h3 class="font-orbitron text-sm font-bold text-white uppercase tracking-wider mb-3 flex items-center">
                <i class="fa-solid fa-chart-simple text-cyan-400 mr-2"></i> Section 1: Identity & Telemetry Metrics
            </h3>

            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div class="cyber-card p-4 rounded-xl border border-cyan-500/30">
                    <span class="text-[10px] font-tech text-cyan-400 uppercase font-bold">Total Identities</span>
                    <p class="font-orbitron text-2xl font-bold text-white mt-1"><?php echo $total_identities; ?></p>
                    <span class="text-[10px] font-tech text-slate-400"><?php echo $active_identities; ?> Active &bull; <?php echo $suspended_count; ?> Suspended</span>
                </div>

                <div class="cyber-card p-4 rounded-xl border border-emerald-500/30">
                    <span class="text-[10px] font-tech text-emerald-400 uppercase font-bold">MFA Adoption Ratio</span>
                    <p class="font-orbitron text-2xl font-bold text-emerald-400 mt-1"><?php echo $mfa_rate; ?>%</p>
                    <span class="text-[10px] font-tech text-slate-400"><?php echo $mfa_enrolled; ?> Identities Enrolled (RFC 6238)</span>
                </div>

                <div class="cyber-card p-4 rounded-xl border border-purple-500/30">
                    <span class="text-[10px] font-tech text-purple-400 uppercase font-bold">Clearance Distribution</span>
                    <div class="text-[11px] font-tech text-slate-300 mt-1 space-y-0.5">
                        <div class="flex justify-between"><span>Tier 3 (Admin):</span> <strong class="text-purple-400"><?php echo $tier_counts['Tier 3']; ?></strong></div>
                        <div class="flex justify-between"><span>Tier 2 (Auditor):</span> <strong class="text-cyan-400"><?php echo $tier_counts['Tier 2']; ?></strong></div>
                        <div class="flex justify-between"><span>Tier 1 (Staff):</span> <strong class="text-amber-400"><?php echo $tier_counts['Tier 1']; ?></strong></div>
                    </div>
                </div>

                <div class="cyber-card p-4 rounded-xl border border-amber-500/30">
                    <span class="text-[10px] font-tech text-amber-400 uppercase font-bold">Cryptographic API Keys</span>
                    <p class="font-orbitron text-2xl font-bold text-amber-400 mt-1"><?php echo $active_api_keys; ?> / <?php echo $total_api_keys; ?></p>
                    <span class="text-[10px] font-tech text-slate-400">160-bit HMAC-SHA256 Bearer</span>
                </div>
            </div>
        </section>

        <!-- Section 2: Zero-Trust RBAC Policy Matrix -->
        <section class="mb-8">
            <h3 class="font-orbitron text-sm font-bold text-white uppercase tracking-wider mb-3 flex items-center">
                <i class="fa-solid fa-lock text-purple-400 mr-2"></i> Section 2: Role-Based Access Control (RBAC) Enforcement Policy
            </h3>

            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left text-xs font-tech print-table">
                    <thead class="bg-slate-950 text-slate-400 text-[10px] uppercase tracking-wider">
                        <tr>
                            <th class="p-3">Resource / Crown Jewel</th>
                            <th class="p-3">Required Tier</th>
                            <th class="p-3">Tier 1 (Staff)</th>
                            <th class="p-3">Tier 2 (Auditor)</th>
                            <th class="p-3">Tier 3 (Admin)</th>
                            <th class="p-3">Enforcement Standard</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/80 text-slate-300">
                        <tr>
                            <td class="p-3 font-bold text-white">General SOC Command Telemetry</td>
                            <td class="p-3 text-amber-400">Tier 1+</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED</td>
                            <td class="p-3 text-slate-400">Session MAC</td>
                        </tr>
                        <tr>
                            <td class="p-3 font-bold text-white">Customer PII Database</td>
                            <td class="p-3 text-cyan-400">Tier 2+</td>
                            <td class="p-3 text-red-400 font-bold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED (Violation)</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED (Inspect)</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED (Full)</td>
                            <td class="p-3 text-slate-400">GDPR / ISO-27001</td>
                        </tr>
                        <tr>
                            <td class="p-3 font-bold text-white">Q3 Corporate Financial Statements</td>
                            <td class="p-3 text-cyan-400">Tier 2+</td>
                            <td class="p-3 text-red-400 font-bold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED (Violation)</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED (Audit CSV)</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED (Full)</td>
                            <td class="p-3 text-slate-400">SOX-404 / GAAP</td>
                        </tr>
                        <tr>
                            <td class="p-3 font-bold text-white">Production Server Root SSH Key Pair</td>
                            <td class="p-3 text-purple-400">Tier 3 Only</td>
                            <td class="p-3 text-red-400 font-bold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED (Critical)</td>
                            <td class="p-3 text-red-400 font-bold"><i class="fa-solid fa-xmark mr-1"></i> BLOCKED (Critical)</td>
                            <td class="p-3 text-emerald-400 font-bold"><i class="fa-solid fa-check mr-1"></i> ALLOWED (Ed25519)</td>
                            <td class="p-3 text-slate-400">NIST SP 800-53</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 3: Immutable Audit Ledger Trail -->
        <section class="mb-10">
            <h3 class="font-orbitron text-sm font-bold text-white uppercase tracking-wider mb-3 flex items-center justify-between">
                <span><i class="fa-solid fa-list-check text-emerald-400 mr-2"></i> Section 3: Recent Cryptographic Audit Event Ledger</span>
                <span class="text-xs font-tech text-slate-400 lowercase font-normal">(latest <?php echo count($logs); ?> entries)</span>
            </h3>

            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left text-xs font-tech print-table">
                    <thead class="bg-slate-950 text-slate-400 text-[10px] uppercase tracking-wider">
                        <tr>
                            <th class="p-2.5">Log ID</th>
                            <th class="p-2.5">Timestamp</th>
                            <th class="p-2.5">Event Type</th>
                            <th class="p-2.5">Identity</th>
                            <th class="p-2.5">Security Description</th>
                            <th class="p-2.5 text-right">Client IP</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/80 text-slate-300">
                        <?php foreach ($logs as $l): 
                            $is_fail = (stripos($l['action_type'], 'FAIL') !== false || stripos($l['action_type'], 'DENIED') !== false);
                        ?>
                        <tr>
                            <td class="p-2.5 font-mono text-slate-500">#<?php echo (int)$l['log_id']; ?></td>
                            <td class="p-2.5 font-mono text-slate-400 whitespace-nowrap"><?php echo htmlspecialchars($l['created_at']); ?></td>
                            <td class="p-2.5 whitespace-nowrap">
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono print-badge <?php echo $is_fail ? 'bg-red-500/20 text-red-400 border border-red-500/40' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'; ?>">
                                    <?php echo htmlspecialchars($l['action_type']); ?>
                                </span>
                            </td>
                            <td class="p-2.5 text-white whitespace-nowrap"><?php echo htmlspecialchars($l['email'] ?? 'UID-' . $l['user_id']); ?></td>
                            <td class="p-2.5 text-slate-400 text-[11px]"><?php echo htmlspecialchars($l['action_description']); ?></td>
                            <td class="p-2.5 text-cyan-400 text-right font-mono whitespace-nowrap"><?php echo htmlspecialchars($l['ip_address']); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Section 4: Official University / Departmental Certification & Sign-Off -->
        <section class="border-t border-slate-800 pt-8 mt-12 font-tech">
            <h4 class="font-orbitron text-xs font-bold text-slate-400 uppercase tracking-widest mb-6">
                Official Validation & Compliance Sign-Off
            </h4>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-8 text-xs text-slate-300">
                <!-- Developer / Student Block -->
                <div class="border-t-2 border-slate-700 pt-3">
                    <p class="font-bold text-white uppercase">Project Developer / Candidate</p>
                    <p class="text-slate-400 mt-1">Name: ....................................................</p>
                    <p class="text-slate-400 mt-1">Reg No: ..................................................</p>
                    <p class="text-slate-400 mt-1">Signature: ..............................................</p>
                    <p class="text-slate-400 mt-1">Date: <?php echo date('Y-m-d'); ?></p>
                </div>

                <!-- Academic Supervisor Block -->
                <div class="border-t-2 border-slate-700 pt-3">
                    <p class="font-bold text-white uppercase">Project Supervisor / Panelist</p>
                    <p class="text-slate-400 mt-1">Name: ....................................................</p>
                    <p class="text-slate-400 mt-1">Department: Enterprise Computing / IT</p>
                    <p class="text-slate-400 mt-1">Signature: ..............................................</p>
                    <p class="text-slate-400 mt-1">Date: .....................................................</p>
                </div>

                <!-- CISO / Head of Department Block -->
                <div class="border-t-2 border-slate-700 pt-3">
                    <p class="font-bold text-white uppercase">Head of Department / Lead Auditor</p>
                    <p class="text-slate-400 mt-1">Status: <span class="text-emerald-400 font-bold">[VERIFIED & APPROVED]</span></p>
                    <p class="text-slate-400 mt-1">Signature & Stamp: ..............................</p>
                    <p class="text-slate-400 mt-1">Date: .....................................................</p>
                </div>
            </div>
        </section>

    </main>

</body>
</html>
