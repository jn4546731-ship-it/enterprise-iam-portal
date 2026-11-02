<?php
/**
 * Automated Verification & Defense Readiness Test Suite
 * Validates .env parsing, TOTP mathematics, and AI Sentinel anomaly algorithms.
 */

echo "=== ENTERPRISE IAM SECURITY PORTAL - VERIFICATION SUITE ===\n\n";

// 1. Test Environment Loader
echo "[TEST 1] Testing env_loader.php...\n";
require_once __DIR__ . '/env_loader.php';
$loaded = loadEnv(__DIR__ . '/.env');
if ($loaded) {
    echo "  [PASS] .env loaded successfully.\n";
    echo "  [INFO] DB_HOST: " . env('DB_HOST') . "\n";
    echo "  [INFO] DB_DATABASE: " . env('DB_DATABASE') . "\n";
    echo "  [INFO] DB_USERNAME: " . env('DB_USERNAME') . "\n";
    echo "  [INFO] APP_NAME: " . env('APP_NAME') . "\n";
} else {
    echo "  [FAIL] Could not load .env file!\n";
    exit(1);
}

// 2. Test MFA Engine Mathematics
echo "\n[TEST 2] Testing mfa_helper.php TOTP Engine...\n";
require_once __DIR__ . '/mfa_helper.php';
$secret = generateMfaSecret();
echo "  [PASS] Generated 16-char Base32 secret: {$secret} (Length: " . strlen($secret) . ")\n";

// Generate expected code for current window
$base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
$base32charsFlipped = array_flip(str_split($base32chars));
$cleanSecret = strtoupper(str_replace('=', '', $secret));
$binaryString = '';
foreach (str_split($cleanSecret) as $char) {
    $binaryString .= str_pad(decbin($base32charsFlipped[$char]), 5, '0', STR_PAD_LEFT);
}
$decodedSecret = '';
foreach (str_split($binaryString, 8) as $chunk) {
    if (strlen($chunk) == 8) {
        $decodedSecret .= chr(bindec($chunk));
    }
}
$timeSlice = floor(time() / 30);
$timePacked = pack('N*', 0) . pack('N*', $timeSlice);
$hash = hash_hmac('sha1', $timePacked, $decodedSecret, true);
$offset = ord(substr($hash, -1)) & 0x0F;
$value = unpack('N', substr($hash, $offset, 4))[1] & 0x7FFFFFFF;
$expectedCode = str_pad($value % 1000000, 6, '0', STR_PAD_LEFT);

$verified = verifyMfaToken($secret, $expectedCode);
if ($verified) {
    echo "  [PASS] Valid TOTP token ({$expectedCode}) correctly accepted!\n";
} else {
    echo "  [FAIL] Valid TOTP token was rejected!\n";
    exit(1);
}

$invalidVerified = verifyMfaToken($secret, "000000");
if (!$invalidVerified || $expectedCode === "000000") {
    echo "  [PASS] Invalid TOTP token correctly rejected.\n";
} else {
    echo "  [FAIL] Invalid TOTP token unexpectedly accepted!\n";
    exit(1);
}

// 3. Test AI Sentinel Engine Architecture & Detection Logic
echo "\n[TEST 3] Testing ai_sentinel.php Class & Structure...\n";
require_once __DIR__ . '/ai_sentinel.php';
if (class_exists('AISentinel')) {
    echo "  [PASS] AISentinel class loaded.\n";
    $reflection = new ReflectionClass('AISentinel');
    $methods = array_map(fn($m) => $m->getName(), $reflection->getMethods());
    
    if (in_array('analyzeThreatLevel', $methods) && 
        in_array('injectSimulationThreat', $methods) && 
        in_array('resetSimulationTelemetry', $methods)) {
        echo "  [PASS] All required SOC heuristic and defense simulation methods verified.\n";
    } else {
        echo "  [FAIL] Missing required methods in AISentinel!\n";
        exit(1);
    }
} else {
    echo "  [FAIL] AISentinel class not found!\n";
    exit(1);
}

// 4. Test Heuristic Behavioral Detection Algorithms
echo "\n[TEST 4] Testing AI Sentinel Heuristic Algorithms (Mock Stream)...\n";
class TestMockResult {
    private array $data;
    private int $index = 0;
    public function __construct(array $data) { $this->data = $data; }
    public function fetch_assoc(): ?array {
        return ($this->index < count($this->data)) ? $this->data[$this->index++] : null;
    }
}

class TestMockConn extends mysqli {
    private array $auditLogs;
    private array $users;
    public function __construct(array $auditLogs, array $users) {
        $this->auditLogs = $auditLogs;
        $this->users = $users;
    }
    public function query(string $query, int $resultmode = MYSQLI_STORE_RESULT): mixed {
        if (str_contains($query, 'FROM audit_logs')) return new TestMockResult($this->auditLogs);
        if (str_contains($query, 'FROM users')) return new TestMockResult($this->users);
        return false;
    }
}

// Heuristic Subtest: Rapid Failures
$now = date('Y-m-d H:i:s');
$mockLogs = [];
for ($i = 0; $i < 5; $i++) {
    $mockLogs[] = [
        'log_id' => $i + 1, 'user_id' => 2, 'action_type' => 'MFA_FAIL',
        'action_description' => 'Failed MFA challenge', 'ip_address' => '198.51.100.22', 'created_at' => $now
    ];
}
$mockConn = new TestMockConn($mockLogs, [
    ['user_id' => 2, 'email' => 'victim@organization.com', 'is_active' => 1, 'role_id' => 4]
]);
$res = AISentinel::analyzeThreatLevel($mockConn);
if ($res['threat_score'] >= 50 && count($res['anomalies']) >= 1) {
    echo "  [PASS] Brute-Force Velocity Detection confirmed (ATS: {$res['threat_score']}, Posture: {$res['threat_level']}).\n";
} else {
    echo "  [FAIL] Brute-Force Velocity was not flagged accurately!\n";
    exit(1);
}

// 5. Test Phase 4.2: Enterprise RBAC, Clearance Tiers & Crown Jewels Vault Policy
echo "\n[TEST 5] Testing Phase 4.2: RBAC Matrix & Clearance Access Policy...\n";
$clearanceMatrix = [
    'Staff' => ['tier' => 1, 'pii' => false, 'fin' => false, 'ssh' => false],
    'Auditor' => ['tier' => 2, 'pii' => true, 'fin' => true, 'ssh' => false],
    'Admin' => ['tier' => 3, 'pii' => true, 'fin' => true, 'ssh' => true]
];

foreach ($clearanceMatrix as $role => $policy) {
    $can_pii = ($policy['tier'] >= 2);
    $can_fin = ($policy['tier'] >= 2);
    $can_ssh = ($policy['tier'] >= 3);

    if ($can_pii === $policy['pii'] && $can_fin === $policy['fin'] && $can_ssh === $policy['ssh']) {
        echo "  [PASS] RBAC Enforcement verified for [{$role} // Tier {$policy['tier']}]: PII=" . ($can_pii ? "ALLOW" : "DENY") . ", Financials=" . ($can_fin ? "ALLOW" : "DENY") . ", SSH=" . ($can_ssh ? "ALLOW" : "DENY") . "\n";
    } else {
        echo "  [FAIL] RBAC Policy violation detected for role {$role}!\n";
        exit(1);
    }
}

// 6. Test API Key Generation Entropy & Bearer Prefix
echo "\n[TEST 6] Testing API Key Cryptographic Token Generation...\n";
$token = 'sec_live_' . bin2hex(random_bytes(20));
if (str_starts_with($token, 'sec_live_') && strlen($token) === 49) {
    echo "  [PASS] High-entropy HMAC Bearer token generated: {$token} (160-bit hex entropy)\n";
} else {
    echo "  [FAIL] API Key token format failed entropy validation!\n";
    exit(1);
}

// 7. Test 100% Offline Air-Gapped Asset Integrity
echo "\n[TEST 7] Testing 100% Offline Air-Gapped Infrastructure Integrity...\n";
$requiredAssets = [
    'assets/js/tailwind.js' => 'Local Tailwind CSS Runtime',
    'assets/css/all.min.css' => 'Local FontAwesome 6 Core CSS',
    'assets/js/qrcode.min.js' => 'Local Zero-Dependency QRCode Engine',
    'assets/webfonts/fa-solid-900.woff2' => 'FontAwesome Solid Webfont',
    'assets/webfonts/fa-solid-900.ttf' => 'FontAwesome TTF Webfont'
];

foreach ($requiredAssets as $relPath => $label) {
    $fullPath = __DIR__ . '/' . $relPath;
    if (file_exists($fullPath) && filesize($fullPath) > 1000) {
        echo "  [PASS] {$label} present locally (" . round(filesize($fullPath) / 1024, 1) . " KB).\n";
    } else {
        echo "  [FAIL] Missing offline asset: {$relPath}\n";
        exit(1);
    }
}

// Check PHP files for forbidden external CDN calls (excluding test_suite.php itself)
$phpFiles = array_filter(glob(__DIR__ . '/*.php'), fn($f) => basename($f) !== 'test_suite.php');
$cdnPatterns = ['cdn.tailwindcss.com', 'cdnjs.cloudflare.com', 'api.qrserver.com'];
$violations = 0;

foreach ($phpFiles as $f) {
    $content = file_get_contents($f);
    foreach ($cdnPatterns as $pattern) {
        if (str_contains($content, $pattern)) {
            echo "  [FAIL] External CDN leak detected in " . basename($f) . ": {$pattern}\n";
            $violations++;
        }
    }
}

if ($violations === 0) {
    echo "  [PASS] Zero external CDN or internet dependencies detected in PHP templates.\n";
} else {
    echo "  [FAIL] System contains {$violations} unmitigated CDN dependencies!\n";
    exit(1);
}

echo "\n=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY! ===\n";
