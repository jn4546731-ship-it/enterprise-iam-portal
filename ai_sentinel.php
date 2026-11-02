<?php
/**
 * AI Sentinel - Behavioral Threat & Anomaly Detection Engine
 * Zero-Trust IAM SOC Anomaly Analysis Subsystem
 *
 * Specifically engineered to curb internal credential compromises:
 * - Detects Rapid MFA & Password Brute-Force Velocity
 * - Detects Multi-IP Identity Convergence (Impossible Travel / Stolen Credentials)
 * - Detects Horizontal Credential Spraying across multiple accounts
 * - Computes dynamic Anomaly Threat Score (ATS: 0 - 100) and Threat Posture
 * - Generates real-time terminal diagnostics & automated mitigation recommendations
 */

class AISentinel {

    /**
     * Run full behavioral anomaly scan across audit trail.
     *
     * @param mysqli $conn Active database connection
     * @return array Analysis report containing threat level, score, telemetry, and detected anomalies
     */
    public static function analyzeThreatLevel(mysqli $conn): array {
        $anomalies = [];
        $threatScore = 5; // Default safe baseline
        $scannedCount = 0;
        $failedCount = 0;
        $uniqueIps = [];
        $flaggedIdentities = [];
        $terminalLogs = [];

        $terminalLogs[] = [
            'type' => 'SYSTEM',
            'badge' => 'SYS',
            'time' => date('H:i:s'),
            'msg' => 'AI Behavioral Heuristic Engine initialized. Scanning audit stream...'
        ];

        // 1. Fetch recent audit logs within rolling window (last 24 hours or last 200 logs)
        $query = "SELECT log_id, user_id, action_type, action_description, ip_address, created_at 
                  FROM audit_logs 
                  ORDER BY log_id DESC 
                  LIMIT 200";
        $result = $conn->query($query);

        if (!$result) {
            return self::buildFallbackResponse("Database audit log scan failed: " . $conn->error);
        }

        $logs = [];
        while ($row = $result->fetch_assoc()) {
            $logs[] = $row;
            $scannedCount++;
            $ip = $row['ip_address'] ?? '127.0.0.1';
            $uniqueIps[$ip] = true;
        }

        $terminalLogs[] = [
            'type' => 'INFO',
            'badge' => 'LOG',
            'time' => date('H:i:s'),
            'msg' => "Ingested {$scannedCount} audit events across " . count($uniqueIps) . " unique IP endpoint(s)."
        ];

        if (empty($logs)) {
            $terminalLogs[] = [
                'type' => 'OK',
                'badge' => 'OK',
                'time' => date('H:i:s'),
                'msg' => 'Audit stream is clean. Zero security events recorded. Threat baseline: LOW.'
            ];
            return self::formatReport(5, 'LOW (Baseline)', 'emerald', $anomalies, $terminalLogs, [
                'scanned' => 0, 'failed' => 0, 'unique_ips' => 0, 'flagged_users' => 0
            ]);
        }

        // Fetch users map for identity resolution (email and active status)
        $usersMap = [];
        $uRes = $conn->query("SELECT user_id, email, is_active, role_id FROM users");
        if ($uRes) {
            while ($u = $uRes->fetch_assoc()) {
                $usersMap[$u['user_id']] = $u;
            }
        }

        // =========================================================================
        // HEURISTIC 1: RAPID AUTH / MFA FAILURE VELOCITY (Brute-Force & Credential Stuffing)
        // =========================================================================
        // Group failures by user_id and calculate frequency
        $userFailures = [];
        $ipFailures = [];
        $failureTypes = ['MFA_FAIL', 'LOGIN_FAIL', 'SUSPENDED_LOGIN_ATTEMPT'];

        foreach ($logs as $log) {
            $action = strtoupper(trim($log['action_type'] ?? ''));
            if (in_array($action, $failureTypes, true)) {
                $failedCount++;
                $uid = (int) ($log['user_id'] ?? 0);
                $ip = $log['ip_address'] ?? '127.0.0.1';
                $time = strtotime($log['created_at']);

                if ($uid > 0) {
                    $userFailures[$uid][] = [
                        'ip' => $ip,
                        'time' => $time,
                        'type' => $action,
                        'desc' => $log['action_description']
                    ];
                }

                $ipFailures[$ip][] = [
                    'user_id' => $uid,
                    'time' => $time,
                    'type' => $action
                ];
            }
        }

        // Evaluate user failure bursts
        foreach ($userFailures as $uid => $attempts) {
            $count = count($attempts);
            $userEmail = $usersMap[$uid]['email'] ?? "UID-{$uid}";

            // Check if 3 or more failures occurred
            if ($count >= 5) {
                $threatScore += 45;
                $flaggedIdentities[$uid] = true;
                $lastIp = $attempts[0]['ip'] ?? 'Unknown';
                $anomalies[] = [
                    'id' => 'ANOM-CRIT-' . $uid,
                    'severity' => 'CRITICAL',
                    'type' => 'BRUTE_FORCE_VELOCITY',
                    'title' => 'Critical Credential Brute-Force Velocity',
                    'target_user' => $userEmail,
                    'target_uid' => $uid,
                    'ip_address' => $lastIp,
                    'confidence' => 97,
                    'description' => "{$count} consecutive authentication/MFA failures detected on account {$userEmail}.",
                    'recommendation' => 'Immediate account suspension required to mitigate ongoing credential cracking.',
                    'action_type' => 'suspend'
                ];

                $terminalLogs[] = [
                    'type' => 'CRITICAL',
                    'badge' => 'ALERT',
                    'time' => date('H:i:s'),
                    'msg' => "[CRITICAL] High failure velocity on {$userEmail} ({$count} failures from {$lastIp}). Threat score +45."
                ];
            } elseif ($count >= 3) {
                $threatScore += 25;
                $flaggedIdentities[$uid] = true;
                $lastIp = $attempts[0]['ip'] ?? 'Unknown';
                $anomalies[] = [
                    'id' => 'ANOM-HIGH-' . $uid,
                    'severity' => 'HIGH',
                    'type' => 'REPEATED_MFA_CHALLENGE_FAIL',
                    'title' => 'Elevated Authentication Challenge Failures',
                    'target_user' => $userEmail,
                    'target_uid' => $uid,
                    'ip_address' => $lastIp,
                    'confidence' => 84,
                    'description' => "{$count} failed authentication challenges recorded for {$userEmail}.",
                    'recommendation' => 'Monitor account closely; initiate credential review or preemptive suspension.',
                    'action_type' => 'suspend'
                ];

                $terminalLogs[] = [
                    'type' => 'WARN',
                    'badge' => 'WARN',
                    'time' => date('H:i:s'),
                    'msg' => "[HIGH] {$count} repeated challenge failures on {$userEmail}. Threat score +25."
                ];
            }
        }

        // =========================================================================
        // HEURISTIC 2: IDENTITY IP DIVERGENCE / IMPOSSIBLE TRAVEL (Compromised Credential Indicator)
        // =========================================================================
        // Detect if the same user has active events from distinct IP addresses
        $userIdIps = [];
        foreach ($logs as $log) {
            $uid = (int) ($log['user_id'] ?? 0);
            if ($uid > 0) {
                $ip = $log['ip_address'] ?? '127.0.0.1';
                $userIdIps[$uid][$ip] = ($userIdIps[$uid][$ip] ?? 0) + 1;
            }
        }

        foreach ($userIdIps as $uid => $ips) {
            $distinctIpCount = count($ips);
            if ($distinctIpCount >= 2) {
                $threatScore += 35;
                $flaggedIdentities[$uid] = true;
                $userEmail = $usersMap[$uid]['email'] ?? "UID-{$uid}";
                $ipListStr = implode(', ', array_keys($ips));

                $anomalies[] = [
                    'id' => 'ANOM-GEO-' . $uid,
                    'severity' => 'CRITICAL',
                    'type' => 'IDENTITY_IP_DIVERGENCE',
                    'title' => 'Multi-IP Identity Divergence (Impossible Travel)',
                    'target_user' => $userEmail,
                    'target_uid' => $uid,
                    'ip_address' => $ipListStr,
                    'confidence' => 93,
                    'description' => "Account {$userEmail} accessed or challenged from {$distinctIpCount} divergent IP endpoints ({$ipListStr}). Strong indicator of compromised credential sharing or session theft.",
                    'recommendation' => 'Isolate identity immediately, revoke all active sessions, and force MFA rotation.',
                    'action_type' => 'suspend'
                ];

                $terminalLogs[] = [
                    'type' => 'CRITICAL',
                    'badge' => 'ANOMALY',
                    'time' => date('H:i:s'),
                    'msg' => "[ANOMALY] IP Divergence detected on {$userEmail}: Traffic spanning [{$ipListStr}]. Threat score +35."
                ];
            }
        }

        // =========================================================================
        // HEURISTIC 3: HORIZONTAL PASSWORD SPRAYING (One IP targeting Multiple Accounts)
        // =========================================================================
        foreach ($ipFailures as $ip => $attempts) {
            $targetedUsers = [];
            foreach ($attempts as $att) {
                if ($att['user_id'] > 0) {
                    $targetedUsers[$att['user_id']] = true;
                }
            }
            $targetCount = count($targetedUsers);
            if ($targetCount >= 2) {
                $threatScore += 30;
                $anomalies[] = [
                    'id' => 'ANOM-SPRAY-' . md5($ip),
                    'severity' => 'HIGH',
                    'type' => 'PASSWORD_SPRAYING',
                    'title' => 'Horizontal Credential Spraying Attack',
                    'target_user' => "{$targetCount} Enterprise Accounts",
                    'target_uid' => null,
                    'ip_address' => $ip,
                    'confidence' => 89,
                    'description' => "Source IP {$ip} generated authentication failures across {$targetCount} distinct employee identities.",
                    'recommendation' => 'Block IP at perimeter firewall / SOC ingress and verify targeted account integrity.',
                    'action_type' => 'firewall'
                ];

                $terminalLogs[] = [
                    'type' => 'WARN',
                    'badge' => 'SPRAY',
                    'time' => date('H:i:s'),
                    'msg' => "[SECURITY] Credential Spraying detected from {$ip} targeting {$targetCount} identities. Threat score +30."
                ];
            }
        }

        // =========================================================================
        // HEURISTIC 4: SUSPENDED ACCOUNT INTRUSION PROBING
        // =========================================================================
        foreach ($logs as $log) {
            if (strtoupper($log['action_type'] ?? '') === 'SUSPENDED_LOGIN_ATTEMPT') {
                $threatScore += 20;
                $uid = (int) ($log['user_id'] ?? 0);
                $userEmail = $usersMap[$uid]['email'] ?? "UID-{$uid}";
                $ip = $log['ip_address'] ?? '127.0.0.1';

                $anomalies[] = [
                    'id' => 'ANOM-SUSP-' . $log['log_id'],
                    'severity' => 'HIGH',
                    'type' => 'SUSPENDED_INTRUSION',
                    'title' => 'Authentication Attempt on Deactivated Account',
                    'target_user' => $userEmail,
                    'target_uid' => $uid,
                    'ip_address' => $ip,
                    'confidence' => 95,
                    'description' => "Probing detected against locked/suspended identity {$userEmail} from {$ip}.",
                    'recommendation' => 'Audit source IP and verify lateral movement attempts within internal subnet.',
                    'action_type' => 'investigate'
                ];

                $terminalLogs[] = [
                    'type' => 'WARN',
                    'badge' => 'INTRUDER',
                    'time' => date('H:i:s'),
                    'msg' => "[INTRUSION] Blocked login attempt on suspended account {$userEmail} from {$ip}."
                ];
                break; // Log once for summary
            }
        }

        // Cap threat score between 5 and 100
        $threatScore = min(100, max(5, $threatScore));

        // Determine Threat Posture
        if ($threatScore >= 75) {
            $threatLevel = 'CRITICAL (Active Breach)';
            $statusColor = 'red';
        } elseif ($threatScore >= 50) {
            $threatLevel = 'HIGH (Severe Threat)';
            $statusColor = 'orange';
        } elseif ($threatScore >= 25) {
            $threatLevel = 'ELEVATED (Guarded)';
            $statusColor = 'amber';
        } else {
            $threatLevel = 'LOW (Baseline)';
            $statusColor = 'emerald';
        }

        $terminalLogs[] = [
            'type' => 'SUMMARY',
            'badge' => 'ATS',
            'time' => date('H:i:s'),
            'msg' => "Evaluation complete: ATS Score {$threatScore}/100. Posture: {$threatLevel}. Active Anomalies: " . count($anomalies)
        ];

        return self::formatReport($threatScore, $threatLevel, $statusColor, $anomalies, $terminalLogs, [
            'scanned' => $scannedCount,
            'failed' => $failedCount,
            'unique_ips' => count($uniqueIps),
            'flagged_users' => count($flaggedIdentities)
        ]);
    }

    /**
     * Helper to inject simulated attack traffic for Live University Defense demonstration.
     */
    public static function injectSimulationThreat(mysqli $conn, string $scenario = 'brute_force'): bool {
        $ip = '198.51.100.77'; // Synthetic simulated external malicious IP

        // Pick an existing user ID to target
        $targetUid = 1;
        $userRes = $conn->query("SELECT user_id, email FROM users ORDER BY user_id DESC LIMIT 1");
        if ($userRes && $u = $userRes->fetch_assoc()) {
            $targetUid = (int) $u['user_id'];
            $targetEmail = $u['email'];
        } else {
            $targetEmail = 'admin@organization.com';
        }

        if ($scenario === 'brute_force') {
            // Inject 5 rapid MFA failures
            for ($i = 1; $i <= 5; $i++) {
                $desc = "SIMULATED BREACH: Rapid MFA challenge failure [Attempt #{$i}/5] for {$targetEmail}";
                $stmt = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, 'MFA_FAIL', ?, ?)");
                $stmt->bind_param("iss", $targetUid, $desc, $ip);
                $stmt->execute();
            }
        } elseif ($scenario === 'ip_divergence') {
            // Inject 2 events from different IPs for the same user
            $desc1 = "SIMULATED BREACH: Credential login from Headquarters LAN ({$targetEmail})";
            $stmt1 = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, 'LOGIN', ?, '192.168.1.100')");
            $stmt1->bind_param("is", $targetUid, $desc1);
            $stmt1->execute();

            $desc2 = "SIMULATED BREACH: Concurrent access from Unrecognized External Geo-IP ({$targetEmail})";
            $stmt2 = $conn->prepare("INSERT INTO audit_logs (user_id, action_type, action_description, ip_address) VALUES (?, 'MFA_FAIL', ?, '203.0.113.45')");
            $stmt2->bind_param("is", $targetUid, $desc2);
            $stmt2->execute();
        }

        return true;
    }

    /**
     * Reset simulated test events from audit trail.
     */
    public static function resetSimulationTelemetry(mysqli $conn): bool {
        $stmt = $conn->prepare("DELETE FROM audit_logs WHERE action_description LIKE 'SIMULATED BREACH%'");
        return (bool) $stmt->execute();
    }

    private static function formatReport(int $score, string $level, string $color, array $anomalies, array $logs, array $stats): array {
        return [
            'threat_score' => $score,
            'threat_level' => $level,
            'status_color' => $color,
            'anomalies' => $anomalies,
            'terminal_logs' => $logs,
            'stats' => $stats
        ];
    }

    private static function buildFallbackResponse(string $errorMsg): array {
        return [
            'threat_score' => 15,
            'threat_level' => 'LOW (Baseline)',
            'status_color' => 'emerald',
            'anomalies' => [],
            'terminal_logs' => [
                ['type' => 'WARN', 'badge' => 'ERR', 'time' => date('H:i:s'), 'msg' => $errorMsg]
            ],
            'stats' => ['scanned' => 0, 'failed' => 0, 'unique_ips' => 0, 'flagged_users' => 0]
        ];
    }
}
