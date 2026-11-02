# Enterprise Zero-Trust Identity & Access Management (IAM) Portal
### University Final Defense Project &bull; B.Sc. Information Technology (4.2 Final Year)
**Lead Developer:** John Njoroge TJ  
**Core Problem Solved:** Curbing enterprise network breaches caused by compromised internal credentials.  
**Production Domain:** `https://iam.secure-defense.internal` (Encrypted via TLS 1.3 / Port 443)

---

## 1. Executive Summary & Defense Relevance
In modern enterprise environments, **over 80% of data breaches originate from compromised internal credentials** (infostealer malware, phishing, dark web dumps, and credential stuffing). Once an attacker obtains valid employee login credentials, perimeter firewalls and legacy perimeter security become completely ineffective.

This system implements **NIST SP 800-207 Zero-Trust Architecture** principles:
> *"Never Trust, Always Verify. Assume Breach."*

Even when an attacker has a valid email and password, the portal actively mitigates the breach through **four autonomous defensive layers**:
1. **Zero-Trust Challenge Intercept:** Native TOTP Multi-Factor Authentication prevents direct access (`mfa_verify.php`).
2. **AI Sentinel Behavioral Threat Engine:** Scans real-time telemetry for credential velocity anomalies, horizontal password spraying, and multi-IP impossible travel (`ai_sentinel.php`).
3. **Automated & Manual Identity Kill-Switch (RBAC):** Instant account suspension revokes all authentication privileges and terminates active sessions (`dashboard.php`).
4. **Hardened Transport Layer Security (TLS 1.3):** Full enterprise domain routing via `https://iam.secure-defense.internal` with automatic HTTP-to-HTTPS permanent redirection and HSTS security headers.

---

## 2. System Architecture & Tech Stack

| Layer | Technology | Security Implementation |
|---|---|---|
| **Domain & TLS** | **`iam.secure-defense.internal`** | Dedicated X.509 SSL certificate with Subject Alternative Names (SAN), installed to Windows Root Store for trusted green padlock |
| **Backend** | **PHP 8.2+ (Native)** | Zero third-party Composer dependencies; pure native cryptographic & mathematical logic |
| **Database** | **MySQL / MariaDB (via XAMPP)** | Relational integrity with foreign key constraints, parameterized `mysqli` prepared statements (immune to SQL Injection), and indexed audit logs |
| **Frontend** | **HTML5 & Tailwind CSS** | Cyber Defense Operations Center (SOC) Dark Theme + Biometric Welcome HUD Sequence |
| **MFA Engine** | **RFC 6238 TOTP Algorithm** | Custom mathematical engine using SHA-1 HMAC and Base32 bitwise conversion. No third-party APIs needed; 100% offline |
| **AI Sentinel** | **Behavioral Heuristics** | Anomaly Threat Scoring (ATS: 0–100), Velocity Analysis, Multi-IP Identity Divergence |
| **Configuration** | **Native `.env` & Apache `.htaccess`** | Keeps database credentials completely decoupled from code with Apache HTTP access prohibition |

---

## 3. Key Features

### Feature 1: Enterprise HTTPS & Custom Domain (`iam.secure-defense.internal`)
* Replaces default `localhost/IAM PROJECT` with an authentic internal enterprise domain: **`https://iam.secure-defense.internal`**.
* **Automatic Port 80 &rarr; 443 Redirect:** Any standard HTTP request is instantly upgraded to HTTPS via Apache `mod_rewrite` and PHP security middleware.
* **Pre-Generated X.509 Certificate:** Includes SAN entries for `iam.secure-defense.internal`, `auth.enterprise-soc.local`, and `localhost`.
* **1-Click Installer (`setup_ssl_and_domain.bat`):** Automates Windows `hosts` DNS entry, installs certificate into Windows Trusted Root store, and provisions Apache VirtualHost.

### Feature 2: Animated Cybersecurity Biometric Welcome HUD
* Upon successful authentication and MFA verification, the dashboard launches a **futuristic sci-fi holographic welcome sequence**:
  * **Biometric Laser Radar Scan:** Rotating holographic cyber-rings with laser scanner animation.
  * **Dynamic Personalized Greeting:** Shows user's full name (e.g., `Agent John Njoroge`), identity UID, and corporate email.
  * **Clearance Level Badges:** `LEVEL 4 // TOP SECRET (SUPER ADMIN)` down to `LEVEL 1 // RESTRICTED ACCESS (EMPLOYEE)`.
  * **Cryptographic Status:** Confirms `TLS 1.3 / AES-256-GCM`, `RFC 6238 TOTP PASSED`, and workstation ingress IP.
  * **Native Web Audio API SFX:** Synthesizes a futuristic 3-note cyber confirmation chime with mute/unmute control (zero external audio files).
  * **Replay Button:** A dedicated **"Identity HUD"** button in the navbar allows replaying the sequence on demand during the defense.

### Feature 3: AI Anomaly Sentinel Engine (`ai_sentinel.php`)
* **Rapid MFA / Credential Velocity (Brute-Force):** Detects bursts of failed authentication challenges ($\ge 3$ failures = HIGH, $\ge 5$ failures = CRITICAL).
* **Multi-IP Identity Divergence (Impossible Travel):** Flags when the same employee identity generates authentication events from distinct IP subnets within a short window.
* **Horizontal Password Spraying:** Flags single IP endpoints attempting to authenticate across multiple distinct accounts.
* **Dynamic Anomaly Threat Score (ATS: 0 - 100):**
  * `0 - 24`: **LOW (Baseline)** (Emerald).
  * `25 - 49`: **ELEVATED (Guarded)** (Amber).
  * `50 - 74`: **HIGH (Severe Threat)** (Orange).
  * `75 - 100`: **CRITICAL (Active Breach)** (Red flashing beacon).
* **Defense Simulation Mode:** 1-click synthetic threat injection in the dashboard so you can demonstrate live breach detection and mitigation.

### Feature 4: Multi-Layered RBAC, Clearance Tiers & "The Crown Jewels" Vault (`vault.php`)
* **Simulated Crown Jewels Assets:**
  1. **Customer PII Database:** 45,820 customer identity records, Social Security/National ID numbers, cryptographic tokens, PCI-DSS billing hashes (`AES-256-GCM`). Requires **Tier 2+ (Auditor / Admin)**.
  2. **Q3 Corporate Financials:** Consolidated corporate treasury ledgers, net revenue performance ($14.2M), EBITDA forecasts, executive salary matrix. Requires **Tier 2+ (Auditor / Admin)**.
  3. **Production Server SSH Keys:** Root Ed25519 cryptographic private key pairs granting root shell authorization into Kubernetes master control planes and database clusters. Requires **Tier 3 (Admin Only)**.
* **Granular RBAC Matrix:**
  * **Staff (Tier 1):** Prominent red **"ACCESS DENIED: INSUFFICIENT CLEARANCE"** overlay across sensitive resources. Any attempt to inspect or download triggers an immediate security alert and logs an `ACCESS_DENIED_UNAUTHORIZED_RESOURCE` event to the SOC audit stream.
  * **Auditor (Tier 2):** Read and inspect privileges for PII and corporate financials with active audit tracking; Production SSH keys remain strictly locked.
  * **Admin (Tier 3):** Unrestricted access with decrypted live previews, downloadable `.pem` keypairs, and CSV financial ledger exports.
* **Enterprise Sidebar Navigation (`dashboard.php`, `vault.php`, `api_management.php`):**
  * Persistent, responsive dark-mode sidebar featuring SOC Command Center, Secure Vault (Crown Jewels), API Management, MFA Configuration, and CSV Audit Ledger Export.
* **Expanded Multi-Attribute Identity Provisioning:**
  * Provisioning modal now assigns **Department** (SOC, IT & Cloud, Finance, Legal, DevOps, HR), **Job Title**, **Functional Role** (`Admin`, `Staff`, `Auditor`), and **Clearance Level** (`Tier 1`, `Tier 2`, `Tier 3`).
* **API Key Management (`api_management.php` / `api_keys.php`):**
  * Programmatic service token generation with 160-bit hex entropy, active/revocation lifecycle controls, and tamper-resistant audit logging.

### Feature 5: 100% Air-Gapped Offline Architecture
* **Zero External Dependencies:** Built specifically for secure university final defense and defense-in-depth environments without active internet connection.
* **Local CSS Runtime:** Tailwind CSS engine bundled locally in `assets/js/tailwind.js`.
* **Local FontAwesome 6 Icons:** Full icon library and WOFF2/TTF webfonts bundled locally in `assets/css/all.min.css` and `assets/webfonts/`.
* **Offline Client-Side QR Engine:** Dynamic TOTP enrollment QR code rendered locally in the browser via `assets/js/qrcode.min.js` (replaces third-party cloud QR generation APIs).
* **Local Cryptography & AI:** Native PHP mathematical RFC 6238 TOTP computation and behavioral anomaly detection heuristics; 0 external API calls.
* **Local DNS & TLS:** Custom enterprise domain `iam.secure-defense.internal` routed via local Windows `hosts` resolution and local Trusted Root X.509 certificate.

---

## 4. 1-Click Setup Instructions (HTTPS & Custom Domain)

1. Open File Explorer to:
   ```
   C:\Users\user\OneDrive\Desktop\PROJECT\
   ```
2. Double-click:
   ```
   setup_ssl_and_domain.bat
   ```
3. Click **"Yes"** on the Windows UAC Administrator prompt.
4. The script will:
   * Map `127.0.0.1 iam.secure-defense.internal` in `C:\Windows\System32\drivers\etc\hosts`.
   * Install the SSL certificate into Windows Trusted Root Authorities.
   * Configure Apache VirtualHosts for Port 80 and Port 443 with TLS 1.3.
   * Sync application files to `C:\xampp\htdocs\IAM PROJECT`.
   * Restart Apache and launch `https://iam.secure-defense.internal` in your browser!

---

## 5. Verification & Testing
Run the automated test suite anytime:
```bash
C:\xampp\php\php.exe test_suite.php
```
Test results verify:
1. Native `.env` file parsing and HTTPS configuration.
2. Google Authenticator RFC 6238 TOTP mathematical generation and token verification.
3. AISentinel class architecture and behavioral scoring algorithms.
4. Phase 4.2 RBAC matrix enforcement across Tier 1, Tier 2, and Tier 3 clearances.
5. High-entropy programmatic API key token generation and prefix validation.
6. Anomaly detection heuristics against mock attack streams.
7. **100% Offline Air-Gapped Asset Verification:** Validates that all local stylesheets, icon webfonts, QR engines, and templates contain zero external CDN or internet dependencies.
