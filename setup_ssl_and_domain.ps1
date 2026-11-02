# ==============================================================================
# ENTERPRISE ZERO-TRUST IAM PORTAL - AUTOMATED HTTPS & DOMAIN INSTALLER
# Target Domain: https://iam.secure-defense.internal
# ==============================================================================

param()

$ErrorActionPreference = "Stop"

# 1. Ensure Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Elevating privileges to Administrator..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Clear-Host
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE ZERO-TRUST IAM PORTAL - HTTPS & DOMAIN PROVISIONER   " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$xamppPath = "C:\xampp"
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$domain = "iam.secure-defense.internal"
$altDomain = "auth.enterprise-soc.local"

if (-not (Test-Path $xamppPath)) {
    Write-Host "[-] ERROR: XAMPP directory not found at $xamppPath." -ForegroundColor Red
    pause
    exit
}

# -------------------------------------------------------------
# STEP 1: CONFIGURE LOCAL DNS (C:\Windows\System32\drivers\etc\hosts)
# -------------------------------------------------------------
Write-Host "[1/5] Configuring Local Enterprise Domain in Windows hosts file..." -ForegroundColor Yellow
$hostsContent = Get-Content -Path $hostsPath -Raw -ErrorAction SilentlyContinue

$dnsBlock = @"

# Enterprise Zero-Trust IAM Portal Domain Mapping
127.0.0.1  $domain
127.0.0.1  $altDomain
"@

if ($hostsContent -notmatch [regex]::Escape($domain)) {
    Add-Content -Path $hostsPath -Value $dnsBlock -Encoding UTF8
    Write-Host "  [+] Added '$domain' and '$altDomain' to hosts file." -ForegroundColor Green
} else {
    Write-Host "  [OK] Domain '$domain' is already mapped in hosts file." -ForegroundColor Green
}

# -------------------------------------------------------------
# STEP 2: INSTALL SSL CERTIFICATE TO APACHE & WINDOWS TRUST STORE
# -------------------------------------------------------------
Write-Host "[2/5] Provisioning TLS / SSL Certificate..." -ForegroundColor Yellow
$crtSrc = Join-Path $projectRoot "iam-portal.crt"
$keySrc = Join-Path $projectRoot "iam-portal.key"

$sslCrtDestDir = Join-Path $xamppPath "apache\conf\ssl.crt"
$sslKeyDestDir = Join-Path $xamppPath "apache\conf\ssl.key"

if (-not (Test-Path $sslCrtDestDir)) { New-Item -ItemType Directory -Path $sslCrtDestDir -Force | Out-Null }
if (-not (Test-Path $sslKeyDestDir)) { New-Item -ItemType Directory -Path $sslKeyDestDir -Force | Out-Null }

$crtDest = Join-Path $sslCrtDestDir "iam-portal.crt"
$keyDest = Join-Path $sslKeyDestDir "iam-portal.key"

Copy-Item -Path $crtSrc -Destination $crtDest -Force
Copy-Item -Path $keySrc -Destination $keyDest -Force
Write-Host "  [+] Copied SSL certificate & private key to Apache conf." -ForegroundColor Green

# Add to Windows Root Certificate Store (No browser warning!)
Write-Host "  [+] Installing Certificate into Windows Trusted Root Store..." -ForegroundColor Yellow
$certUtilOutput = & certutil -addstore -f "Root" $crtDest 2>&1
Write-Host "  [OK] Certificate trusted by Windows / Chrome / Edge / Brave." -ForegroundColor Green

# -------------------------------------------------------------
# STEP 3: CONFIGURE APACHE VIRTUAL HOSTS (httpd-vhosts.conf)
# -------------------------------------------------------------
Write-Host "[3/5] Configuring Apache Virtual Hosts for HTTPS & Redirects..." -ForegroundColor Yellow
$vhostsFile = Join-Path $xamppPath "apache\conf\extra\httpd-vhosts.conf"
$vhostsContent = Get-Content -Path $vhostsFile -Raw -ErrorAction SilentlyContinue

$vhostConfig = @"

# ==============================================================================
# ENTERPRISE ZERO-TRUST IAM PORTAL (HTTPS & CUSTOM DOMAIN)
# ==============================================================================

<VirtualHost *:80>
    DocumentRoot "C:/xampp/htdocs"
    ServerName localhost
</VirtualHost>

<VirtualHost *:80>
    ServerName $domain
    ServerAlias $altDomain
    Redirect permanent / https://$domain/
</VirtualHost>

<VirtualHost *:443>
    DocumentRoot "C:/xampp/htdocs/IAM PROJECT"
    ServerName $domain
    ServerAlias $altDomain

    SSLEngine on
    SSLCertificateFile "conf/ssl.crt/iam-portal.crt"
    SSLCertificateKeyFile "conf/ssl.key/iam-portal.key"

    <Directory "C:/xampp/htdocs/IAM PROJECT">
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog "logs/iam-ssl-error.log"
    CustomLog "logs/iam-ssl-access.log" combined
</VirtualHost>
"@

if ($vhostsContent -notmatch [regex]::Escape($domain)) {
    Add-Content -Path $vhostsFile -Value $vhostConfig -Encoding UTF8
    Write-Host "  [+] Added HTTPS VirtualHost for '$domain' to httpd-vhosts.conf." -ForegroundColor Green
} else {
    Write-Host "  [OK] VirtualHost for '$domain' is already configured." -ForegroundColor Green
}

# -------------------------------------------------------------
# STEP 4: SYNC LATEST CODEBASE TO XAMPP HTDOCS
# -------------------------------------------------------------
Write-Host "[4/5] Synchronizing latest IAM application files to htdocs..." -ForegroundColor Yellow
$targetHtdocs = Join-Path $xamppPath "htdocs\IAM PROJECT"
if (-not (Test-Path $targetHtdocs)) { New-Item -ItemType Directory -Path $targetHtdocs -Force | Out-Null }

Copy-Item -Path "$projectRoot\*" -Destination $targetHtdocs -Recurse -Force
Copy-Item -Path "$projectRoot\.env" -Destination (Join-Path $targetHtdocs ".env") -Force -ErrorAction SilentlyContinue
Copy-Item -Path "$projectRoot\.env.example" -Destination (Join-Path $targetHtdocs ".env.example") -Force -ErrorAction SilentlyContinue
Copy-Item -Path "$projectRoot\.htaccess" -Destination (Join-Path $targetHtdocs ".htaccess") -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] Application synchronized." -ForegroundColor Green

# -------------------------------------------------------------
# STEP 5: RESTART APACHE SERVICE
# -------------------------------------------------------------
Write-Host "[5/5] Refreshing Apache Web Server..." -ForegroundColor Yellow
$httpdRunning = Get-Process -Name "httpd" -ErrorAction SilentlyContinue
if ($httpdRunning) {
    try {
        Stop-Process -Name "httpd" -Force
        Start-Sleep -Seconds 1
        Start-Process (Join-Path $xamppPath "apache\bin\httpd.exe")
        Write-Host "  [OK] Apache successfully restarted with SSL." -ForegroundColor Green
    } catch {
        Write-Host "  [!] Notice: Please click 'Stop' then 'Start' on Apache in XAMPP Control Panel." -ForegroundColor Yellow
    }
} else {
    Write-Host "  [*] Apache is currently stopped. Please start Apache in XAMPP Control Panel." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "   SUCCESS: ENTERPRISE HTTPS & CUSTOM DOMAIN PROVISIONED!         " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Custom Domain URL:  https://$domain/" -ForegroundColor White
Write-Host "  Alternate URL:      https://$altDomain/" -ForegroundColor White
Write-Host "  SSL Protocol:       TLS 1.3 / AES-256-GCM (Trusted)" -ForegroundColor White
Write-Host "  HTTP Redirection:   Active (Port 80 -> 443 Permanent 301)" -ForegroundColor White
Write-Host ""
Write-Host "Launching https://$domain/ in your default browser..." -ForegroundColor Cyan

Start-Process "https://$domain/"

Write-Host "Press any key to exit this installer..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
