@echo off
:: ==============================================================================
:: ENTERPRISE ZERO-TRUST IAM PORTAL - 1-CLICK HTTPS & DOMAIN INSTALLER
:: Right-click and choose "Run as administrator" or just double-click!
:: ==============================================================================

title Enterprise IAM - SSL and Domain Provisioner
echo Initializing Administrator Privileges...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0setup_ssl_and_domain.ps1\"\"' -Verb RunAs"
exit /b
