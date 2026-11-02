@echo off
title Enterprise Zero-Trust IAM Portal - One-Click Launcher
echo ========================================================
echo   ENTERPRISE ZERO-TRUST IAM PORTAL (100%% OFFLINE)
echo   Starting Local Apache & MySQL Database Services...
echo ========================================================
echo.

:: Check if Apache is running, start if not
tasklist /FI "IMAGENAME eq httpd.exe" 2>NUL | find /I /N "httpd.exe" >NUL
if "%ERRORLEVEL%"=="0" (
    echo [OK] Apache Web Server is already running.
) else (
    echo [*] Starting Apache Web Server (TLS 1.3 / Port 443)...
    start "" /B "C:\xampp\apache\bin\httpd.exe"
)

:: Check if MySQL is running, start if not
tasklist /FI "IMAGENAME eq mysqld.exe" 2>NUL | find /I /N "mysqld.exe" >NUL
if "%ERRORLEVEL%"=="0" (
    echo [OK] MySQL Database is already running.
) else (
    echo [*] Starting MySQL MariaDB Engine (Port 3306)...
    start "" /B "C:\xampp\mysql\bin\mysqld.exe" --defaults-file="C:\xampp\mysql\bin\my.ini" --standalone
)

timeout /t 2 /nobreak >nul

echo.
echo ========================================================
echo  [SUCCESS] All Local Infrastructure Online!
echo  Launching Enterprise Domain: https://iam.secure-defense.internal/
echo ========================================================
echo.

start https://iam.secure-defense.internal/
