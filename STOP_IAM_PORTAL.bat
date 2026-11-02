@echo off
title Stop Enterprise IAM Services
echo ========================================================
echo   Stopping Local Apache & MySQL Services...
echo ========================================================
taskkill /F /IM httpd.exe 2>NUL
taskkill /F /IM mysqld.exe 2>NUL
echo.
echo [OK] All local IAM server processes have been stopped safely.
echo.
pause
