@echo off
echo ===================================================
echo Syncing Enterprise IAM Portal to XAMPP htdocs...
echo ===================================================
xcopy /E /Y /I "%~dp0*" "C:\xampp\htdocs\IAM PROJECT\"
echo.
echo Sync Complete!
echo Access via HTTPS: https://iam.secure-defense.internal/
echo (Or fallback: http://localhost/IAM%%20PROJECT/)
echo.
pause
