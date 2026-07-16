@echo off
setlocal
REM Build the standalone NSIS installer required for Microsoft Store submission.
REM Partner Center must use /S as the silent install parameter.

call "%~dp0load-msvc-env.cmd"
if errorlevel 1 exit /b %errorlevel%

call npm run version:check
if errorlevel 1 exit /b %errorlevel%

echo Building Fwoosh Microsoft Store installer (offline NSIS)...
call npm run tauri -- build --target x86_64-pc-windows-msvc --bundles nsis --config src-tauri\tauri.microsoftstore.conf.json --ci
exit /b %errorlevel%
