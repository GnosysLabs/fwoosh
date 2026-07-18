@echo off
setlocal
REM Build the Windows release and generate both native installer formats.
REM The local MSVC environment avoids Git Bash's GNU link.exe shadowing
REM Microsoft's linker.

call "%~dp0load-msvc-env.cmd"
if errorlevel 1 exit /b %errorlevel%

call npm run version:check
if errorlevel 1 exit /b %errorlevel%

echo Building Fwoosh Windows installers (NSIS + MSI)...
call npm run tauri -- build --target x86_64-pc-windows-msvc --bundles nsis msi --ci
exit /b %errorlevel%
