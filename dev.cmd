@echo off
REM Fwoosh dev launcher: loads the MSVC build env, then runs the native app.
REM
REM Use this instead of `npm run tauri dev` when launching from PowerShell or
REM cmd on a machine where Git Bash's /usr/bin/link shadows MSVC's link.exe.
REM Double-click this file, or run `dev.cmd` from the project root.
call "%~dp0scripts\load-msvc-env.cmd"
if errorlevel 1 exit /b %errorlevel%
echo Starting Fwoosh (native desktop app)...
npm run tauri dev
exit /b %errorlevel%
