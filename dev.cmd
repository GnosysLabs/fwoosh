@echo off
REM ClipVault dev launcher: loads the MSVC build env, then runs the native app.
REM
REM Use this instead of `npm run tauri dev` when launching from PowerShell or
REM cmd on a machine where Git Bash's /usr/bin/link shadows MSVC's link.exe.
REM Double-click this file, or run `dev.cmd` from the project root.
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
echo Starting ClipVault (native desktop app)...
npm run tauri dev
