@echo off
REM ClipVault cargo wrapper: load the full MSVC C++ build environment.
REM
REM vcvars64.bat sets LIB/INCLUDE/PATH correctly (MSVC CRT headers + libs +
REM Windows SDK). Git Bash's /usr/bin/link.exe would shadow the MSVC linker,
REM so the real linker is also pinned in .cargo/config.toml.
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cargo %* 2>&1
echo CARGO_EXIT=%errorlevel%
