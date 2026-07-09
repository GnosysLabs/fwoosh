@echo off
REM Fwoosh cargo wrapper: load the full MSVC C++ build environment.
REM
REM vcvars64.bat sets LIB/INCLUDE/PATH correctly (MSVC CRT headers + libs +
REM Windows SDK). Git Bash's /usr/bin/link.exe can otherwise shadow MSVC's
REM linker, so this wrapper sets a local Cargo linker override after vcvars.
call "%~dp0..\scripts\load-msvc-env.cmd"
if errorlevel 1 exit /b %errorlevel%
pushd "%~dp0"
if errorlevel 1 exit /b %errorlevel%
cargo %* 2>&1
set "CARGO_EXIT=%errorlevel%"
popd
echo CARGO_EXIT=%CARGO_EXIT%
exit /b %CARGO_EXIT%
