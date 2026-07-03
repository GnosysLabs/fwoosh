@echo off
REM ============================================================================
REM ClipVault cargo wrapper: set up the MSVC C++ build environment manually.
REM
REM Background: this VS 2026 install ships only vcvars64.bat which calls a
REM non-existent vcvarsall.bat, so the standard batch chain fails (exit 1).
REM We instead set LIB/INCLUDE/PATH directly to the known-good toolset paths.
REM Git Bash's /usr/bin/link.exe is also shadowed, so the real linker is pinned
REM in .cargo/config.toml.
REM ============================================================================

set "MSVC=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.50.35717"
set "WINSDK=C:\Program Files (x86)\Windows Kits\10"

set "LIB=%MSVC%\lib\onecore\x64;%WINSDK%\Lib\10.0.26100.0\ucrt\x64;%WINSDK%\Lib\10.0.26100.0\um\x64"
set "INCLUDE=%~dp0msvc-shim;%MSVC%\include;%WINSDK%\Include\10.0.26100.0\ucrt;%WINSDK%\Include\10.0.26100.0\um;%WINSDK%\Include\10.0.26100.0\shared;%WINSDK%\Include\10.0.26100.0\winrt;%WINSDK%\Include\10.0.26100.0\cppwinrt"
set "PATH=%MSVC%\bin\Hostx64\x64;%WINSDK%\bin\10.0.26100.0\x64;%PATH%"

cargo %* 2>&1
echo CARGO_EXIT=%errorlevel%
