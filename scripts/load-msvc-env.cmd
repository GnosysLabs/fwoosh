@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM Load the local MSVC x64 build environment without committing a
REM machine-specific linker path. This is for Windows developer shells only.

REM CI runners and Visual Studio developer shells may already have the correct
REM linker configured. Re-running vcvars64.bat is unnecessary there and can
REM break when a self-hosted runner has parenthesized paths in its environment.
call :find_msvc_linker
if not errorlevel 1 goto :ready

set "VCVARS64="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "!VSWHERE!" (
  for /f "usebackq delims=" %%I in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%I\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS64=%%I\VC\Auxiliary\Build\vcvars64.bat"
  )
)

if not defined VCVARS64 (
  for %%P in (
    "!ProgramFiles!\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    "!ProgramFiles!\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  ) do (
    if not defined VCVARS64 if exist "%%~P" set "VCVARS64=%%~P"
  )
)

if not defined VCVARS64 (
  echo Could not find Visual Studio Build Tools with the C++ workload.
  echo Install Visual Studio 2019 or later, or Build Tools for Visual Studio, with Desktop development with C++.
  exit /b 1
)

call "!VCVARS64!" >nul
if errorlevel 1 exit /b !errorlevel!

call :find_msvc_linker
if errorlevel 1 (
  echo MSVC link.exe was not first in PATH after loading vcvars64.bat.
  echo First link.exe: !FIRST_LINK!
  exit /b 1
)

:ready
echo Using MSVC linker: !FIRST_LINK!
set "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=link.exe"
exit /b 0

:find_msvc_linker
set "FIRST_LINK="
for /f "delims=" %%L in ('where link.exe 2^>nul') do (
  if not defined FIRST_LINK set "FIRST_LINK=%%L"
)

if not defined FIRST_LINK exit /b 1
echo(!FIRST_LINK!| findstr /I /C:"Microsoft Visual Studio" >nul
exit /b !errorlevel!
