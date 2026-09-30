@echo off
REM Build zonetrace.dll (x86 - Ashita is 32bit). Loads MSVC env first; cmake cannot find the
REM standard headers without it.
REM Usage from bash: cmd.exe //c "C:\Users\sruon\Documents\GitHub\zonetrace\build.bat" [outdir]
REM   outdir - where to write zonetrace.dll. Defaults to the live polplugins folder; pass a staging
REM            path to build while clients are up, since they hold the dll open.
setlocal

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars32.bat
set NINJA=C:\Users\sruon\AppData\Local\Programs\CLion\bin\ninja\win\x64\ninja.exe
set BUILD=%~dp0build-x86
set OUTDIR=%~1
if "%OUTDIR%"=="" set OUTDIR=E:/Ashita-v4beta/polplugins
if "%ASHITA4_SDK_PATH%"=="" set ASHITA4_SDK_PATH=E:\Ashita-v4beta\plugins\sdk

call "%VCVARS%" >nul
if errorlevel 1 (
  echo [build.bat] Failed to load vcvars32.bat
  exit /b 1
)

cmake -S "%~dp0." -B "%BUILD%" -G Ninja -DCMAKE_MAKE_PROGRAM="%NINJA%" -DCMAKE_BUILD_TYPE=Release -DZONETRACE_OUTPUT_DIR="%OUTDIR%" >nul
if errorlevel 1 exit /b 1

cmake --build "%BUILD%" --target zonetrace -j 16
exit /b %errorlevel%
