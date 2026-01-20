$sf='C:\Users\Karl\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\MapZ_TCL.cmd';$c='@echo off
if /I "%USERNAME%" NEQ "Karl" exit /b
rem --- optional: log to confirm it ran ---
echo %DATE% %TIME% - Starting map to \\LARRY-PC\TCL >> "%USERPROFILE%\MapZ_TCL.log"
rem remove any existing Z:
net use Z: /delete /y >nul 2>&1
rem map Z: and persist across reboots
net use Z: "\\LARRY-PC\TCL" /persistent:yes
if %ERRORLEVEL% EQU 0 (
  echo %DATE% %TIME% - Success mapping Z: >> "%USERPROFILE%\MapZ_TCL.log"
  del "%~f0"
) else (
  echo %DATE% %TIME% - FAILED with %ERRORLEVEL% >> "%USERPROFILE%\MapZ_TCL.log"
)';New-Item -ItemType Directory -Force -Path (Split-Path $sf) | Out-Null;Set-Content -Path $sf -Value $c -Encoding ASCII