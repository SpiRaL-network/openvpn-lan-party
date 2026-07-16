@echo off
setlocal
set "SCRIPT=%~dp0Join-VPN.ps1"
if not exist "%SCRIPT%" (
  echo This invitation must be fully extracted before it can run.
  echo Cette invitation doit etre entierement extraite avant son lancement.
  pause
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -BundleDirectory "%~dp0."
if errorlevel 1 pause
exit /b %errorlevel%
