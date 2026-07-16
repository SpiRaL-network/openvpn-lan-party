@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass ^
  -File "%~dp0LAN-Party-Companion.ps1" -ConfigPath "%~dp0companion.json" %*
