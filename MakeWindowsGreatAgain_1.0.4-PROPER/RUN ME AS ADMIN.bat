@echo off
Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File %~dp0main.ps1' -Verb RunAs}"
echo "MakeWindowsGreatAgain is running in a PowerShell window. Do not close it, it will close itself after the process is completed."
pause