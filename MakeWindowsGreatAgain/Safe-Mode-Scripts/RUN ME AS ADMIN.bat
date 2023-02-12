@echo off
set "psScript=%~dp0safemodescripts.ps1"
powershell -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File ""%psScript%""' -Verb RunAs}";