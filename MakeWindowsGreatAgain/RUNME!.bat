@echo off
set "psScript=%~dp0main.ps1"
powershell -ExecutionPolicy Bypass -NoProfile -Command "& {Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File ""%psScript%""' -Verb RunAs}"
