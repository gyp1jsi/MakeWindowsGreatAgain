@echo off
set "psScript=%~dp0main.ps1"
powershell -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass -File ""%psScript%""' -Verb RunAs}";