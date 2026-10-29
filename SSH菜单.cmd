@echo off
chcp 65001 >nul
cd /d "%~dp0"
python ssh_cli.py
if errorlevel 1 pause
