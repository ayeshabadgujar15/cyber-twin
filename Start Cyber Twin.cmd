@echo off
cd /d "%~dp0"
python start_server.py
if errorlevel 1 pause
