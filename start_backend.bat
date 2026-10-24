@echo off
title SecureCode AI - Backend (Port 8000)
cd /d "%~dp0backend"
echo Starting FastAPI Backend on http://127.0.0.1:8000 ...
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" main.py
) else if exist "%~dp0backend\.venv\Scripts\python.exe" (
    "%~dp0backend\.venv\Scripts\python.exe" main.py
) else (
    python main.py
)
pause

