@echo off
title SecureCode AI - Backend (Port 8000)
cd /d "%~dp0backend"
echo Starting FastAPI Backend on http://127.0.0.1:8000 ...
python main.py
pause

