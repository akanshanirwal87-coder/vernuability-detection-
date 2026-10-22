@echo off
title SecureCode AI - Launcher
echo ========================================================
echo       Launching SecureCode AI (Frontend + Backend)
echo ========================================================
echo.

:: Launch Backend in a new window
echo [1/2] Starting Python FastAPI Backend on port 8000...
start "SecureCode AI - Backend" cmd /k "cd /d "%~dp0backend" && python main.py"

:: Wait 2 seconds
timeout /t 2 /nobreak >nul

:: Launch Frontend in a new window
echo [2/2] Starting React + Vite Frontend on port 5173...
start "SecureCode AI - Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ========================================================
echo Both services launched successfully!
echo.
echo - Web App:    http://localhost:5173
echo - API Docs:   http://localhost:8000/docs
echo.
echo (Keep the two newly opened command windows running)
echo ========================================================
pause

