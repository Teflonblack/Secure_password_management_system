@echo off
title Secure Password Manager API
color 0A

echo.
echo ======================================================
echo     🔐 Starting Secure Password Manager API Server
echo ======================================================
echo.

REM --- Check if Python is installed ---
python --version >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Python not found or not in PATH!
    pause
    exit /b
)

REM --- Check if start_api.py exists ---
if not exist start_api.py (
    echo ❌ start_api.py not found in current directory!
    pause
    exit /b
)

REM --- Launch Flask API (start_api.py handles DB-based password loading) ---
echo 🚀 Launching Secure Password Manager backend...
python start_api.py

if errorlevel 1 (
    echo ❌ Failed to start API. Check for import or database errors.
    pause
)
