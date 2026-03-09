@echo off
title SecureShare – AI File Sharing Platform
color 0B
cls

echo ============================================================
echo   SecureShare  -  AI-Powered Secure File Sharing Platform
echo ============================================================
echo.

REM Change to project root directory
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo [1/5] Checking dependencies...
pip show flask >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
)
echo       Dependencies OK

echo.
echo [2/5] Checking Firebase configuration...
if not exist ".env" (
    echo.
    echo [ERROR] .env file not found!
    echo.
    echo  Please follow these steps to set up Firebase:
    echo  1. Go to https://console.firebase.google.com
    echo  2. Create a project ^& enable Email/Password Auth + Storage
    echo  3. Download serviceAccountKey.json from Project Settings ^> Service Accounts
    echo  4. Place serviceAccountKey.json in this folder
    echo  5. Fill in the values in the .env file
    echo.
    pause
    exit /b 1
)

REM Check if .env still has the placeholder values
findstr /C:"YOUR_PROJECT_ID" ".env" >nul 2>&1
if not errorlevel 1 (
    echo.
    echo [WARNING] Your .env file still has placeholder values!
    echo.
    echo  You need to fill in your real Firebase credentials.
    echo  Open the .env file in Notepad and replace all YOUR_* values
    echo  with your actual Firebase project values.
    echo.
    echo  See the guide: https://console.firebase.google.com
    echo.
    pause
    exit /b 1
)
echo       Firebase config found OK

echo.
echo [3/5] Checking ML models...
if not exist "models\exe_model.pkl" (
    echo [INFO] Models not found. Generating placeholder models...
    python training\generate_models.py
    if errorlevel 1 (
        echo [WARN] Could not generate models. Heuristic scan will be used.
    )
) else (
    echo       Models found OK
)

echo.
echo [4/5] Creating required directories...
if not exist "uploads\"   mkdir uploads
if not exist "qr_codes\"  mkdir qr_codes
if not exist "models\"    mkdir models
if not exist "scalers\"   mkdir scalers
if not exist "features\"  mkdir features
echo       Directories OK

echo.
echo [5/5] Starting Flask server...
echo.
echo ============================================================
echo   Platform is running at:  http://localhost:5000
echo   Press Ctrl+C to stop the server
echo ============================================================
echo.

start "" "http://localhost:5000"
python backend\app.py

pause
