@echo off
title The Stealer - Production Edition
color 0A

echo.
echo ========================================
echo   The Stealer - Production Edition
echo ========================================
echo.
echo [1] Production Mode (Full Features)
echo [2] Stealth Mode (Background Operation)
echo [3] Persistence Mode (System Integration)
echo [4] Extraction Mode (Data Collection)
echo [5] Exit
echo.

set /p choice="Select mode (1-5): "

if "%choice%"=="1" (
    echo Starting Production Mode...
    python launcher.py --mode production
) else if "%choice%"=="2" (
    echo Starting Stealth Mode...
    python launcher.py --mode stealth
) else if "%choice%"=="3" (
    echo Starting Persistence Mode...
    python launcher.py --mode persistence
) else if "%choice%"=="4" (
    set /p target="Enter target path: "
    echo Starting Extraction Mode...
    python launcher.py --mode extraction --target "%target%"
) else if "%choice%"=="5" (
    echo Exiting...
    exit
) else (
    echo Invalid choice. Please run the script again.
    pause
)

pause