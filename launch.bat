@echo off
title Phishing URL Detector Launcher
echo ========================================================
echo        Phishing URL Detector - Quick Launcher
echo ========================================================
echo.

cd /d "%~dp0"

where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Starting application with Python server...
    python launch.py
) else (
    echo Python not found in PATH.
    echo Opening index.html directly in your default browser...
    start "" "%~dp0index.html"
)

pause
