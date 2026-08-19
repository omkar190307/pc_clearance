@echo off
title CleanMyPC - Launcher
color 0A

echo.
echo  =========================================
echo   CleanMyPC - Junk File Remover
echo   Images and Videos are NEVER touched
echo  =========================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo.
    echo  Please install Python from: https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b
)

echo  Starting CleanMyPC...
echo  (A window will open shortly)
echo.
python "%~dp0CleanMyPC.py"

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo  [ERROR] Something went wrong. Make sure Python is installed correctly.
    pause
)
