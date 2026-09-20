@echo off
cd /d "%~dp0"

rem ------------------------------------------------------------
rem Check for administrator privileges
rem (fltmc only works from an elevated prompt)
rem ------------------------------------------------------------
fltmc >nul 2>&1
if errorlevel 1 (
    echo.
    echo ============================================================
    echo   WARNING: this script was NOT started as administrator.
    echo.
    echo   Please run it again as administrator:
    echo   right-click this file, then "Run as administrator".
    echo ============================================================
    echo.
    pause
    exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%~dp0falso_positivo.ps1"
pause
