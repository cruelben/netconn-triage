@echo off
cd /d "%~dp0"

rem ------------------------------------------------------------
rem Verifica privilegi di amministratore
rem (fltmc funziona solo da prompt con privilegi elevati)
rem ------------------------------------------------------------
fltmc >nul 2>&1
if errorlevel 1 (
    echo.
    echo ============================================================
    echo   ATTENZIONE: script NON avviato come amministratore.
    echo.
    echo   Avviare nuovamente come amministratore:
    echo   tasto destro su questo file, poi "Esegui come amministratore".
    echo ============================================================
    echo.
    pause
    exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%~dp0controllo-connessioni.ps1"
pause