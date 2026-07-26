@echo off
cd /d "%~dp0"

netstat -ano | findstr ":8000" | findstr "LISTENING" >nul
if %errorlevel%==0 (
    echo Bridge NG is already running - opening it in your browser.
    start "" http://localhost:8000/
) else (
    echo Starting Bridge NG server...
    start "" http://localhost:8000/
    python server.py
    pause
)
