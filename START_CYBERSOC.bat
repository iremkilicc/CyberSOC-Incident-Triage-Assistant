@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

rem Usage:
rem   START_CYBERSOC.bat          normal launch (no console window)
rem   START_CYBERSOC.bat debug    launch with console output and the QML log

set "DEBUG_MODE=0"
if /i "%~1"=="debug" set "DEBUG_MODE=1"

if "%DEBUG_MODE%"=="1" (
    title CyberSOC Debug
) else (
    title CyberSOC Incident Triage Assistant
)

where foundry >nul 2>&1
if errorlevel 1 (
    echo ERROR: Microsoft Foundry Local is not installed.
    echo Install it with: winget install Microsoft.FoundryLocal
    pause
    exit /b 1
)

if exist ".venv-qml\Scripts\python.exe" goto start_server

echo Creating the CyberSOC environment...
py -3.13 -m venv .venv-qml 2>nul
if errorlevel 1 py -3.12 -m venv .venv-qml 2>nul
if errorlevel 1 py -3 -m venv .venv-qml 2>nul
if not exist ".venv-qml\Scripts\python.exe" (
    echo ERROR: A compatible 64-bit Python installation could not be found.
    echo Install Python 3.12 or newer and enable the Python launcher.
    pause
    exit /b 1
)

echo Installing requirements...
".venv-qml\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto setup_error
".venv-qml\Scripts\python.exe" -m pip install -r requirements-qml.txt
if errorlevel 1 goto setup_error

:start_server
echo Starting Foundry Local server...
if "%DEBUG_MODE%"=="1" (
    foundry server start
) else (
    foundry server start >nul 2>&1
)
if errorlevel 1 (
    echo ERROR: Foundry Local server could not be started.
    pause
    exit /b 1
)

if exist "data\knowledge_index.db" goto launch_app
echo Creating the local knowledge index for first run...
".venv-qml\Scripts\python.exe" "src\ingest_knowledge_base.py"
if errorlevel 1 (
    echo ERROR: The local knowledge index could not be created.
    echo Run this launcher in debug mode for details.
    pause
    exit /b 1
)

:launch_app

del /q "qml_preview_error.log" 2>nul

if "%DEBUG_MODE%"=="1" goto run_debug

start "CyberSOC" ".venv-qml\Scripts\pythonw.exe" "qml_preview\main.py"
exit /b 0

:run_debug
echo.
echo Launching CyberSOC with console output...
".venv-qml\Scripts\python.exe" "qml_preview\main.py"
echo.
echo Exit code: %errorlevel%
if exist "qml_preview_error.log" (
    echo.
    echo ---------- QML LOG ----------
    type "qml_preview_error.log"
)
pause
exit /b 0

:setup_error
echo.
echo ERROR: The CyberSOC environment could not be installed.
pause
exit /b 1
