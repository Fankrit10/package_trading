@echo off
setlocal enabledelayedexpansion

echo.
echo ====================================
echo   Vulnerability Detection System
echo ====================================
echo.

python -c "import streamlit" >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Streamlit not installed.
    echo Run: pip install streamlit
    pause
    exit /b 1
)

echo.
echo Starting both applications...
echo.
echo Security Remediation System: http://localhost:8501
echo Vulnerability Detection System: http://localhost:8502
echo.

REM Start app_gui.py on port 8501
start cmd /k streamlit run app_gui.py --server.port=8501

REM Wait 2 seconds for first app to start
timeout /t 2 /nobreak

REM Start app_gui_detect.py on port 8502
start cmd /k streamlit run app_gui_detect.py --server.port=8502

echo.
echo Both applications are starting in separate windows.
echo.
pause

