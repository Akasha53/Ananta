@echo off
title ANANTA OSINT - Launcher

echo ========================================
echo   ANANTA OSINT - NETTOYAGE AVANT DEMARRAGE
echo ========================================

REM --- Kill FastAPI / Uvicorn (port 8010)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8010 ^| findstr LISTENING') do (
    echo Kill process on port 8010 - PID %%a
    taskkill /PID %%a /F >nul 2>&1
)

REM --- Kill LLM / text-generation-webui (port 5000)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
    echo Kill process on port 5000 - PID %%a
    taskkill /PID %%a /F >nul 2>&1
)

REM --- Kill Celery workers
taskkill /F /IM celery.exe >nul 2>&1

REM --- (Optionnel mais recommandé en dev) Kill python restants liés au projet
REM ATTENTION : commente cette ligne si tu as d'autres python importants ouverts
REM taskkill /F /IM python.exe >nul 2>&1

timeout /t 2 /nobreak >nul

echo Nettoyage termine.
echo.

REM Utiliser des chemins relatifs (basé sur l'emplacement du script)
set "FASTAPI_DIR=%~dp0"
set "FASTAPI_DIR=%FASTAPI_DIR:~0,-1%"
set "WEBUI_DIR=%FASTAPI_DIR%\text-generation-webui"
set "LLM_MODEL=mistralai_Mistral-7B-Instruct-v0.2"

echo ========================================
echo   ANANTA OSINT - DEMARRAGE
echo ========================================
echo.

echo [1/5] Verification des chemins...
if not exist "%FASTAPI_DIR%\main.py" (
    echo ERREUR: main.py introuvable
    call :pause_if_needed
    exit /b 1
)
echo OK

echo.
echo [2/5] Redis (Memurai)...
REM Fail fast if Redis isn't running, otherwise Celery jobs will stay PENDING.
powershell -Command "if ((Get-Service -Name 'Memurai').Status -eq 'Running') { exit 0 } else { exit 1 }"
if errorlevel 1 goto redis_error
echo Redis OK (RUNNING)
goto redis_ok

:redis_error
    echo ERREUR: Redis/Memurai n'est pas en cours d'execution.
    echo - Demarre Memurai (service "memurai") puis relance launch_all.bat
    call :pause_if_needed
    exit /b 1

:redis_ok

echo.
echo [3/5] Lancement FastAPI...
REM Note: --reload can cause WinError 10013 on some Windows systems.
REM If you get this error, use the NO_RELOAD version below instead.
REM The issue is related to watchfiles/antivirus conflicts.
REM 
REM Option A: With reload (development - may fail with WinError 10013)
REM start "FastAPI" cmd /k "cd /d "%FASTAPI_DIR%" && python -m uvicorn main:app --host 0.0.0.0 --port 8010 --reload"
REM 
REM Option B: Without reload (stable, recommended on Windows)
start "FastAPI" cmd /k "cd /d "%FASTAPI_DIR%" && python -m uvicorn main:app --host 0.0.0.0 --port 8010 --log-level info"
timeout /t 3 /nobreak >nul

echo.
echo [4/5] Lancement LLM (Mistral 7B - 32k context)...
start "Mistral LLM" cmd /k "cd /d "%WEBUI_DIR%" && python server.py --model-dir "%WEBUI_DIR%\models" --model %LLM_MODEL% --api --nowebui --load-in-4bit"
timeout /t 5 /nobreak >nul

echo.
echo [5/5] Lancement Worker Celery...
REM Use tasks.app explicitly to ensure we start the correct Celery application.
start "Ananta Worker" cmd /k "cd /d "%FASTAPI_DIR%" && python -m celery -A tasks.app worker -Q default,osint_fast,osint_medium,osint_critical,priority,maintenance -c 4 -n worker@%%h --loglevel=info --pool=solo"
timeout /t 2 /nobreak >nul

echo.
echo Init BDD...
cd /d "%FASTAPI_DIR%"
python -c "from database import init_db; init_db()" 2>nul

echo.
echo ========================================
echo   ANANTA DEMARRE
echo ========================================
echo.
echo   FastAPI : http://localhost:8010
echo   Web UI  : http://localhost:8010/web/html/index.html
echo   LLM API : http://localhost:5000
echo   Model   : %LLM_MODEL% (32k context)
echo.
echo   3 fenetres ouvertes (FastAPI, Mistral, Worker)
echo   Pour arreter: stop_all.bat
echo ========================================
echo.
call :pause_if_needed

:pause_if_needed
if "%NONINTERACTIVE%"=="1" goto :eof
if "%CI%"=="1" goto :eof
if /I "%CI%"=="true" goto :eof
pause
goto :eof
