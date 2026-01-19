@echo off
setlocal EnableExtensions EnableDelayedExpansion
title ANANTA OSINT - Launcher

:: -------- CONFIG --------
set "WEBUI_DIR=C:\Users\guilh\Desktop\Dossier perso\nas-akasha\Projet\IA\code\text-generation-webui"
set "FASTAPI_DIR=C:\Users\guilh\Desktop\Dossier perso\nas-akasha\Projet\IA\code"

echo ========================================
echo   ANANTA OSINT - DEMARRAGE
echo ========================================
echo.

:: -------- CHECK CHEMINS --------
echo [1/5] Verification des chemins...
if not exist "%FASTAPI_DIR%" (
    echo ERREUR: FASTAPI_DIR introuvable
    goto :error
)

if not exist "%WEBUI_DIR%" (
    echo ERREUR: WEBUI_DIR introuvable
    goto :error
)
echo OK
timeout /t 2 /nobreak > nul

:: -------- REDIS / MEMURAI --------
echo.
echo [2/5] Verification de Redis (Memurai)...
sc query memurai >nul 2>&1

if %errorlevel% equ 0 (
    for /f "tokens=3" %%S in ('sc query memurai ^| findstr /i "STATE"') do set "STATE=%%S"
    if /i "!STATE!"=="RUNNING" (
        echo Redis OK
    ) else (
        echo Demarrage Redis...
        net start memurai >nul 2>&1
    )
) else (
    echo Redis (Memurai) non detecte
)
timeout /t 2 /nobreak > nul

:: -------- FASTAPI --------
echo.
echo [3/5] Lancement FastAPI...
start "FastAPI" cmd /k "cd /d ""%FASTAPI_DIR%"" && python -m uvicorn main:app --host 0.0.0.0 --port 8010 --reload"
timeout /t 3 /nobreak > nul

:: -------- LLM / WEBUI --------
echo.
echo [4/5] Lancement LLM local (DeepSeek)...
start "DeepSeek LLM" cmd /k "cd /d ""%WEBUI_DIR%"" && python server.py --model deepseek-llm-7b-chat --api --nowebui --gpu-memory 7GiB --load-in-4bit"
timeout /t 3 /nobreak > nul

:: -------- CELERY WORKER --------
echo.
echo [5/5] Lancement Worker Celery...
cd /d "%FASTAPI_DIR%"
start "Ananta Worker" cmd /k "cd /d ""%FASTAPI_DIR%"" && celery -A tasks worker -Q default,osint_fast,osint_medium,osint_critical,priority,maintenance -c 4 -n worker@%%h --loglevel=info --pool=solo"
timeout /t 2 /nobreak > nul

:: -------- INIT DB --------
echo.
echo Initialisation BDD...
python -c "from database import init_db; init_db()" 2>nul
echo OK

echo.
echo ========================================
echo   ANANTA DEMARRE
echo ========================================
echo.
echo   FastAPI : http://localhost:8010
echo   Web UI  : http://localhost:8010/web/html/index.html
echo   LLM API : http://localhost:5000
echo.
echo   3 fenetres ouvertes (FastAPI, LLM, Worker)
echo   Pour arreter: stop_all.bat
echo ========================================
echo.
goto :stay

:error
echo.
echo ========================================
echo   ERREUR - Verifiez les chemins
echo ========================================

:stay
echo.
echo Appuyez sur une touche pour fermer cette fenetre...
pause > nul
cmd /k
