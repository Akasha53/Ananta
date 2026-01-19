@echo off
title ANANTA OSINT - Launcher

set "WEBUI_DIR=C:\Users\guilh\Desktop\Dossier perso\nas-akasha\Projet\IA\code\text-generation-webui"
set "FASTAPI_DIR=C:\Users\guilh\Desktop\Dossier perso\nas-akasha\Projet\IA\code"

echo ========================================
echo   ANANTA OSINT - DEMARRAGE
echo ========================================
echo.

echo [1/5] Verification des chemins...
if not exist "%FASTAPI_DIR%\main.py" (
    echo ERREUR: main.py introuvable
    pause
    exit /b 1
)
echo OK

echo.
echo [2/5] Redis (Memurai)...
sc query memurai >nul 2>&1
if errorlevel 1 (
    echo Redis non detecte - continuons quand meme
) else (
    echo Redis OK
)

echo.
echo [3/5] Lancement FastAPI...
start "FastAPI" cmd /k "cd /d "%FASTAPI_DIR%" && python -m uvicorn main:app --host 0.0.0.0 --port 8010 --reload"
timeout /t 3 /nobreak >nul

echo.
echo [4/5] Lancement LLM (DeepSeek)...
start "DeepSeek LLM" cmd /k "cd /d "%WEBUI_DIR%" && python server.py --model-dir "%WEBUI_DIR%\models" --model deepseek-llm-7b-chat --api --nowebui --load-in-4bit"
timeout /t 3 /nobreak >nul

echo.
echo [5/5] Lancement Worker Celery...
start "Ananta Worker" cmd /k "cd /d "%FASTAPI_DIR%" && celery -A tasks worker -Q default,osint_fast,osint_medium,osint_critical,priority,maintenance -c 4 -n worker@%%h --loglevel=info --pool=solo"
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
echo.
echo   3 fenetres ouvertes (FastAPI, LLM, Worker)
echo   Pour arreter: stop_all.bat
echo ========================================
echo.
pause
