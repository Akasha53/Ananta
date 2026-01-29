@echo off
REM ============================================================================
REM Ananta - Stop All Services
REM Arrête tous les services Ananta (FastAPI, LLM, Workers)
REM ============================================================================

title ANANTA - Arret des Services

echo.
echo ========================================
echo   ANANTA - ARRET DE TOUS LES SERVICES
echo ========================================
echo.

echo [1/3] Arret des Workers Celery...
REM Fermer les fenêtres des workers par leur titre
taskkill /FI "WINDOWTITLE eq Ananta Worker*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq Ananta Celery Beat*" /T /F >nul 2>&1
taskkill /F /IM celery.exe >nul 2>&1
echo Workers Celery arretes

timeout /t 2 /nobreak > nul

echo.
echo [2/3] Arret du Backend FastAPI...
taskkill /FI "WINDOWTITLE eq FastAPI*" /T /F >nul 2>&1
REM Fallback: arrêter uvicorn sur port 8010
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8010 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo FastAPI arrete

timeout /t 2 /nobreak > nul

echo.
echo [3/3] Arret du LLM (Mistral)...
taskkill /FI "WINDOWTITLE eq Mistral LLM*" /T /F >nul 2>&1
REM Fallback: arrêter sur port 5000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo LLM arrete

echo.
echo ========================================
echo   TOUS LES SERVICES SONT ARRETES
echo ========================================
echo.
echo Redis (Memurai) reste actif (service Windows)
echo Pour l'arreter: net stop memurai (droits admin requis)
echo.

pause
