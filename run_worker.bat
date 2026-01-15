@echo off
title The APEX - Celery Worker
echo [+] Iniciando Celery Worker...
echo [+] Certifique-se de que o Redis esta rodando (localhost:6379).
echo.
celery -A app.tasks worker --loglevel=info
pause
