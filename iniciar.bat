@echo off
setlocal enabledelayedexpansion
title THE APEX - Core Server

where python >nul 2>&1 || (echo [!] Python nao encontrado no PATH & pause & goto end)

echo [+] Instalando/Atualizando dependencias...
python -m pip install -r requirements.txt

echo [+] Iniciando The APEX Core...
python initializer.py

if %ERRORLEVEL% neq 0 (
    echo [!] O servidor encerrou com erro (%ERRORLEVEL%).
) else (
    echo [+] Servidor encerrado.
)

pause

:end
endlocal
exit /b 0
