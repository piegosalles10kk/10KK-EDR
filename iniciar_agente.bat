@echo off
chcp 65001 >nul
title EDR Ultra Agent v1.0 - Inicializador

echo.
echo ═══════════════════════════════════════════════════════════════
echo   🛡️  EDR ULTRA AGENT v1.0 - CONFIGURAÇÃO RÁPIDA
echo ═══════════════════════════════════════════════════════════════
echo.

REM Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python não encontrado!
    echo    Instale Python 3.8+ de: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo ✓ Python detectado

REM Verificar dependências
echo.
echo Verificando dependências...
python -c "import psutil, requests" >nul 2>&1
if errorlevel 1 (
    echo ⚠ Instalando dependências necessárias...
    pip install psutil requests --quiet
    if errorlevel 1 (
        echo ❌ Erro ao instalar dependências
        pause
        exit /b 1
    )
    echo ✓ Dependências instaladas
) else (
    echo ✓ Dependências OK
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo   CONFIGURAÇÃO DO SERVIDOR
echo ═══════════════════════════════════════════════════════════════
echo.

REM Modo de operação
echo Escolha o modo de operação:
echo.
echo   [1] Servidor LOCAL (localhost:8000)
echo   [2] Servidor na REDE (digitar IP)
echo   [3] Configuração AVANÇADA
echo.
set /p MODE="Digite sua escolha (1-3): "

if "%MODE%"=="1" (
    set SERVER=http://localhost:8000
    set INTERVAL=60
    echo.
    echo ✓ Modo: Servidor Local
    echo ✓ URL: %SERVER%
    goto :START
)

if "%MODE%"=="2" (
    echo.
    set /p SERVER_IP="Digite o IP do servidor (ex: 192.168.1.100): "
    set SERVER=http://%SERVER_IP%:8000
    set INTERVAL=60
    echo.
    echo ✓ Servidor: %SERVER%
    goto :START
)

if "%MODE%"=="3" (
    echo.
    set /p SERVER="Digite a URL completa do servidor: "
    set /p INTERVAL="Intervalo de coleta em segundos (padrão 60): "
    if "%INTERVAL%"=="" set INTERVAL=60
    goto :START
)

echo ❌ Opção inválida!
pause
exit /b 1

:START
echo.
echo ═══════════════════════════════════════════════════════════════
echo   TESTANDO CONEXÃO COM O SERVIDOR
echo ═══════════════════════════════════════════════════════════════
echo.

REM Testar conexão
echo Testando: %SERVER%/health
python -c "import requests; r = requests.get('%SERVER%/health', timeout=5); print('✓ Servidor respondeu:', r.status_code)" 2>nul
if errorlevel 1 (
    echo.
    echo ⚠ Não foi possível conectar ao servidor!
    echo.
    echo Possíveis causas:
    echo   • Servidor não está rodando
    echo   • IP/URL incorreto
    echo   • Firewall bloqueando
    echo   • Servidor não está acessível desta rede
    echo.
    set /p CONTINUE="Deseja continuar mesmo assim? (S/N): "
    if /i not "%CONTINUE%"=="S" (
        echo Operação cancelada.
        pause
        exit /b 1
    )
) else (
    echo ✓ Conexão estabelecida com sucesso!
)

echo.
echo ═══════════════════════════════════════════════════════════════
echo   INICIANDO AGENTE
echo ═══════════════════════════════════════════════════════════════
echo.
echo Configuração:
echo   • Servidor: %SERVER%
echo   • Intervalo: %INTERVAL% segundos
echo   • Log: edr_agent.log
echo.
echo Pressione Ctrl+C para encerrar o agente
echo.
timeout /t 3 /nobreak >nul

REM Iniciar agente
python edr-agent-lite.py --server %SERVER% --interval %INTERVAL%

echo.
echo ═══════════════════════════════════════════════════════════════
echo   AGENTE ENCERRADO
echo ═══════════════════════════════════════════════════════════════
pause