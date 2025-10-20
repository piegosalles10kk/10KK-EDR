@echo off
chcp 65001 >nul
title EDR Ultra v4.0 - Infraestrutura Completa

echo.
echo ═══════════════════════════════════════════════════════════════
echo   🛡️  EDR ULTRA v4.0 - INICIALIZAÇÃO DA INFRAESTRUTURA
echo ═══════════════════════════════════════════════════════════════
echo.

echo [1/5] Verificando ambiente...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python não encontrado!
    pause
    exit /b 1
)
echo ✓ Python OK

echo.
echo [2/5] Instalando dependências extras...
pip install flask fastapi uvicorn psutil --quiet
if errorlevel 1 (
    echo ⚠ Algumas dependências podem ter falhado
) else (
    echo ✓ Dependências instaladas
)

echo.
echo [3/5] Verificando modelos treinados...
if not exist "modelos\ensemble_v4.joblib" (
    echo.
    echo ⚠ Modelos não encontrados! Treinando agora...
    echo Isso levará 2-4 minutos...
    echo.
    python treinador-v4-ultra.py --quick
    if errorlevel 1 (
        echo ❌ Erro no treinamento!
        pause
        exit /b 1
    )
) else (
    echo ✓ Modelos encontrados
)

echo.
echo [4/5] Criando estrutura de diretórios...
if not exist "logs" mkdir logs
if not exist "alertas" mkdir alertas
if not exist "dados" mkdir dados
if not exist "metricas" mkdir metricas
echo ✓ Diretórios criados

echo.
echo [5/5] Iniciando serviços...
echo.
echo ═══════════════════════════════════════════════════════════════
echo   ✅ INFRAESTRUTURA PRONTA!
echo ═══════════════════════════════════════════════════════════════
echo.
echo Escolha o modo de operação:
echo.
echo   [1] 📊 DASHBOARD    - Dashboard web em tempo real
echo   [2] 🎯 DEMO         - Demonstração com eventos de teste
echo   [3] 🌐 API          - Servidor API REST
echo   [4] 🔄 DAEMON       - Monitoramento contínuo do sistema
echo   [5] 📋 TUDO         - Dashboard + API + Daemon
echo.
set /p choice="Digite sua escolha (1-5): "

if "%choice%"=="1" goto dashboard
if "%choice%"=="2" goto demo
if "%choice%"=="3" goto api
if "%choice%"=="4" goto daemon
if "%choice%"=="5" goto tudo
goto fim

:dashboard
echo.
echo 🚀 Iniciando Dashboard...
echo 🔗 Acesse: http://localhost:5000
echo.
start http://localhost:5000
python dashboard-edr-v4.py
goto fim

:demo
echo.
echo 🎯 Executando demonstração...
echo.
python jogador-v4-operacional.py --mode demo
goto fim

:api
echo.
echo 🚀 Iniciando API REST...
echo 🔗 API: http://localhost:8000
echo 📖 Docs: http://localhost:8000/docs
echo.
start http://localhost:8000/docs
python jogador-v4-operacional.py --mode api --port 8000
goto fim

:daemon
echo.
echo 🔄 Iniciando Daemon...
echo Monitoramento a cada 60 segundos
echo Pressione Ctrl+C para encerrar
echo.
python jogador-v4-operacional.py --mode daemon --interval 60
goto fim

:tudo
echo.
echo 🚀 Iniciando TODOS os serviços...
echo.
echo Abrindo 3 terminais:
echo   Terminal 1: Dashboard (porta 5000)
echo   Terminal 2: API (porta 8000)
echo   Terminal 3: Daemon (monitoramento)
echo.

start "EDR Dashboard" cmd /k "python dashboard-edr-v4.py"
timeout /t 3 /nobreak >nul
start "EDR API" cmd /k "python jogador-v4-operacional.py --mode api --port 8000"
timeout /t 3 /nobreak >nul
start "EDR Daemon" cmd /k "python jogador-v4-operacional.py --mode daemon --interval 60"

echo.
echo ✅ Todos os serviços iniciados!
echo.
echo 🔗 Dashboard: http://localhost:5000
echo 🔗 API: http://localhost:8000/docs
echo.
echo Pressione qualquer tecla para voltar ao menu...
pause >nul
goto fim

:fim
echo.
echo ═══════════════════════════════════════════════════════════════
echo   Obrigado por usar o EDR Ultra v4.0!
echo ═══════════════════════════════════════════════════════════════
echo.
pause