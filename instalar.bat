@echo off
chcp 65001 >nul
echo ================================================================
echo   EDR AVANÇADO v3.0 - INSTALADOR AUTOMÁTICO PARA WINDOWS
echo ================================================================
echo.

echo [1/4] Verificando Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERRO: Python não encontrado!
    echo.
    echo Por favor, instale Python 3.8+ de: https://www.python.org/downloads/
    echo Marque a opção "Add Python to PATH" durante instalação!
    pause
    exit /b 1
)

python --version
echo ✓ Python encontrado!
echo.

echo [2/4] Atualizando pip...
python -m pip install --upgrade pip --quiet
echo ✓ pip atualizado!
echo.

echo [3/4] Instalando dependências...
echo    Isso pode levar alguns minutos...
echo.

pip install pandas numpy scikit-learn joblib requests --quiet
if errorlevel 1 (
    echo ❌ Erro na instalação!
    echo Tentando novamente sem cache...
    pip install pandas numpy scikit-learn joblib requests --no-cache-dir
)

echo ✓ Dependências instaladas!
echo.

echo [4/4] Verificando instalação...
python -c "import pandas, numpy, sklearn, joblib, requests; print('✓ Todas as bibliotecas OK!')"
if errorlevel 1 (
    echo ❌ Erro na verificação!
    pause
    exit /b 1
)
echo.

echo ================================================================
echo   INSTALAÇÃO CONCLUÍDA COM SUCESSO!
echo ================================================================
echo.
echo Próximos passos:
echo   1. Execute: python treinador-v3-windows-fixed.py
echo   2. Aguarde 2-4 minutos para o treinamento
echo   3. Execute: python jogador-v3-avancado.py
echo.
echo ================================================================
pause