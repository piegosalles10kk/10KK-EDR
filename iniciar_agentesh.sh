#!/bin/bash

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════"
echo "  🛡️  EDR ULTRA AGENT v1.0 - CONFIGURAÇÃO RÁPIDA"
echo "═══════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python não encontrado!${NC}"
    echo "   Instale Python 3.8+ com: sudo apt install python3 python3-pip"
    exit 1
fi
echo -e "${GREEN}✓ Python detectado${NC}"

# Verificar dependências
echo ""
echo "Verificando dependências..."
python3 -c "import psutil, requests" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠ Instalando dependências necessárias...${NC}"
    pip3 install psutil requests --quiet
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ Erro ao instalar dependências${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Dependências instaladas${NC}"
else
    echo -e "${GREEN}✓ Dependências OK${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════"
echo "  CONFIGURAÇÃO DO SERVIDOR"
echo "═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Modo de operação
echo "Escolha o modo de operação:"
echo ""
echo "  [1] Servidor LOCAL (localhost:8000)"
echo "  [2] Servidor na REDE (digitar IP)"
echo "  [3] Configuração AVANÇADA"
echo ""
read -p "Digite sua escolha (1-3): " MODE

if [ "$MODE" == "1" ]; then
    SERVER="http://localhost:8000"
    INTERVAL=60
    echo ""
    echo -e "${GREEN}✓ Modo: Servidor Local${NC}"
    echo -e "${GREEN}✓ URL: $SERVER${NC}"
elif [ "$MODE" == "2" ]; then
    echo ""
    read -p "Digite o IP do servidor (ex: 192.168.1.100): " SERVER_IP
    SERVER="http://${SERVER_IP}:8000"
    INTERVAL=60
    echo ""
    echo -e "${GREEN}✓ Servidor: $SERVER${NC}"
elif [ "$MODE" == "3" ]; then
    echo ""
    read -p "Digite a URL completa do servidor: " SERVER
    read -p "Intervalo de coleta em segundos (padrão 60): " INTERVAL
    [ -z "$INTERVAL" ] && INTERVAL=60
else
    echo -e "${RED}❌ Opção inválida!${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════"
echo "  TESTANDO CONEXÃO COM O SERVIDOR"
echo "═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Testar conexão
echo "Testando: ${SERVER}/health"
python3 -c "import requests; r = requests.get('${SERVER}/health', timeout=5); print('✓ Servidor respondeu:', r.status_code)" 2>/dev/null

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${YELLOW}⚠ Não foi possível conectar ao servidor!${NC}"
    echo ""
    echo "Possíveis causas:"
    echo "  • Servidor não está rodando"
    echo "  • IP/URL incorreto"
    echo "  • Firewall bloqueando"
    echo "  • Servidor não está acessível desta rede"
    echo ""
    read -p "Deseja continuar mesmo assim? (s/n): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Ss]$ ]]; then
        echo "Operação cancelada."
        exit 1
    fi
else
    echo -e "${GREEN}✓ Conexão estabelecida com sucesso!${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════"
echo "  INICIANDO AGENTE"
echo "═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Configuração:"
echo "  • Servidor: $SERVER"
echo "  • Intervalo: $INTERVAL segundos"
echo "  • Log: edr_agent.log"
echo ""
echo "Pressione Ctrl+C para encerrar o agente"
echo ""
sleep 3

# Iniciar agente
python3 edr-agent-lite.py --server "$SERVER" --interval "$INTERVAL"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════"
echo "  AGENTE ENCERRADO"
echo "═══════════════════════════════════════════════════════════════${NC}"