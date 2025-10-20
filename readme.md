# 🌐 Guia Completo - Arquitetura EDR com Agentes Distribuídos

## 📋 Visão Geral

Sistema EDR Ultra com arquitetura **cliente-servidor**, onde:
- **Servidor Central**: Processa análises com IA (precisa dos modelos)
- **Agentes Leves**: Coletam telemetria e enviam ao servidor (sem modelos)

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│                    REDE CORPORATIVA                      │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Máquina 1   │  │  Máquina 2   │  │  Máquina N   │  │
│  │              │  │              │  │              │  │
│  │ Agent v1.0   │  │ Agent v1.0   │  │ Agent v1.0   │  │
│  │ (~50MB RAM)  │  │ (~50MB RAM)  │  │ (~50MB RAM)  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │           │
│         └─────────────────┼─────────────────┘           │
│                           │                             │
│                           ▼                             │
│                  ┌─────────────────┐                    │
│                  │ Servidor EDR    │                    │
│                  │                 │                    │
│                  │ • Modelos ML    │                    │
│                  │ • Análise IA    │                    │
│                  │ • Dashboard     │                    │
│                  │ • API REST      │                    │
│                  └─────────────────┘                    │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Setup do Servidor Central

### Passo 1: Preparar Máquina Servidor

**Requisitos:**
- ✅ Python 3.8+
- ✅ 4GB RAM (8GB recomendado)
- ✅ 2GB disco
- ✅ Ubuntu/Windows Server

```bash
# Instalar dependências
pip install pandas numpy scikit-learn joblib requests fastapi uvicorn psutil flask

# Estrutura de diretórios
mkdir edr-server
cd edr-server
```

### Passo 2: Treinar Modelos (Apenas Uma Vez)

```bash
# Copiar treinador e executar
python treinador-v4-ultra.py --quick

# Arquivos gerados em modelos/:
# - scaler_v4.joblib
# - ensemble_v4.joblib
# - anomaly_v4.joblib
# - features_v4.joblib
# - mitre_mapping_v4.joblib
```

### Passo 3: Iniciar Servidor

```bash
# Opção 1: API REST (para agentes)
python jogador-v5-operacional.py --mode api --port 8000 --host 0.0.0.0 --enable-agents

# Opção 2: API + Dashboard (completo)
# Terminal 1:
python jogador-v5-operacional.py --mode api --port 8000 --host 0.0.0.0 --enable-agents

# Terminal 2:
python dashboard-edr-v5.py
```

**Servidor estará rodando em:**
- 🌐 API: `http://IP_SERVIDOR:8000`
- 📊 Dashboard: `http://IP_SERVIDOR:5000`
- 📖 Docs: `http://IP_SERVIDOR:8000/docs`

---

## 📦 Setup dos Agentes (Máquinas Cliente)

### Passo 1: Instalar Apenas o Agente

**Requisitos mínimos:**
- ✅ Python 3.8+
- ✅ 50MB RAM
- ✅ ~5% CPU

```bash
# Instalar dependências mínimas (SEM scikit-learn!)
pip install psutil requests

# Copiar apenas o agente
# Não precisa dos modelos nem do treinador!
```

### Passo 2: Executar Agente

**Windows:**
```powershell
# Conectar ao servidor
python edr-agent-lite.py --server http://192.168.1.100:8000 --interval 60

# Executar como serviço (background)
pythonw edr-agent-lite.py --server http://IP_SERVIDOR:8000 --interval 300
```

**Linux:**
```bash
# Conectar ao servidor
python3 edr-agent-lite.py --server http://192.168.1.100:8000 --interval 60

# Executar como daemon
nohup python3 edr-agent-lite.py --server http://IP_SERVIDOR:8000 --interval 300 > /dev/null 2>&1 &
```

**Argumentos disponíveis:**
- `--server`: URL do servidor (OBRIGATÓRIO)
- `--interval`: Intervalo de coleta em segundos (padrão: 60)
- `--agent-id`: ID customizado (gerado automaticamente)
- `--log-file`: Arquivo de log (padrão: edr_agent.log)

---

## 🔧 Configuração Avançada

### Servidor como Serviço (Linux)

```bash
# Criar arquivo de serviço
sudo nano /etc/systemd/system/edr-server.service
```

```ini
[Unit]
Description=EDR Ultra Server
After=network.target

[Service]
Type=simple
User=edr
WorkingDirectory=/opt/edr-server
ExecStart=/usr/bin/python3 jogador-v5-operacional.py --mode api --port 8000 --host 0.0.0.0 --enable-agents
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Ativar serviço
sudo systemctl enable edr-server
sudo systemctl start edr-server
sudo systemctl status edr-server
```

### Agente como Serviço (Windows)

```powershell
# Usar NSSM (Non-Sucking Service Manager)
# Download: https://nssm.cc/download

nssm install EDRAgent
# Program: C:\Python39\python.exe
# Arguments: C:\edr\edr-agent-lite.py --server http://192.168.1.100:8000
# Startup directory: C:\edr

nssm start EDRAgent
```

### Agente como Serviço (Linux)

```bash
# Criar arquivo de serviço
sudo nano /etc/systemd/system/edr-agent.service
```

```ini
[Unit]
Description=EDR Ultra Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/edr/edr-agent-lite.py --server http://192.168.1.100:8000 --interval 60
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable edr-agent
sudo systemctl start edr-agent
```

---

## 📊 Monitoramento

### Verificar Agentes Conectados

**Via Dashboard:**
```
http://IP_SERVIDOR:5000
```

**Via API:**
```bash
curl http://IP_SERVIDOR:8000/agents/list
```

**Resposta:**
```json
{
  "total": 5,
  "agentes": {
    "agent_WS-001_a1b2c3d4": {
      "hostname": "WS-001",
      "sistema_operacional": "Windows",
      "ip_address": "192.168.1.101",
      "ultima_conexao": "2025-10-20T15:30:45",
      "eventos_enviados": 234,
      "ameacas_detectadas": 2
    }
  }
}
```

### Ver Estatísticas Gerais

```bash
curl http://IP_SERVIDOR:8000/stats
```

```json
{
  "total_analisados": 15234,
  "ameacas_detectadas": 45,
  "alertas_criticos": 8,
  "alertas_altos": 37,
  "tempo_medio_ms": 87.3,
  "agentes_conectados": 5,
  "ultima_atualizacao": "2025-10-20T15:45:30"
}
```

---

## 🔥 Casos de Uso

### Caso 1: Pequena Rede (5-10 máquinas)

**Setup:**
- 1 servidor (pode ser VM)
- Agentes em todas as máquinas

**Comando servidor:**
```bash
python jogador-v5-operacional.py --mode api --port 8000 --enable-agents &
python dashboard-edr-v5.py &
```

**Comando agentes:**
```bash
python edr-agent-lite.py --server http://192.168.1.100:8000 --interval 300
```

### Caso 2: Rede Média (50+ máquinas)

**Setup:**
- 1 servidor dedicado (4 cores, 8GB RAM)
- Agentes em todas as máquinas
- Load balancer opcional

**Otimizações:**
- Aumentar intervalo dos agentes (300s)
- Configurar cache no servidor
- Monitorar uso de CPU/RAM

### Caso 3: Multi-Site

**Setup:**
- 1 servidor central
- Agentes em sites remotos via VPN/WAN

**Configurações:**
```bash
# Agente com timeout maior
python edr-agent-lite.py \
  --server https://edr-central.empresa.com:8000 \
  --interval 600
```

---

## 🛡️ Segurança

### Servidor

1. **Firewall:**
```bash
# Permitir apenas rede interna
sudo ufw allow from 192.168.1.0/24 to any port 8000
```

2. **HTTPS (Recomendado):**
```bash
# Usar nginx como proxy reverso com SSL
# Ou usar certificados Let's Encrypt
```

3. **Autenticação (Futuro):**
- API Keys por agente
- Token JWT
- Certificados mútuo (mTLS)

### Agentes

1. **Permissões Mínimas:**
- Executar com usuário limitado
- Acesso read-only ao sistema

2. **Validação de Servidor:**
```python
# Adicionar verificação de certificado SSL
requests.post(url, json=data, verify=True)
```

---

## 🐛 Troubleshooting

### Agente não conecta ao servidor

```bash
# Verificar conectividade
ping IP_SERVIDOR
telnet IP_SERVIDOR 8000

# Verificar se servidor está rodando
curl http://IP_SERVIDOR:8000/health

# Ver logs do agente
tail -f edr_agent.log
```

### Servidor não responde

```bash
# Verificar se está rodando
ps aux | grep jogador

# Ver logs
tail -f logs/deteccao_20251020.log

# Verificar porta
netstat -tuln | grep 8000
```

### Alta latência

**Sintomas:** Tempo de análise > 1000ms

**Soluções:**
```bash
# 1. Aumentar intervalo dos agentes
python edr-agent-lite.py --server URL --interval 600

# 2. Aumentar recursos do servidor
# 3. Otimizar modelos (usar --quick no treino)

# 4. Adicionar cache no servidor (futuro)
```

---

## 📈 Performance

### Métricas Esperadas

| Métrica | Valor |
|---------|-------|
| Tempo análise/evento | 50-200ms |
| RAM servidor | 500MB-2GB |
| CPU servidor | 10-30% |
| RAM agente | 30-60MB |
| CPU agente | 2-5% |
| Throughput | 100+ eventos/s |

### Escalabilidade

| Agentes | Servidor Recomendado |
|---------|---------------------|
| 1-10 | 2 cores, 4GB RAM |
| 11-50 | 4 cores, 8GB RAM |
| 51-200 | 8 cores, 16GB RAM |
| 200+ | Cluster / Load Balancer |

---

## ✅ Checklist de Deploy

**Servidor:**
- [ ] Python 3.8+ instalado
- [ ] Dependências instaladas
- [ ] Modelos treinados (modelos/*.joblib)
- [ ] Firewall configurado
- [ ] API rodando (porta 8000)
- [ ] Dashboard rodando (porta 5000)
- [ ] Health check OK (`/health`)

**Agentes:**
- [ ] Python 3.8+ instalado
- [ ] psutil e requests instalados
- [ ] Conectividade com servidor OK
- [ ] Agente registrado (`/agents/register`)
- [ ] Logs sendo gerados
- [ ] Telemetria sendo enviada

---

## 🎯 Próximos Passos

### Melhorias Futuras

1. **Autenticação:**
   - API Keys
   - OAuth2
   - Certificados mútuo

2. **Criptografia:**
   - TLS/SSL obrigatório
   - Criptografia de dados em trânsito

3. **Persistência:**
   - Banco de dados (PostgreSQL)
   - TimeSeries DB (InfluxDB)
   - Elasticsearch para logs

4. **Alertas:**
   - Email
   - Slack/Teams
   - Webhook customizado
   - SMS (Twilio)

5. **Resposta Automática:**
   - Bloquear IP
   - Matar processo
   - Isolar máquina

6. **Machine Learning:**
   - Retreinamento automático
   - Aprendizado federado
   - Modelos personalizados por cliente

---

## 📞 Comandos Úteis

```bash
# Servidor
python jogador-v5-operacional.py --mode api --port 8000 --enable-agents

# Agente
python edr-agent-lite.py --server http://IP:8000 --interval 60

# Dashboard
python dashboard-edr-v5.py

# Health check
curl http://IP:8000/health

# Listar agentes
curl http://IP:8000/agents/list

# Estatísticas
curl http://IP:8000/stats

# Testar envio manual
curl -X POST http://IP:8000/analyze \
  -H "Content-Type: application/json" \
  -H "agente-id: test-agent" \
  -d '{"process_id_count": 50, ...}'
```

---

## 🎉 Conclusão

Você agora tem uma **arquitetura EDR distribuída e escalável**:

✅ **Servidor central** com IA processando análises  
✅ **Agentes leves** coletando telemetria  
✅ **Comunicação via API REST**  
✅ **Dashboard em tempo real**  
✅ **Suporte a múltiplos agentes**  
✅ **Fácil de escalar**  

**Total de instalação em nova máquina:**
- Servidor: ~2GB (modelos + deps)
- Agente: ~100MB (apenas deps leves)

**Economia:** Não precisa instalar scikit-learn e modelos em cada máquina! 🚀