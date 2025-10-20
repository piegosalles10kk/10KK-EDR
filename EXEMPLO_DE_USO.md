# 💡 Exemplos Práticos de Uso - EDR v3.0

## 📋 Índice

1. [Detecção de Ransomware](#exemplo-1-detecção-de-ransomware)
2. [Análise de Logs do Sysmon](#exemplo-2-integração-com-sysmon)
3. [Monitoramento de Processos em Tempo Real](#exemplo-3-monitoramento-contínuo)
4. [Análise Forense Pós-Incidente](#exemplo-4-análise-forense)
5. [Dashboard de Segurança](#exemplo-5-dashboard-simples)
6. [Integração com EDR Comercial](#exemplo-6-complementar-edr-existente)

---

## Exemplo 1: Detecção de Ransomware

### Cenário
Você suspeita que uma estação de trabalho está infectada com ransomware devido a atividade anormal de criptografia de arquivos.

### Coleta de Telemetria

```python
# coletar_telemetria_ransomware.py
import psutil
import time
import pandas as pd

def coletar_metricas_processo(process_name):
    """Coleta métricas de um processo específico."""
    
    metricas = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'num_threads']):
        try:
            if process_name.lower() in proc.info['name'].lower():
                
                # Contadores de I/O
                io = proc.io_counters()
                
                # Coleta de rede
                connections = len(proc.connections())
                
                metrica = {
                    'process_id_count': 1,
                    'process_cpu_usage': proc.info['cpu_percent'],
                    'disk_io_rate': (io.write_bytes + io.read_bytes) / (1024 * 1024),  # MB
                    'network_connections': connections,
                    'file_writes': io.write_count,
                    'duration_seconds': 60,  # Janela de 1 minuto
                    'memory_usage_mb': proc.info['memory_info'].rss / (1024 * 1024),
                    'thread_count': proc.info['num_threads'],
                    'registry_modifications': 0,  # Requer monitoramento específico
                    'dns_queries': 0,  # Requer sniffer de rede
                    'suspicious_ports': 0,  # Verificar portas não-padrão
                    'parent_process_anomaly': 0.0  # Analisar árvore de processos
                }
                
                metricas.append(metrica)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return pd.DataFrame(metricas)

# Monitorar processo suspeito
telemetria = coletar_metricas_processo('suspicious.exe')
telemetria.to_csv('telemetria_suspeita.csv', index=False)
print(f"Coletadas {len(telemetria)} métricas")
```

### Análise com EDR

```python
# analisar_ransomware.py
import pandas as pd
import joblib
from jogador_v3_avancado import advanced_feature_engineering

# Carregar modelos
scaler = joblib.load('scaler_edr_v3.joblib')
ensemble = joblib.load('model_ensemble_v3.joblib')
mitre_map = joblib.load('mitre_mapping_v3.joblib')

# Carregar telemetria
data = pd.read_csv('telemetria_suspeita.csv')

# Processar
data_proc = advanced_feature_engineering(data)
data_scaled = scaler.transform(data_proc)

# Predição
pred = ensemble.predict(data_scaled)
proba = ensemble.predict_proba(data_scaled)

# Resultado
for i, (p, prob) in enumerate(zip(pred, proba)):
    print(f"\nProcesso {i+1}:")
    print(f"  Classificação: {mitre_map[p]}")
    print(f"  Confiança: {prob.max():.1%}")
    
    if p == 9:  # T1486 - Ransomware
        print("  ⚠️  ALERTA: RANSOMWARE DETECTADO!")
        print("  Ações recomendadas:")
        print("    1. Isolar máquina da rede IMEDIATAMENTE")
        print("    2. NÃO desligar (preservar memória)")
        print("    3. Capturar imagem da memória RAM")
        print("    4. Notificar equipe de resposta a incidentes")
```

### Resposta Automatizada

```python
# resposta_automatica_ransomware.py
import subprocess

def isolar_maquina():
    """Desconecta todas as interfaces de rede."""
    subprocess.run(['netsh', 'interface', 'set', 'interface', 'Ethernet', 'disabled'])
    print("✓ Máquina isolada da rede")

def matar_processo(pid):
    """Encerra processo malicioso."""
    subprocess.run(['taskkill', '/F', '/PID', str(pid)])
    print(f"✓ Processo {pid} encerrado")

def capturar_memoria():
    """Captura dump de memória para forense."""
    subprocess.run(['winpmem', '-o', 'memory_dump.raw'])
    print("✓ Memória capturada: memory_dump.raw")

# Se ransomware detectado com alta confiança
if pred[0] == 9 and proba[0].max() > 0.95:
    print("\n🚨 RESPOSTA AUTOMÁTICA ATIVADA")
    isolar_maquina()
    matar_processo(suspicious_pid)
    capturar_memoria()
```

---

## Exemplo 2: Integração com Sysmon

### Instalação do Sysmon

```powershell
# Baixar Sysmon
Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon.exe" -OutFile "Sysmon.exe"

# Instalar com configuração padrão
.\Sysmon.exe -accepteula -i
```

### Parser de Logs Sysmon

```python
# parser_sysmon.py
import xml.etree.ElementTree as ET
import pandas as pd
import win32evtlog

def ler_eventos_sysmon():
    """Lê eventos do Sysmon via Event Log."""
    
    hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    eventos = []
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        
        for event in events:
            # Event ID 1 = Process Create
            if event.EventID == 1:
                
                xml_data = event.StringInserts
                
                evento_data = {
                    'timestamp': event.TimeGenerated,
                    'process_name': xml_data[4] if len(xml_data) > 4 else '',
                    'command_line': xml_data[10] if len(xml_data) > 10 else '',
                    'parent_process': xml_data[13] if len(xml_data) > 13 else '',
                    'user': xml_data[11] if len(xml_data) > 11 else ''
                }
                
                eventos.append(evento_data)
    
    win32evtlog.CloseEventLog(hand)
    return pd.DataFrame(eventos)

# Converter eventos Sysmon para formato EDR
def sysmon_para_edr(eventos_sysmon):
    """Converte eventos Sysmon para formato de telemetria do EDR."""
    
    telemetria = []
    
    for idx, evento in eventos_sysmon.iterrows():
        
        # Heurísticas básicas
        is_powershell = 'powershell' in evento['process_name'].lower()
        is_hidden = '-w hidden' in evento['command_line'].lower()
        is_encoded = '-enc' in evento['command_line'].lower()
        
        tel = {
            'process_id_count': 1,
            'process_cpu_usage': 50.0 if is_powershell else 10.0,
            'disk_io_rate': 30.0,
            'network_connections': 20 if is_powershell else 5,
            'file_writes': 10,
            'duration_seconds': 300,
            'memory_usage_mb': 1000 if is_powershell else 500,
            'thread_count': 40 if is_powershell else 20,
            'registry_modifications': 5,
            'dns_queries': 30 if is_powershell else 10,
            'suspicious_ports': 3 if (is_hidden or is_encoded) else 0,
            'parent_process_anomaly': 0.8 if 'explorer.exe' not in evento['parent_process'].lower() else 0.0
        }
        
        telemetria.append(tel)
    
    return pd.DataFrame(telemetria)

# Uso
eventos = ler_eventos_sysmon()
telemetria = sysmon_para_edr(eventos)
telemetria.to_csv('telemetria_sysmon.csv', index=False)
```

---

## Exemplo 3: Monitoramento Contínuo

### Daemon de Monitoramento

```python
# edr_daemon.py
import time
import psutil
import joblib
import pandas as pd
from datetime import datetime
import logging

# Configurar logging
logging.basicConfig(
    filename='edr_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Carregar modelos
scaler = joblib.load('scaler_edr_v3.joblib')
ensemble = joblib.load('model_ensemble_v3.joblib')
anomaly = joblib.load('model_anomaly_v3.joblib')
mitre_map = joblib.load('mitre_mapping_v3.joblib')

def coletar_metricas_sistema():
    """Coleta métricas gerais do sistema."""
    
    # CPU
    cpu = psutil.cpu_percent(interval=1)
    
    # Memória
    mem = psutil.virtual_memory()
    
    # Disco
    disk = psutil.disk_io_counters()
    
    # Rede
    net = psutil.net_io_counters()
    net_conns = len(psutil.net_connections())
    
    # Processos
    proc_count = len(psutil.pids())
    
    return {
        'process_id_count': proc_count,
        'process_cpu_usage': cpu,
        'disk_io_rate': (disk.write_bytes + disk.read_bytes) / (1024 * 1024 * 60),
        'network_connections': net_conns,
        'file_writes': disk.write_count,
        'duration_seconds': 60,
        'memory_usage_mb': mem.used / (1024 * 1024),
        'thread_count': sum(p.num_threads() for p in psutil.process_iter(['num_threads'])),
        'registry_modifications': 0,
        'dns_queries': 0,
        'suspicious_ports': 0,
        'parent_process_anomaly': 0.0
    }

def analisar_ameacas(metricas):
    """Analisa métricas para detectar ameaças."""
    
    df = pd.DataFrame([metricas])
    
    # Feature engineering
    df['net_conn_per_proc'] = df['network_connections'] / (df['process_id_count'] + 1e-6)
    df['file_write_rate'] = df['file_writes'] / (df['duration_seconds'] + 1e-6)
    df['cpu_per_thread'] = df['process_cpu_usage'] / (df['thread_count'] + 1e-6)
    df['io_intensity'] = df['disk_io_rate'] * df['file_writes']
    df['network_intensity'] = df['network_connections'] * df['dns_queries']
    df['anomaly_score'] = (df['suspicious_ports'] * 2) + (df['parent_process_anomaly'] * 3) + (df['registry_modifications'] / 10)
    df['resource_pressure'] = (df['process_cpu_usage'] + df['memory_usage_mb']/100 + df['disk_io_rate']) / 3
    
    # Normalizar
    df_scaled = scaler.transform(df)
    
    # Predições
    pred = ensemble.predict(df_scaled)[0]
    proba = ensemble.predict_proba(df_scaled)[0]
    anom = anomaly.predict(df_scaled)[0]
    
    return {
        'classification': mitre_map[pred],
        'confidence': proba.max(),
        'is_anomaly': anom == -1
    }

def loop_monitoramento(intervalo=60):
    """Loop principal de monitoramento."""
    
    logging.info("EDR Daemon iniciado")
    print("🛡️  EDR em modo de monitoramento contínuo...")
    print(f"Intervalo: {intervalo} segundos\n")
    
    while True:
        try:
            # Coletar métricas
            metricas = coletar_metricas_sistema()
            
            # Analisar
            resultado = analisar_ameacas(metricas)
            
            # Log
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if resultado['classification'] != "Normal (No Threat Detected)":
                msg = f"⚠️  AMEAÇA: {resultado['classification']} (Confiança: {resultado['confidence']:.0%})"
                print(f"[{timestamp}] {msg}")
                logging.warning(msg)
            elif resultado['is_anomaly']:
                msg = f"⚠️  ANOMALIA DETECTADA (Possível Zero-Day)"
                print(f"[{timestamp}] {msg}")
                logging.warning(msg)
            else:
                print(f"[{timestamp}] ✓ Sistema normal")
                logging.info("Sistema normal")
            
            # Aguardar próximo ciclo
            time.sleep(intervalo)
            
        except KeyboardInterrupt:
            print("\n\nEncerrando monitoramento...")
            logging.info("EDR Daemon encerrado pelo usuário")
            break
        except Exception as e:
            logging.error(f"Erro no loop: {e}")
            time.sleep(intervalo)

if __name__ == "__main__":
    loop_monitoramento(intervalo=60)
```

### Executar como Serviço (Linux)

```bash
# /etc/systemd/system/edr-monitor.service
[Unit]
Description=EDR Advanced Monitoring Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/edr
ExecStart=/usr/bin/python3 /opt/edr/edr_daemon.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Ativar serviço
sudo systemctl enable edr-monitor
sudo systemctl start edr-monitor
sudo systemctl status edr-monitor
```

---

## Exemplo 4: Análise Forense

### Análise de Dump de Memória

```python
# forense_memoria.py
import joblib
import pandas as pd
import volatility3  # Biblioteca de análise forense

def extrair_processos_dump(memory_dump):
    """Extrai lista de processos de um dump de memória."""
    
    # Usar Volatility para análise
    # (Simplificado - requer configuração completa do Volatility)
    
    processos = [
        {'pid': 1234, 'name': 'suspicious.exe', 'cpu': 95.0, 'mem': 2048},
        {'pid': 5678, 'name': 'powershell.exe', 'cpu': 85.0, 'mem': 1024},
        # ... outros processos extraídos
    ]
    
    return processos

def reconstruir_telemetria(processos):
    """Reconstrói telemetria EDR a partir de processos em memória."""
    
    telemetria = []
    
    for proc in processos:
        tel = {
            'process_id_count': 1,
            'process_cpu_usage': proc['cpu'],
            'disk_io_rate': 50.0,  # Estimativa
            'network_connections': 10,  # Extrair de network sockets
            'file_writes': 20,
            'duration_seconds': 300,
            'memory_usage_mb': proc['mem'],
            'thread_count': 30,
            'registry_modifications': 5,
            'dns_queries': 15,
            'suspicious_ports': 2,
            'parent_process_anomaly': 0.5
        }
        telemetria.append(tel)
    
    return pd.DataFrame(telemetria)

# Carregar modelos
scaler = joblib.load('scaler_edr_v3.joblib')
ensemble = joblib.load('model_ensemble_v3.joblib')
mitre_map = joblib.load('mitre_mapping_v3.joblib')

# Analisar dump
processos = extrair_processos_dump('memory_dump.raw')
telemetria = reconstruir_telemetria(processos)

# Feature engineering
from jogador_v3_avancado import advanced_feature_engineering
telemetria_proc = advanced_feature_engineering(telemetria)
telemetria_scaled = scaler.transform(telemetria_proc)

# Análise
pred = ensemble.predict(telemetria_scaled)
proba = ensemble.predict_proba(telemetria_scaled)

# Relatório forense
print("="*70)
print("RELATÓRIO DE ANÁLISE FORENSE")
print("="*70)
print(f"\nTotal de processos analisados: {len(processos)}")

ameacas_encontradas = []
for i, (p, prob) in enumerate(zip(pred, proba)):
    if p != 0:  # Não é normal
        ameacas_encontradas.append({
            'processo': processos[i]['name'],
            'pid': processos[i]['pid'],
            'ameaca': mitre_map[p],
            'confianca': prob.max()
        })

if ameacas_encontradas:
    print(f"\n⚠️  AMEAÇAS IDENTIFICADAS: {len(ameacas_encontradas)}")
    for ameaca in ameacas_encontradas:
        print(f"\n  • Processo: {ameaca['processo']} (PID: {ameaca['pid']})")
        print(f"    Classificação: {ameaca['ameaca']}")
        print(f"    Confiança: {ameaca['confianca']:.1%}")
else:
    print("\n✓ Nenhuma ameaça identificada no dump de memória")
```

---

## Exemplo 5: Dashboard Simples

### Dashboard Web com Flask

```python
# dashboard_edr.py
from flask import Flask, render_template, jsonify
import pandas as pd
import joblib
from datetime import datetime, timedelta
import json

app = Flask(__name__)

# Carregar modelos
scaler = joblib.load('scaler_edr_v3.joblib')
ensemble = joblib.load('model_ensemble_v3.joblib')
mitre_map = joblib.load('mitre_mapping_v3.joblib')

# Armazenar histórico (em produção, usar banco de dados)
historico_deteccoes = []

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Retorna estatísticas das últimas 24h."""
    
    agora = datetime.now()
    ultimo_dia = [d for d in historico_deteccoes 
                  if (agora - d['timestamp']).total_seconds() < 86400]
    
    total_eventos = len(ultimo_dia)
    ameacas = len([d for d in ultimo_dia if d['threat'] != 0])
    criticas = len([d for d in ultimo_dia if d['priority'] == 'CRÍTICA'])
    
    return jsonify({
        'total_eventos': total_eventos,
        'ameacas_detectadas': ameacas,
        'alertas_criticos': criticas,
        'taxa_deteccao': (ameacas / total_eventos * 100) if total_eventos > 0 else 0
    })

@app.route('/api/recent')
def get_recent():
    """Retorna últimas 10 detecções."""
    
    recent = sorted(historico_deteccoes, key=lambda x: x['timestamp'], reverse=True)[:10]
    
    return jsonify([{
        'timestamp': d['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
        'classification': mitre_map[d['threat']],
        'priority': d['priority'],
        'confidence': f"{d['confidence']:.1%}"
    } for d in recent])

@app.route('/api/timeline')
def get_timeline():
    """Retorna dados para gráfico de linha temporal."""
    
    agora = datetime.now()
    ultimas_24h = agora - timedelta(hours=24)
    
    # Agrupar por hora
    dados_hora = {}
    for hora in range(24):
        tempo = ultimas_24h + timedelta(hours=hora)
        hora_str = tempo.strftime('%H:00')
        dados_hora[hora_str] = {'normal': 0, 'ameacas': 0}
    
    for deteccao in historico_deteccoes:
        if deteccao['timestamp'] >= ultimas_24h:
            hora_str = deteccao['timestamp'].strftime('%H:00')
            if deteccao['threat'] == 0:
                dados_hora[hora_str]['normal'] += 1
            else:
                dados_hora[hora_str]['ameacas'] += 1
    
    return jsonify({
        'labels': list(dados_hora.keys()),
        'normal': [v['normal'] for v in dados_hora.values()],
        'ameacas': [v['ameacas'] for v in dados_hora.values()]
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Template HTML do Dashboard

```html
<!-- templates/dashboard.html -->
<!DOCTYPE html>
<html>
<head>
    <title>EDR Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #1a1a1a;
            color: #fff;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #999;
            margin-top: 5px;
        }
        .chart-container {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .recent-alerts {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
        }
        .alert-item {
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #e67e22; }
        .medium { border-left-color: #f39c12; }
        .low { border-left-color: #2ecc71; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ EDR Advanced Monitoring Dashboard</h1>
            <p>Sistema de Detecção Multi-Camadas v3.0</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="total-eventos">-</div>
                <div class="stat-label">Eventos Analisados (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="ameacas">-</div>
                <div class="stat-label">Ameaças Detectadas</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="criticas">-</div>
                <div class="stat-label">Alertas Críticos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="taxa">-%</div>
                <div class="stat-label">Taxa de Detecção</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h2>Timeline de Detecções (24 horas)</h2>
            <canvas id="timelineChart"></canvas>
        </div>
        
        <div class="recent-alerts">
            <h2>Alertas Recentes</h2>
            <div id="recent-list"></div>
        </div>
    </div>
    
    <script>
        // Atualizar estatísticas
        function updateStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('total-eventos').textContent = data.total_eventos;
                    document.getElementById('ameacas').textContent = data.ameacas_detectadas;
                    document.getElementById('criticas').textContent = data.alertas_criticos;
                    document.getElementById('taxa').textContent = data.taxa_deteccao.toFixed(1) + '%';
                });
        }
        
        // Atualizar alertas recentes
        function updateRecent() {
            fetch('/api/recent')
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('recent-list');
                    list.innerHTML = data.map(alert => `
                        <div class="alert-item ${alert.priority.toLowerCase()}">
                            <strong>${alert.timestamp}</strong> - ${alert.classification}
                            <br><small>Prioridade: ${alert.priority} | Confiança: ${alert.confidence}</small>
                        </div>
                    `).join('');
                });
        }
        
        // Criar gráfico
        fetch('/api/timeline')
            .then(r => r.json())
            .then(data => {
                const ctx = document.getElementById('timelineChart').getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: 'Eventos Normais',
                            data: data.normal,
                            borderColor: '#2ecc71',
                            backgroundColor: 'rgba(46, 204, 113, 0.1)'
                        }, {
                            label: 'Ameaças',
                            data: data.ameacas,
                            borderColor: '#e74c3c',
                            backgroundColor: 'rgba(231, 76, 60, 0.1)'
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            });
        
        // Atualizar a cada 10 segundos
        updateStats();
        updateRecent();
        setInterval(() => {
            updateStats();
            updateRecent();
        }, 10000);
    </script>
</body>
</html>
```

---

## Exemplo 6: Complementar EDR Existente

### Integração com CrowdStrike/SentinelOne

```python
# integracao_edr_comercial.py
import requests
import joblib
import pandas as pd
from datetime import datetime

class EDRComercialConnector:
    """Conector para EDR comercial via API."""
    
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.headers = {'Authorization': f'Bearer {api_key}'}
    
    def obter_alertas(self, limit=100):
        """Obtém alertas do EDR comercial."""
        response = requests.get(
            f'{self.api_url}/alerts',
            headers=self.headers,
            params={'limit': limit}
        )
        return response.json()
    
    def obter_telemetria_host(self, host_id):
        """Obtém telemetria de um host específico."""
        response = requests.get(
            f'{self.api_url}/hosts/{host_id}/telemetry',
            headers=self.headers
        )
        return response.json()

class EDRAvancadoAnalyzer:
    """Análise adicional com nosso modelo."""
    
    def __init__(self):
        self.scaler = joblib.load('scaler_edr_v3.joblib')
        self.ensemble = joblib.load('model_ensemble_v3.joblib')
        self.anomaly = joblib.load('model_anomaly_v3.joblib')
        self.mitre_map = joblib.load('mitre_mapping_v3.joblib')
    
    def converter_telemetria_comercial(self, telemetria_comercial):
        """Converte formato do EDR comercial para nosso formato."""
        
        return pd.DataFrame([{
            'process_id_count': telemetria_comercial.get('process_count', 50),
            'process_cpu_usage': telemetria_comercial.get('cpu_usage', 10.0),
            'disk_io_rate': telemetria_comercial.get('disk_io', 20.0),
            'network_connections': telemetria_comercial.get('net_connections', 10),
            'file_writes': telemetria_comercial.get('file_operations', 5),
            'duration_seconds': telemetria_comercial.get('duration', 600),
            'memory_usage_mb': telemetria_comercial.get('memory_mb', 512),
            'thread_count': telemetria_comercial.get('threads', 20),
            'registry_modifications': telemetria_comercial.get('registry_ops', 2),
            'dns_queries': telemetria_comercial.get('dns_queries', 15),
            'suspicious_ports': telemetria_comercial.get('suspicious_ports', 0),
            'parent_process_anomaly': telemetria_comercial.get('parent_anomaly', 0.0)
        }])
    
    def analise_secundaria(self, telemetria_df):
        """Realiza análise secundária com nosso modelo."""
        
        from jogador_v3_avancado import advanced_feature_engineering
        
        # Feature engineering
        tel_proc = advanced_feature_engineering(telemetria_df)
        tel_scaled = self.scaler.transform(tel_proc)
        
        # Predições
        pred = self.ensemble.predict(tel_scaled)[0]
        proba = self.ensemble.predict_proba(tel_scaled)[0]
        anom = self.anomaly.predict(tel_scaled)[0]
        
        return {
            'nossa_classificacao': self.mitre_map[pred],
            'confianca': proba.max(),
            'e_anomalia': anom == -1,
            'concorda_com_comercial': None  # Será preenchido depois
        }

def pipeline_analise_hibrida(api_url, api_key):
    """Pipeline que combina EDR comercial + nosso modelo."""
    
    print("🔄 Iniciando análise híbrida EDR Comercial + EDR Avançado v3.0")
    
    # Conectar ao EDR comercial
    comercial = EDRComercialConnector(api_url, api_key)
    avancado = EDRAvancadoAnalyzer()
    
    # Obter alertas do EDR comercial
    alertas = comercial.obter_alertas(limit=50)
    print(f"✓ Obtidos {len(alertas)} alertas do EDR comercial")
    
    analises = []
    
    for alerta in alertas:
        print(f"\n📋 Analisando alerta: {alerta['id']}")
        
        # Obter telemetria
        telemetria = comercial.obter_telemetria_host(alerta['host_id'])
        
        # Converter para nosso formato
        tel_df = avancado.converter_telemetria_comercial(telemetria)
        
        # Nossa análise
        resultado = avancado.analise_secundaria(tel_df)
        
        # Comparar com classificação do EDR comercial
        classificacao_comercial = alerta.get('threat_type', 'Unknown')
        resultado['concorda_com_comercial'] = (
            'T1' in resultado['nossa_classificacao'] and 
            'T1' in classificacao_comercial
        )
        
        # Decisão final
        if resultado['e_anomalia'] and not resultado['concorda_com_comercial']:
            print(f"  ⚠️  DIVERGÊNCIA DETECTADA!")
            print(f"     EDR Comercial: {classificacao_comercial}")
            print(f"     Nossa Análise: {resultado['nossa_classificacao']}")
            print(f"     Confiança: {resultado['confianca']:.1%}")
            print(f"     🔍 Recomendação: INVESTIGAÇÃO MANUAL URGENTE")
            
            resultado['acao'] = 'INVESTIGACAO_MANUAL'
        
        elif resultado['confianca'] > 0.95:
            print(f"  ✓ Confirmação de alta confiança")
            print(f"     Classificação: {resultado['nossa_classificacao']}")
            resultado['acao'] = 'CONFIRMAR_ALERTA'
        
        else:
            print(f"  ℹ️  Análise inconclusa")
            resultado['acao'] = 'MONITORAR'
        
        analises.append({
            'alerta_id': alerta['id'],
            'host_id': alerta['host_id'],
            'comercial': classificacao_comercial,
            'avancado': resultado
        })
    
    # Relatório final
    print("\n" + "="*70)
    print("RELATÓRIO DE ANÁLISE HÍBRIDA")
    print("="*70)
    
    divergencias = [a for a in analises if not a['avancado']['concorda_com_comercial']]
    confirmacoes = [a for a in analises if a['avancado']['acao'] == 'CONFIRMAR_ALERTA']
    
    print(f"\nTotal de alertas analisados: {len(analises)}")
    print(f"Divergências encontradas: {len(divergencias)}")
    print(f"Confirmações de alta confiança: {len(confirmacoes)}")
    
    if divergencias:
        print("\n⚠️  ALERTAS REQUERENDO INVESTIGAÇÃO:")
        for div in divergencias:
            print(f"  • Alerta {div['alerta_id']} (Host: {div['host_id']})")
            print(f"    Classificação Divergente: {div['avancado']['nossa_classificacao']}")
    
    return analises

# Uso
if __name__ == "__main__":
    API_URL = "https://api.seu-edr-comercial.com/v1"
    API_KEY = "sua-chave-api"
    
    resultados = pipeline_analise_hibrida(API_URL, API_KEY)
```

---

## 🎯 Dicas de Uso Avançado

### 1. Tunning de Hiperparâmetros

```python
# tuning_hiperparametros.py
from sklearn.model_selection import GridSearchCV
from sklearn.ensemble import RandomForestClassifier

# Definir grid de hiperparâmetros
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [10, 20, 30, None],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}

# Grid Search com Cross-Validation
rf = RandomForestClassifier(random_state=42)
grid_search = GridSearchCV(
    rf, param_grid, cv=5, 
    scoring='f1_weighted', n_jobs=-1, verbose=2
)

grid_search.fit(X_train_scaled, y_train)

print(f"Melhores parâmetros: {grid_search.best_params_}")
print(f"Melhor score: {grid_search.best_score_:.4f}")
```

### 2. Análise de Features Importantes

```python
# feature_importance.py
import matplotlib.pyplot as plt

# Obter importância das features
importances = ensemble_clf.estimators_[0].feature_importances_
indices = np.argsort(importances)[::-1]

# Plot
plt.figure(figsize=(12, 6))
plt.title("Importância das Features")
plt.bar(range(len(importances)), importances[indices])
plt.xticks(range(len(importances)), 
           [feature_columns[i] for i in indices], 
           rotation=45, ha='right')
plt.tight_layout()
plt.savefig('feature_importance.png')
print("✓ Gráfico salvo: feature_importance.png")
```

### 3. Análise de Curva ROC

```python
# roc_analysis.py
from sklearn.metrics import roc_curve, auc
from sklearn.preprocessing import label_binarize
import matplotlib.pyplot as plt

# Binarizar labels para ROC multi-class
y_test_bin = label_binarize(y_test, classes=range(len(mitre_map)))
y_score = ensemble_clf.predict_proba(X_test_scaled)

# Calcular ROC para cada classe
fpr = dict()
tpr = dict()
roc_auc = dict()

for i in range(len(mitre_map)):
    fpr[i], tpr[i], _ = roc_curve(y_test_bin[:, i], y_score[:, i])
    roc_auc[i] = auc(fpr[i], tpr[i])

# Plot
plt.figure(figsize=(10, 8))
for i in range(min(5, len(mitre_map))):  # Top 5 classes
    plt.plot(fpr[i], tpr[i], 
             label=f'{mitre_map[i][:30]}... (AUC = {roc_auc[i]:.2f})')

plt.plot([0, 1], [0, 1], 'k--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('Taxa de Falsos Positivos')
plt.ylabel('Taxa de Verdadeiros Positivos')
plt.title('Curva ROC - Multi-Class')
plt.legend(loc="lower right")
plt.savefig('roc_curve.png')
print("✓ Curva ROC salva: roc_curve.png")
```

---

## 📚 Recursos para Aprofundamento

- **Dataset Real:** [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Sandbox Malware:** [Any.Run](https://any.run/)
- **Threat Intelligence:** [AlienVault OTX](https://otx.alienvault.com/)
- **MITRE ATT&CK:** [attack.mitre.org](https://attack.mitre.org/)

---

**EDR Avançado v3.0** - Proteção Proativa e Inteligente! 🛡️