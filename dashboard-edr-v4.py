"""
EDR ULTRA v4.0 - DASHBOARD WEB COMPLETO
Dashboard em tempo real com métricas, gráficos e alertas
"""

from flask import Flask, render_template_string, jsonify, request
import pandas as pd
import json
import os
from datetime import datetime, timedelta
from collections import Counter
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ----------------------------------------------------------------------
# FUNÇÕES DE COLETA DE DADOS
# ----------------------------------------------------------------------

def carregar_alertas():
    """Carrega todos os alertas."""
    alertas = []
    if os.path.exists('alertas'):
        for filename in sorted(os.listdir('alertas'), reverse=True)[:100]:
            if filename.endswith('.json'):
                with open(f'alertas/{filename}', 'r') as f:
                    alertas.append(json.load(f))
    return alertas

def carregar_logs():
    """Carrega logs de detecção."""
    logs = []
    if os.path.exists('logs'):
        log_files = [f for f in os.listdir('logs') if f.startswith('deteccao_')]
        if log_files:
            ultimo_log = sorted(log_files)[-1]
            try:
                with open(f'logs/{ultimo_log}', 'r', encoding='utf-8') as f:
                    for line in f.readlines()[-1000:]:  # Últimas 1000 linhas
                        logs.append(line.strip())
            except:
                pass
    return logs

def carregar_metricas_treino():
    """Carrega métricas de treinamento."""
    if os.path.exists('metricas'):
        metric_files = [f for f in os.listdir('metricas') if f.startswith('training_metrics')]
        if metric_files:
            ultimo = sorted(metric_files)[-1]
            with open(f'metricas/{ultimo}', 'r') as f:
                return json.load(f)
    return {}

def calcular_estatisticas():
    """Calcula estatísticas gerais."""
    alertas = carregar_alertas()
    
    agora = datetime.now()
    ultimas_24h = [a for a in alertas if (agora - datetime.fromisoformat(a['timestamp'])).total_seconds() < 86400]
    
    stats = {
        'total_alertas': len(alertas),
        'ultimas_24h': len(ultimas_24h),
        'criticos': len([a for a in ultimas_24h if a.get('priority') == 'CRÍTICA']),
        'altos': len([a for a in ultimas_24h if a.get('priority') == 'ALTA']),
        'medios': len([a for a in ultimas_24h if a.get('priority') == 'MÉDIA']),
        'baixos': len([a for a in ultimas_24h if a.get('priority') == 'BAIXA']),
    }
    
    # Top ameaças
    if ultimas_24h:
        classificacoes = [a['classificacao'] for a in ultimas_24h if a.get('label', 0) != 0]
        stats['top_ameacas'] = dict(Counter(classificacoes).most_common(5)) if classificacoes else {}
    else:
        stats['top_ameacas'] = {}
    
    # Taxa de detecção
    if ultimas_24h:
        ameacas = len([a for a in ultimas_24h if a.get('label', 0) != 0])
        stats['taxa_deteccao'] = (ameacas / len(ultimas_24h)) * 100 if ultimas_24h else 0
    else:
        stats['taxa_deteccao'] = 0
    
    return stats

# ----------------------------------------------------------------------
# TEMPLATE HTML DO DASHBOARD
# ----------------------------------------------------------------------

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EDR Ultra v4.0 - Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 48px rgba(0,0,0,0.15);
        }
        
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #64748b;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-change {
            font-size: 0.85em;
            margin-top: 10px;
        }
        
        .stat-change.positive {
            color: #10b981;
        }
        
        .stat-change.negative {
            color: #ef4444;
        }
        
        .critical { color: #ef4444; }
        .high { color: #f59e0b; }
        .medium { color: #3b82f6; }
        .low { color: #10b981; }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .chart-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .chart-container h2 {
            color: #334155;
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        
        .alerts-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .alert-item {
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid;
            background: #f8fafc;
            transition: all 0.3s;
        }
        
        .alert-item:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
        }
        
        .alert-item.critical { border-left-color: #ef4444; }
        .alert-item.high { border-left-color: #f59e0b; }
        .alert-item.medium { border-left-color: #3b82f6; }
        .alert-item.low { border-left-color: #10b981; }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .alert-title {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .alert-time {
            color: #64748b;
            font-size: 0.85em;
        }
        
        .alert-details {
            color: #475569;
            font-size: 0.9em;
        }
        
        .priority-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .priority-badge.critical {
            background: #fee2e2;
            color: #dc2626;
        }
        
        .priority-badge.high {
            background: #fef3c7;
            color: #d97706;
        }
        
        .priority-badge.medium {
            background: #dbeafe;
            color: #2563eb;
        }
        
        .priority-badge.low {
            background: #d1fae5;
            color: #059669;
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
        }
        
        .refresh-badge {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.95);
            padding: 10px 20px;
            border-radius: 20px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
            font-size: 0.9em;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="refresh-badge">
        🔄 Atualização automática: <span id="countdown">10</span>s
    </div>
    
    <div class="container">
        <div class="header">
            <h1>
                🛡️ EDR Ultra v4.0
                <span class="status-badge">● OPERACIONAL</span>
            </h1>
            <p style="color: #64748b; margin-top: 10px;">
                Sistema de Detecção e Resposta em Tempo Real | 
                Última atualização: <span id="last-update">{{ now }}</span>
            </p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total de Eventos (24h)</div>
                <div class="stat-value" style="color: #667eea;">{{ stats.ultimas_24h }}</div>
                <div class="stat-change positive">↑ Monitoramento ativo</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Ameaças Detectadas</div>
                <div class="stat-value critical">{{ stats.criticos + stats.altos }}</div>
                <div class="stat-change">
                    <span class="critical">{{ stats.criticos }} críticas</span> | 
                    <span class="high">{{ stats.altos }} altas</span>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Taxa de Detecção</div>
                <div class="stat-value low">{{ "%.1f"|format(stats.taxa_deteccao) }}%</div>
                <div class="stat-change positive">↑ Dentro do esperado</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Status do Sistema</div>
                <div class="stat-value low" style="font-size: 2em;">✓ SAUDÁVEL</div>
                <div class="stat-change positive">Todos os módulos operacionais</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h2>📊 Distribuição de Prioridades</h2>
                <canvas id="priorityChart"></canvas>
            </div>
            
            <div class="chart-container">
                <h2>🎯 Top 5 Ameaças Detectadas</h2>
                <canvas id="threatsChart"></canvas>
            </div>
        </div>
        
        <div class="chart-container" style="margin-bottom: 20px;">
            <h2>📈 Timeline de Detecções (Últimas 24 horas)</h2>
            <canvas id="timelineChart"></canvas>
        </div>
        
        <div class="alerts-container">
            <h2 style="color: #334155; margin-bottom: 20px;">🚨 Alertas Recentes (Top 10)</h2>
            <div id="alerts-list">
                {% for alerta in alertas[:10] %}
                <div class="alert-item {{ alerta.priority.lower() }}">
                    <div class="alert-header">
                        <div class="alert-title">
                            <span class="priority-badge {{ alerta.priority.lower() }}">
                                {{ alerta.priority }}
                            </span>
                            {{ alerta.classificacao }}
                        </div>
                        <div class="alert-time">
                            {{ alerta.timestamp.split('T')[0] }} 
                            {{ alerta.timestamp.split('T')[1][:8] }}
                        </div>
                    </div>
                    <div class="alert-details">
                        <strong>Status:</strong> {{ alerta.status }} | 
                        <strong>Confiança:</strong> {{ "%.0f"|format(alerta.confidence * 100) }}% |
                        <strong>Ação:</strong> {{ alerta.action }}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="footer">
            <p>EDR Ultra v4.0 - Sistema de Detecção Multi-Camadas</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                Desenvolvido com Machine Learning Avançado | 
                Cobertura: 15 Técnicas MITRE ATT&CK
            </p>
        </div>
    </div>
    
    <script>
        // Dados do servidor
        const stats = {{ stats | tojson }};
        const alertas = {{ alertas | tojson }};
        
        // Gráfico de Prioridades
        const priorityCtx = document.getElementById('priorityChart').getContext('2d');
        new Chart(priorityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Críticas', 'Altas', 'Médias', 'Baixas'],
                datasets: [{
                    data: [stats.criticos, stats.altos, stats.medios, stats.baixos],
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
        
        // Gráfico de Top Ameaças
        const threatsCtx = document.getElementById('threatsChart').getContext('2d');
        const topAmeacas = stats.top_ameacas;
        const ameacasLabels = Object.keys(topAmeacas).map(label => {
            return label.length > 40 ? label.substring(0, 40) + '...' : label;
        });
        const ameacasData = Object.values(topAmeacas);
        
        new Chart(threatsCtx, {
            type: 'bar',
            data: {
                labels: ameacasLabels,
                datasets: [{
                    label: 'Detecções',
                    data: ameacasData,
                    backgroundColor: '#667eea',
                    borderRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        });
        
        // Gráfico de Timeline
        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        
        // Agrupar alertas por hora
        const horasData = {};
        for (let i = 0; i < 24; i++) {
            horasData[i] = { normal: 0, ameacas: 0 };
        }
        
        alertas.forEach(a => {
            const hora = new Date(a.timestamp).getHours();
            if (a.label === 0) {
                horasData[hora].normal++;
            } else {
                horasData[hora].ameacas++;
            }
        });
        
        const timelineLabels = Object.keys(horasData).map(h => h + ':00');
        const normalData = Object.values(horasData).map(d => d.normal);
        const ameacasData = Object.values(horasData).map(d => d.ameacas);
        
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: timelineLabels,
                datasets: [
                    {
                        label: 'Eventos Normais',
                        data: normalData,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Ameaças',
                        data: ameacasData,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        });
        
        // Auto-refresh
        let countdown = 10;
        setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown <= 0) {
                location.reload();
            }
        }, 1000);
        
        // Atualizar timestamp
        document.getElementById('last-update').textContent = new Date().toLocaleString('pt-BR');
    </script>
</body>
</html>
'''

# ----------------------------------------------------------------------
# ROTAS DO DASHBOARD
# ----------------------------------------------------------------------

@app.route('/')
def dashboard():
    """Página principal do dashboard."""
    stats = calcular_estatisticas()
    alertas = carregar_alertas()
    
    return render_template_string(
        DASHBOARD_HTML,
        stats=stats,
        alertas=alertas,
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/api/stats')
def api_stats():
    """API: Estatísticas em JSON."""
    return jsonify(calcular_estatisticas())

@app.route('/api/alertas')
def api_alertas():
    """API: Lista de alertas."""
    limit = request.args.get('limit', 100, type=int)
    alertas = carregar_alertas()[:limit]
    return jsonify(alertas)

@app.route('/api/metricas')
def api_metricas():
    """API: Métricas de treinamento."""
    return jsonify(carregar_metricas_treino())

@app.route('/health')
def health():
    """Health check."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '4.0'
    })

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

if __name__ == '__main__':
    logger.info("="*70)
    logger.info("🌐 EDR ULTRA v4.0 - DASHBOARD WEB")
    logger.info("="*70)
    logger.info("\n📊 Dashboard iniciando...")
    logger.info("🔗 Acesse: http://localhost:5000")
    logger.info("📖 API Docs: http://localhost:5000/api/stats")
    logger.info("\n✅ Dashboard pronto!\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)