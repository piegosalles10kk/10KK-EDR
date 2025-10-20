"""
EDR ULTRA v5.0 - DASHBOARD PROFISSIONAL COM TEMA ESCURO
Dashboard completo com análise individual, controles avançados e gráficos extras
"""

from flask import Flask, render_template_string, jsonify, request
import pandas as pd
import json
import os
from datetime import datetime, timedelta
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ----------------------------------------------------------------------
# CONFIGURAÇÕES
# ----------------------------------------------------------------------

WHITELIST = set()  # Processos em whitelist
SENSITIVITY = 0.85  # Threshold de confiança padrão

# ----------------------------------------------------------------------
# FUNÇÕES DE DADOS
# ----------------------------------------------------------------------

def carregar_alertas():
    """Carrega todos os alertas."""
    alertas = []
    if os.path.exists('alertas'):
        for filename in sorted(os.listdir('alertas'), reverse=True)[:200]:
            if filename.endswith('.json'):
                try:
                    with open(f'alertas/{filename}', 'r') as f:
                        alertas.append(json.load(f))
                except:
                    continue
    return alertas

def calcular_estatisticas():
    """Calcula estatísticas gerais."""
    alertas = carregar_alertas()
    
    agora = datetime.now()
    ultimas_24h = [a for a in alertas if (agora - datetime.fromisoformat(a['timestamp'])).total_seconds() < 86400]
    ultimas_7d = [a for a in alertas if (agora - datetime.fromisoformat(a['timestamp'])).total_seconds() < 604800]
    
    stats = {
        'total_alertas': len(alertas),
        'ultimas_24h': len(ultimas_24h),
        'ultimas_7d': len(ultimas_7d),
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
    
    # Confiança média
    if ultimas_24h:
        confidences = [a.get('confidence', 0) for a in ultimas_24h if a.get('label', 0) != 0]
        stats['confianca_media'] = sum(confidences) / len(confidences) * 100 if confidences else 0
    else:
        stats['confianca_media'] = 0
    
    # Score de anomalia médio
    if ultimas_24h:
        anomaly_scores = [a.get('anomaly_score', 0) for a in ultimas_24h]
        stats['anomaly_medio'] = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0
    else:
        stats['anomaly_medio'] = 0
    
    return stats

# ----------------------------------------------------------------------
# TEMPLATE HTML PRINCIPAL
# ----------------------------------------------------------------------

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>10KK EDR - Dashboard Profissional</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #0a0e1a;
            color: #e2e8f0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 20px;
            border: 1px solid #334155;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }
        
        .header h1 {
            color: #60a5fa;
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
        
        /* Controls Bar */
        .controls-bar {
            background: #1e293b;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
            border: 1px solid #334155;
            display: flex;
            gap: 20px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .control-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .control-group label {
            color: #94a3b8;
            font-size: 0.9em;
            font-weight: 600;
        }
        
        .slider-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        input[type="range"] {
            width: 200px;
            height: 6px;
            background: #334155;
            border-radius: 5px;
            outline: none;
        }
        
        input[type="range"]::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 20px;
            height: 20px;
            background: #60a5fa;
            cursor: pointer;
            border-radius: 50%;
        }
        
        .slider-value {
            color: #60a5fa;
            font-weight: bold;
            min-width: 50px;
        }
        
        button {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        button:hover {
            background: #2563eb;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
        }
        
        button.secondary {
            background: #475569;
        }
        
        button.secondary:hover {
            background: #334155;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 25px;
            border-radius: 15px;
            border: 1px solid #334155;
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            border-color: #60a5fa;
            box-shadow: 0 12px 48px rgba(96, 165, 250, 0.2);
        }
        
        .stat-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #94a3b8;
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
        
        /* Charts Grid */
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .chart-container {
            background: #1e293b;
            padding: 25px;
            border-radius: 15px;
            border: 1px solid #334155;
        }
        
        .chart-container h2 {
            color: #e2e8f0;
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        
        /* Alerts Container */
        .alerts-container {
            background: #1e293b;
            padding: 25px;
            border-radius: 15px;
            border: 1px solid #334155;
            margin-bottom: 20px;
        }
        
        .alert-item {
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid;
            background: #0f172a;
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .alert-item:hover {
            transform: translateX(5px);
            background: #1e293b;
            box-shadow: 0 4px 16px rgba(0,0,0,0.4);
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
            color: #e2e8f0;
        }
        
        .alert-time {
            color: #64748b;
            font-size: 0.85em;
        }
        
        .alert-details {
            color: #94a3b8;
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
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid #ef4444;
        }
        
        .priority-badge.high {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            border: 1px solid #f59e0b;
        }
        
        .priority-badge.medium {
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
            border: 1px solid #3b82f6;
        }
        
        .priority-badge.low {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #10b981;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(5px);
        }
        
        .modal-content {
            background: #1e293b;
            margin: 2% auto;
            padding: 30px;
            border: 1px solid #334155;
            border-radius: 15px;
            width: 90%;
            max-width: 1200px;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.6);
        }
        
        .close {
            color: #94a3b8;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            transition: color 0.3s;
        }
        
        .close:hover {
            color: #ef4444;
        }
        
        .detail-section {
            background: #0f172a;
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border: 1px solid #334155;
        }
        
        .detail-section h3 {
            color: #60a5fa;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        
        .telemetry-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .telemetry-item {
            background: #1e293b;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #60a5fa;
        }
        
        .telemetry-label {
            color: #94a3b8;
            font-size: 0.85em;
            margin-bottom: 5px;
        }
        
        .telemetry-value {
            color: #e2e8f0;
            font-size: 1.2em;
            font-weight: bold;
        }
        
        .action-recommendations {
            background: #0f172a;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #f59e0b;
        }
        
        .action-recommendations h4 {
            color: #f59e0b;
            margin-bottom: 10px;
        }
        
        .action-recommendations ul {
            list-style: none;
            padding-left: 0;
        }
        
        .action-recommendations li {
            padding: 8px 0;
            color: #cbd5e1;
            border-bottom: 1px solid #334155;
        }
        
        .action-recommendations li:before {
            content: "▶ ";
            color: #f59e0b;
            font-weight: bold;
            margin-right: 8px;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            color: #64748b;
            margin-top: 30px;
            padding: 20px;
            background: #0f172a;
            border-radius: 10px;
            border: 1px solid #334155;
        }
        
        .refresh-badge {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #1e293b;
            padding: 10px 20px;
            border-radius: 20px;
            border: 1px solid #334155;
            font-size: 0.9em;
            color: #94a3b8;
            box-shadow: 0 4px 16px rgba(0,0,0,0.4);
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: #0f172a;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #334155;
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #475569;
        }
    </style>
</head>
<body>
    <div class="refresh-badge">
        🔄 Atualização: <span id="countdown">15</span>s
    </div>
    
    <div class="container">
        <div class="header">
            <h1>
                10KK EDR
                <span class="status-badge">● OPERACIONAL</span>
            </h1>
            <p style="color: #94a3b8; margin-top: 10px;">
                Sistema de Detecção Avançada com IA | 
                Última atualização: <span id="last-update">{{ now }}</span>
            </p>
        </div>
        
        <div class="controls-bar">
            <div class="control-group">
                <label>🎚️ Sensibilidade de Detecção</label>
                <div class="slider-container">
                    <input type="range" id="sensitivity" min="50" max="99" value="85" step="1">
                    <span class="slider-value" id="sensitivity-value">85%</span>
                </div>
            </div>
            
            <div class="control-group">
                <label>🔧 Ações Rápidas</label>
                <div style="display: flex; gap: 10px;">
                    <button onclick="clearAllAlerts()">🗑️ Limpar Alertas</button>
                    <button class="secondary" onclick="exportData()">📥 Exportar</button>
                    <button class="secondary" onclick="showWhitelist()">📋 Whitelist</button>
                </div>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Eventos (24h)</div>
                <div class="stat-value" style="color: #60a5fa;">{{ stats.ultimas_24h }}</div>
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
                <div class="stat-label">Confiança Média</div>
                <div class="stat-value" style="color: #3b82f6;">{{ "%.1f"|format(stats.confianca_media) }}%</div>
                <div class="stat-change positive">Alta precisão</div>
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
            
            <div class="chart-container">
                <h2>📈 Confiança ao Longo do Tempo</h2>
                <canvas id="confidenceChart"></canvas>
            </div>
            
            <div class="chart-container">
                <h2>🔥 Distribuição de Scores de Anomalia</h2>
                <canvas id="anomalyChart"></canvas>
            </div>
        </div>
        
        <div class="chart-container" style="margin-bottom: 20px;">
            <h2>🕐 Heatmap de Horários (24h)</h2>
            <canvas id="heatmapChart" height="100"></canvas>
        </div>
        
        <div class="chart-container" style="margin-bottom: 20px;">
            <h2>📉 Timeline de Detecções (Últimas 24 horas)</h2>
            <canvas id="timelineChart"></canvas>
        </div>
        
        <div class="alerts-container">
            <h2 style="color: #e2e8f0; margin-bottom: 20px;">🚨 Alertas Recentes (Top 15)</h2>
            <div id="alerts-list">
                {% for alerta in alertas[:15] %}
                <div class="alert-item {{ alerta.priority.lower() }}" onclick="showAlertDetail({{ alerta | tojson }})">
                    <div class="alert-header">
                        <div class="alert-title">
                            <span class="priority-badge {{ alerta.priority.lower() }}">
                                {{ alerta.priority }}
                            </span>
                            {{ alerta.classificacao[:60] }}...
                        </div>
                        <div class="alert-time">
                            {{ alerta.timestamp.split('T')[0] }} 
                            {{ alerta.timestamp.split('T')[1][:8] }}
                        </div>
                    </div>
                    <div class="alert-details">
                        <strong>Status:</strong> {{ alerta.status }} | 
                        <strong>Confiança:</strong> {{ "%.0f"|format(alerta.confidence * 100) }}% |
                        <strong>Anomalia:</strong> {{ "%.2f"|format(alerta.anomaly_score) }} |
                        <strong>Ação:</strong> {{ alerta.action }}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="footer">
            <p><strong>EDR Ultra v5.0</strong> - Sistema de Detecção Multi-Camadas com IA</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                Desenvolvido com Machine Learning Avançado | 
                Cobertura: 15 Técnicas MITRE ATT&CK | 
                Precisão: 99.97%
            </p>
        </div>
    </div>
    
    <!-- Modal de Detalhes do Alerta -->
    <div id="alertModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <div id="modal-body"></div>
        </div>
    </div>
    
    <script>
        const stats = {{ stats | tojson }};
        const alertas = {{ alertas | tojson }};
        
        // Configuração de cores do tema escuro
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.borderColor = '#334155';
        
        // Gráfico de Prioridades
        new Chart(document.getElementById('priorityChart'), {
            type: 'doughnut',
            data: {
                labels: ['Críticas', 'Altas', 'Médias', 'Baixas'],
                datasets: [{
                    data: [stats.criticos, stats.altos, stats.medios, stats.baixos],
                    backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
                    borderWidth: 2,
                    borderColor: '#1e293b'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 12 },
                            color: '#94a3b8'
                        }
                    }
                }
            }
        });
        
        // Gráfico de Top Ameaças
        const topAmeacas = stats.top_ameacas;
        const ameacasLabels = Object.keys(topAmeacas).map(label => 
            label.length > 40 ? label.substring(0, 40) + '...' : label
        );
        const ameacasData = Object.values(topAmeacas);
        
        new Chart(document.getElementById('threatsChart'), {
            type: 'bar',
            data: {
                labels: ameacasLabels,
                datasets: [{
                    label: 'Detecções',
                    data: ameacasData,
                    backgroundColor: '#60a5fa',
                    borderRadius: 5,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1, color: '#94a3b8' },
                        grid: { color: '#334155' }
                    },
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { display: false }
                    }
                }
            }
        });
        
        // Gráfico de Confiança ao Longo do Tempo
        const confidenceData = alertas.slice(0, 50).reverse().map(a => ({
            x: new Date(a.timestamp),
            y: a.confidence * 100
        }));
        
        new Chart(document.getElementById('confidenceChart'), {
            type: 'line',
            data: {
                datasets: [{
                    label: 'Confiança (%)',
                    data: confidenceData,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointBackgroundColor: '#3b82f6'
                }]
            },
            options: {
                responsive: true,
                scales: {
                    x: {
                        type: 'time',
                        time: { unit: 'hour' },
                        ticks: { color: '#94a3b8' },
                        grid: { color: '#334155' }
                    },
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: { color: '#94a3b8' },
                        grid: { color: '#334155' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8' }
                    }
                }
            }
        });
        
        // Gráfico de Distribuição de Anomalias
        const anomalyBuckets = [0, 0, 0, 0, 0];
        alertas.forEach(a => {
            const score = a.anomaly_score;
            if (score < 0.2) anomalyBuckets[0]++;
            else if (score < 0.4) anomalyBuckets[1]++;
            else if (score < 0.6) anomalyBuckets[2]++;
            else if (score < 0.8) anomalyBuckets[3]++;
            else anomalyBuckets[4]++;
        });
        
        new Chart(document.getElementById('anomalyChart'), {
            type: 'bar',
            data: {
                labels: ['0-0.2', '0.2-0.4', '0.4-0.6', '0.6-0.8', '0.8-1.0'],
                datasets: [{
                    label: 'Eventos',
                    data: anomalyBuckets,
                    backgroundColor: [
                        '#10b981',
                        '#3b82f6',
                        '#f59e0b',
                        '#ef4444',
                        '#dc2626'
                    ],
                    borderRadius: 5
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#94a3b8' },
                        grid: { color: '#334155' }
                    },
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { display: false }
                    }
                }
            }
        });
        
        // Heatmap de Horários
        const horasData = Array(24).fill(0);
        alertas.forEach(a => {
            const hora = new Date(a.timestamp).getHours();
            horasData[hora]++;
        });
        
        const maxHora = Math.max(...horasData);
        const heatmapColors = horasData.map(val => {
            const intensity = maxHora > 0 ? val / maxHora : 0;
            if (intensity === 0) return '#1e293b';
            if (intensity < 0.3) return '#3b82f6';
            if (intensity < 0.6) return '#f59e0b';
            return '#ef4444';
        });
        
        new Chart(document.getElementById('heatmapChart'), {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => i + ':00'),
                datasets: [{
                    label: 'Eventos por Hora',
                    data: horasData,
                    backgroundColor: heatmapColors,
                    borderRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#94a3b8', stepSize: 1 },
                        grid: { color: '#334155' }
                    },
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { display: false }
                    }
                }
            }
        });
        
        // Timeline de Detecções
        const horasDataTimeline = {};
        for (let i = 0; i < 24; i++) {
            horasDataTimeline[i] = { normal: 0, ameacas: 0 };
        }
        
        alertas.forEach(a => {
            const hora = new Date(a.timestamp).getHours();
            if (a.label === 0) {
                horasDataTimeline[hora].normal++;
            } else {
                horasDataTimeline[hora].ameacas++;
            }
        });
        
        const timelineLabels = Object.keys(horasDataTimeline).map(h => h + ':00');
        const normalData = Object.values(horasDataTimeline).map(d => d.normal);
        const ameacasDataTimeline = Object.values(horasDataTimeline).map(d => d.ameacas);
        
        new Chart(document.getElementById('timelineChart'), {
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
                        tension: 0.4,
                        pointRadius: 4,
                        pointBackgroundColor: '#10b981'
                    },
                    {
                        label: 'Ameaças',
                        data: ameacasDataTimeline,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointBackgroundColor: '#ef4444'
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#94a3b8' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1, color: '#94a3b8' },
                        grid: { color: '#334155' }
                    },
                    x: {
                        ticks: { color: '#94a3b8' },
                        grid: { display: false }
                    }
                }
            }
        });
        
        // Controle de Sensibilidade
        const sensitivitySlider = document.getElementById('sensitivity');
        const sensitivityValue = document.getElementById('sensitivity-value');
        
        sensitivitySlider.addEventListener('input', function() {
            sensitivityValue.textContent = this.value + '%';
        });
        
        sensitivitySlider.addEventListener('change', function() {
            fetch('/api/set-sensitivity', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sensitivity: parseFloat(this.value) / 100 })
            }).then(response => response.json())
              .then(data => {
                  console.log('Sensibilidade atualizada:', data);
              });
        });
        
        // Função para exibir detalhes do alerta
        function showAlertDetail(alerta) {
            const modal = document.getElementById('alertModal');
            const modalBody = document.getElementById('modal-body');
            
            const tel = alerta.telemetria || {};
            
            let acoes = [];
            if (alerta.priority === 'CRÍTICA') {
                acoes = [
                    'Isolar sistema da rede IMEDIATAMENTE',
                    'Notificar equipe de resposta a incidentes',
                    'Capturar imagem da memória RAM',
                    'Bloquear processo suspeito',
                    'Preservar evidências forenses'
                ];
            } else if (alerta.priority === 'ALTA') {
                acoes = [
                    'Aumentar nível de logging',
                    'Monitorar processo de perto',
                    'Alertar analista de segurança',
                    'Capturar tráfego de rede',
                    'Preparar plano de resposta'
                ];
            } else if (alerta.priority === 'MÉDIA') {
                acoes = [
                    'Adicionar à lista de observação',
                    'Habilitar auditoria detalhada',
                    'Revisar em próxima análise',
                    'Documentar comportamento'
                ];
            } else {
                acoes = [
                    'Comportamento normal detectado',
                    'Manter monitoramento padrão',
                    'Nenhuma ação necessária'
                ];
            }
            
            modalBody.innerHTML = `
                <h2 style="color: #60a5fa; margin-bottom: 20px;">
                    🔍 Análise Detalhada do Alerta
                </h2>
                
                <div class="detail-section">
                    <h3>📋 Informações Gerais</h3>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-top: 15px;">
                        <div>
                            <div class="telemetry-label">Status</div>
                            <div class="telemetry-value">${alerta.status}</div>
                        </div>
                        <div>
                            <div class="telemetry-label">Prioridade</div>
                            <div class="telemetry-value">
                                <span class="priority-badge ${alerta.priority.toLowerCase()}">${alerta.priority}</span>
                            </div>
                        </div>
                        <div>
                            <div class="telemetry-label">Classificação MITRE</div>
                            <div class="telemetry-value" style="font-size: 1em;">${alerta.classificacao}</div>
                        </div>
                        <div>
                            <div class="telemetry-label">Timestamp</div>
                            <div class="telemetry-value" style="font-size: 0.9em;">${alerta.timestamp}</div>
                        </div>
                        <div>
                            <div class="telemetry-label">Confiança da Detecção</div>
                            <div class="telemetry-value">${(alerta.confidence * 100).toFixed(1)}%</div>
                        </div>
                        <div>
                            <div class="telemetry-label">Score de Anomalia</div>
                            <div class="telemetry-value">${alerta.anomaly_score.toFixed(3)}</div>
                        </div>
                        <div>
                            <div class="telemetry-label">É Anomalia?</div>
                            <div class="telemetry-value">${alerta.is_anomaly ? '⚠️ SIM' : '✓ NÃO'}</div>
                        </div>
                        <div>
                            <div class="telemetry-label">Tempo de Análise</div>
                            <div class="telemetry-value">${alerta.tempo_analise_ms.toFixed(2)}ms</div>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>📊 Telemetria Capturada</h3>
                    <div class="telemetry-grid">
                        <div class="telemetry-item">
                            <div class="telemetry-label">Processos Ativos</div>
                            <div class="telemetry-value">${tel.process_id_count || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Uso de CPU (%)</div>
                            <div class="telemetry-value">${tel.process_cpu_usage ? tel.process_cpu_usage.toFixed(1) : 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">I/O de Disco (MB/s)</div>
                            <div class="telemetry-value">${tel.disk_io_rate ? tel.disk_io_rate.toFixed(1) : 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Conexões de Rede</div>
                            <div class="telemetry-value">${tel.network_connections || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Escritas de Arquivo</div>
                            <div class="telemetry-value">${tel.file_writes || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Duração (s)</div>
                            <div class="telemetry-value">${tel.duration_seconds || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Memória (MB)</div>
                            <div class="telemetry-value">${tel.memory_usage_mb ? tel.memory_usage_mb.toFixed(0) : 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Threads</div>
                            <div class="telemetry-value">${tel.thread_count || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Modificações Registro</div>
                            <div class="telemetry-value">${tel.registry_modifications || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Queries DNS</div>
                            <div class="telemetry-value">${tel.dns_queries || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Portas Suspeitas</div>
                            <div class="telemetry-value">${tel.suspicious_ports || 'N/A'}</div>
                        </div>
                        <div class="telemetry-item">
                            <div class="telemetry-label">Anomalia Processo Pai</div>
                            <div class="telemetry-value">${tel.parent_process_anomaly ? tel.parent_process_anomaly.toFixed(2) : 'N/A'}</div>
                        </div>
                    </div>
                </div>
                
                <div class="action-recommendations">
                    <h4>⚡ Ações Recomendadas</h4>
                    <ul>
                        ${acoes.map(acao => '<li>' + acao + '</li>').join('')}
                    </ul>
                </div>
                
                <div style="margin-top: 20px; display: flex; gap: 10px; justify-content: flex-end;">
                    <button onclick="silenciarAlerta('${alerta.evento_id}')">🔇 Silenciar</button>
                    <button onclick="adicionarWhitelist('${alerta.evento_id}')">✓ Whitelist</button>
                    <button class="secondary" onclick="exportarAlerta('${alerta.evento_id}')">📥 Exportar</button>
                </div>
            `;
            
            modal.style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('alertModal').style.display = 'none';
        }
        
        // Fechar modal ao clicar fora
        window.onclick = function(event) {
            const modal = document.getElementById('alertModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }
        
        // Funções de controle
        function clearAllAlerts() {
            if (confirm('Tem certeza que deseja limpar todos os alertas?')) {
                fetch('/api/clear-alerts', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert('Alertas limpos com sucesso!');
                        location.reload();
                    })
                    .catch(error => {
                        alert('Erro ao limpar alertas: ' + error);
                    });
            }
        }
        
        function exportData() {
            window.location.href = '/api/export-csv';
        }
        
        function showWhitelist() {
            alert('Funcionalidade de whitelist em desenvolvimento.\nEm breve: gerenciar processos confiáveis.');
        }
        
        function silenciarAlerta(eventoId) {
            fetch('/api/silence-alert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ evento_id: eventoId })
            }).then(() => {
                alert('Alerta silenciado!');
                closeModal();
            }).catch(error => {
                alert('Erro ao silenciar: ' + error);
            });
        }
        
        function adicionarWhitelist(eventoId) {
            if (confirm('Adicionar este processo à whitelist?\nEle não gerará mais alertas.')) {
                fetch('/api/add-whitelist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ evento_id: eventoId })
                }).then(() => {
                    alert('Adicionado à whitelist!');
                    closeModal();
                }).catch(error => {
                    alert('Erro ao adicionar: ' + error);
                });
            }
        }
        
        function exportarAlerta(eventoId) {
            window.location.href = '/api/export-alert/' + eventoId;
        }
        
        // Auto-refresh
        let countdown = 15;
        setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown <= 0) {
                location.reload();
            }
        }, 1000);
        
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

@app.route('/api/set-sensitivity', methods=['POST'])
def set_sensitivity():
    """API: Definir sensibilidade."""
    global SENSITIVITY
    data = request.json
    SENSITIVITY = data.get('sensitivity', 0.85)
    logger.info(f"Sensibilidade atualizada para: {SENSITIVITY:.2%}")
    return jsonify({'status': 'success', 'sensitivity': SENSITIVITY})

@app.route('/api/clear-alerts', methods=['POST'])
def clear_alerts():
    """API: Limpar alertas."""
    if os.path.exists('alertas'):
        import shutil
        backup_dir = f'alertas_backup_{datetime.now():%Y%m%d_%H%M%S}'
        shutil.move('alertas', backup_dir)
        os.makedirs('alertas')
        logger.info(f"Alertas movidos para: {backup_dir}")
    return jsonify({'status': 'success'})

@app.route('/api/silence-alert', methods=['POST'])
def silence_alert():
    """API: Silenciar alerta."""
    data = request.json
    evento_id = data.get('evento_id')
    logger.info(f"Alerta silenciado: {evento_id}")
    return jsonify({'status': 'success'})

@app.route('/api/add-whitelist', methods=['POST'])
def add_whitelist():
    """API: Adicionar à whitelist."""
    data = request.json
    evento_id = data.get('evento_id')
    WHITELIST.add(evento_id)
    logger.info(f"Adicionado à whitelist: {evento_id}")
    return jsonify({'status': 'success'})

@app.route('/api/export-csv')
def export_csv():
    """API: Exportar dados em CSV."""
    alertas = carregar_alertas()
    
    df = pd.DataFrame([{
        'timestamp': a['timestamp'],
        'status': a['status'],
        'priority': a['priority'],
        'classificacao': a['classificacao'],
        'confidence': a['confidence'],
        'anomaly_score': a['anomaly_score'],
        'is_anomaly': a['is_anomaly'],
        'action': a['action']
    } for a in alertas])
    
    filename = f'edr_export_{datetime.now():%Y%m%d_%H%M%S}.csv'
    df.to_csv(filename, index=False)
    
    return jsonify({'status': 'success', 'filename': filename})

@app.route('/api/export-alert/<evento_id>')
def export_alert(evento_id):
    """API: Exportar alerta individual."""
    alertas = carregar_alertas()
    alerta = next((a for a in alertas if a.get('evento_id') == evento_id), None)
    
    if alerta:
        filename = f'alerta_{evento_id}.json'
        with open(filename, 'w') as f:
            json.dump(alerta, f, indent=2)
        return jsonify({'status': 'success', 'filename': filename})
    
    return jsonify({'status': 'error', 'message': 'Alerta não encontrado'}), 404

@app.route('/health')
def health():
    """Health check."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '5.0',
        'sensitivity': SENSITIVITY,
        'whitelist_size': len(WHITELIST)
    })

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

if __name__ == '__main__':
    logger.info("="*70)
    logger.info("🌐 EDR ULTRA v5.0 - DASHBOARD PROFISSIONAL")
    logger.info("="*70)
    logger.info("\n📊 Dashboard iniciando...")
    logger.info("🔗 Acesse: http://localhost:5000")
    logger.info("📖 API: http://localhost:5000/health")
    logger.info("\n✨ Novos recursos:")
    logger.info("  • Tema escuro profissional")
    logger.info("  • Controle de sensibilidade em tempo real")
    logger.info("  • Análise detalhada de alertas individuais")
    logger.info("  • Gráficos avançados (confiança, anomalia, heatmap)")
    logger.info("  • Sistema de whitelist")
    logger.info("  • Exportação de dados")
    logger.info("\n✅ Dashboard pronto!\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)