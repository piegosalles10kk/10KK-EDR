"""
EDR ULTRA v4.0 - JOGADOR OPERACIONAL
Sistema de detecção em tempo real com API REST e logging completo
"""

import pandas as pd
import numpy as np
import joblib
import json
import sys
import os
import logging
import time
from datetime import datetime
from collections import deque
import argparse

# ----------------------------------------------------------------------
# CONFIGURAÇÃO
# ----------------------------------------------------------------------

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Criar diretórios
os.makedirs('logs', exist_ok=True)
os.makedirs('alertas', exist_ok=True)
os.makedirs('dados', exist_ok=True)

# Logging com encoding UTF-8 para Windows
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f'logs/deteccao_{datetime.now():%Y%m%d}.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Argumentos
parser = argparse.ArgumentParser(description='EDR Ultra v4.0 - Detector Operacional')
parser.add_argument('--mode', choices=['demo', 'api', 'daemon'], default='demo', 
                    help='Modo de operação')
parser.add_argument('--port', type=int, default=8000, help='Porta da API')
parser.add_argument('--interval', type=int, default=60, help='Intervalo daemon (segundos)')
args = parser.parse_args()

# ----------------------------------------------------------------------
# FEATURE ENGINEERING (DEVE SER IDÊNTICO AO TREINO)
# ----------------------------------------------------------------------

def advanced_feature_engineering(df):
    """Feature engineering idêntico ao treinamento."""
    df = df.copy()
    df['net_conn_per_proc'] = df['network_connections'] / (df['process_id_count'] + 1e-6)
    df['file_write_rate'] = df['file_writes'] / (df['duration_seconds'] + 1e-6)
    df['cpu_per_thread'] = df['process_cpu_usage'] / (df['thread_count'] + 1e-6)
    df['io_intensity'] = df['disk_io_rate'] * df['file_writes']
    df['network_intensity'] = df['network_connections'] * df['dns_queries']
    df['anomaly_score'] = (
        (df['suspicious_ports'] * 2) + 
        (df['parent_process_anomaly'] * 3) +
        (df['registry_modifications'] / 10)
    )
    df['resource_pressure'] = (
        df['process_cpu_usage'] + 
        df['memory_usage_mb']/100 + 
        df['disk_io_rate']
    ) / 3
    return df

# ----------------------------------------------------------------------
# CARREGAR MODELOS
# ----------------------------------------------------------------------

class EDREngine:
    """Motor principal de detecção."""
    
    def __init__(self):
        logger.info("="*70)
        logger.info("EDR ULTRA v4.0 - INICIALIZANDO MOTOR DE DETECÇÃO")
        logger.info("="*70)
        
        # Carregar modelos
        try:
            self.scaler = joblib.load('modelos/scaler_v4.joblib')
            self.ensemble = joblib.load('modelos/ensemble_v4.joblib')
            self.anomaly = joblib.load('modelos/anomaly_v4.joblib')
            self.mitre_map = joblib.load('modelos/mitre_mapping_v4.joblib')
            self.features = joblib.load('modelos/features_v4.joblib')
            
            logger.info("✓ Modelos carregados")
            
            # Carregar contexto MITRE
            try:
                with open('modelos/mitre_context_v4.json', 'r', encoding='utf-8') as f:
                    self.mitre_context = json.load(f)
                logger.info(f"✓ Contexto MITRE: {len(self.mitre_context)} técnicas")
            except:
                self.mitre_context = {}
                logger.warning("⚠ Contexto MITRE não disponível")
            
            # Carregar info de versão
            try:
                with open('modelos/version_info.json', 'r') as f:
                    self.version_info = json.load(f)
                logger.info(f"✓ Versão: {self.version_info['version']}")
                logger.info(f"✓ Acurácia: {self.version_info['accuracy']:.2%}")
            except:
                self.version_info = {}
            
            # Estatísticas
            self.stats = {
                'total_analisados': 0,
                'ameacas_detectadas': 0,
                'alertas_criticos': 0,
                'alertas_altos': 0,
                'tempo_medio_ms': 0.0
            }
            
            # Buffer de histórico (últimas 1000 detecções)
            self.historico = deque(maxlen=1000)
            
            logger.info("="*70)
            logger.info("✅ SISTEMA OPERACIONAL E PRONTO!")
            logger.info("="*70 + "\n")
            
        except Exception as e:
            logger.error(f"❌ ERRO AO CARREGAR MODELOS: {e}")
            logger.error("Execute primeiro: python treinador-v4-ultra.py")
            sys.exit(1)
    
    def analisar_evento(self, telemetria):
        """Analisa um único evento de telemetria."""
        
        inicio = time.time()
        
        try:
            # Converter para DataFrame
            if isinstance(telemetria, dict):
                df = pd.DataFrame([telemetria])
            else:
                df = telemetria.copy()
            
            # Feature engineering
            df_proc = advanced_feature_engineering(df)
            
            # Normalizar
            df_scaled = self.scaler.transform(df_proc)
            
            # Predições
            pred_class = self.ensemble.predict(df_scaled)[0]
            pred_proba = self.ensemble.predict_proba(df_scaled)[0]
            pred_anomaly = self.anomaly.predict(df_scaled)[0]
            anomaly_score = -self.anomaly.score_samples(df_scaled)[0]
            
            # Análise híbrida
            resultado = self._analisar_hibrido(
                pred_class, pred_proba, pred_anomaly, anomaly_score
            )
            
            # Adicionar metadados
            resultado['timestamp'] = datetime.now().isoformat()
            resultado['tempo_analise_ms'] = (time.time() - inicio) * 1000
            resultado['evento_id'] = f"evt_{int(time.time()*1000)}"
            
            # Atualizar estatísticas
            self._atualizar_stats(resultado)
            
            # Salvar no histórico
            self.historico.append(resultado)
            
            # Salvar alerta se necessário
            if resultado['priority'] in ['CRÍTICA', 'ALTA']:
                self._salvar_alerta(resultado, df.iloc[0].to_dict())
            
            return resultado
            
        except Exception as e:
            logger.error(f"Erro ao analisar evento: {e}")
            return {
                'status': 'ERRO',
                'erro': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _analisar_hibrido(self, pred_class, pred_proba, pred_anomaly, anomaly_score):
        """Motor de decisão híbrido."""
        
        confidence = pred_proba.max()
        is_anomaly = pred_anomaly == -1
        
        # Lógica de fusão avançada
        if pred_class != 0 and confidence > 0.85:
            return {
                'status': 'AMEAÇA DETECTADA',
                'label': int(pred_class),
                'classificacao': self.mitre_map[pred_class],
                'priority': 'CRÍTICA' if confidence > 0.95 else 'ALTA',
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'action': 'BLOQUEAR_E_ISOLAR' if confidence > 0.95 else 'ALERTAR_SOC'
            }
        
        elif pred_class != 0 and is_anomaly:
            return {
                'status': 'AMEAÇA CONFIRMADA (Multi-Camadas)',
                'label': int(pred_class),
                'classificacao': self.mitre_map[pred_class],
                'priority': 'CRÍTICA',
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': True,
                'action': 'BLOQUEAR_IMEDIATAMENTE'
            }
        
        elif is_anomaly and anomaly_score > 0.7:
            return {
                'status': 'ANOMALIA SEVERA (Possível Zero-Day)',
                'label': -1,
                'classificacao': self.mitre_map[-1],
                'priority': 'CRÍTICA',
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': True,
                'action': 'QUARENTENA_E_ANALISE_FORENSE'
            }
        
        elif is_anomaly and anomaly_score > 0.4:
            return {
                'status': 'COMPORTAMENTO ANÔMALO',
                'label': -1,
                'classificacao': 'Suspeita de atividade anormal',
                'priority': 'ALTA',
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': True,
                'action': 'MONITORAR_E_ALERTAR'
            }
        
        elif pred_class != 0:
            return {
                'status': 'AMEAÇA SUSPEITA',
                'label': int(pred_class),
                'classificacao': self.mitre_map[pred_class],
                'priority': 'MÉDIA',
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': False,
                'action': 'AUMENTAR_LOGGING'
            }
        
        else:
            return {
                'status': 'NORMAL',
                'label': 0,
                'classificacao': self.mitre_map[0],
                'priority': 'BAIXA',
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': False,
                'action': 'NENHUMA'
            }
    
    def _atualizar_stats(self, resultado):
        """Atualiza estatísticas do sistema."""
        self.stats['total_analisados'] += 1
        
        if resultado['label'] != 0:
            self.stats['ameacas_detectadas'] += 1
        
        if resultado['priority'] == 'CRÍTICA':
            self.stats['alertas_criticos'] += 1
        elif resultado['priority'] == 'ALTA':
            self.stats['alertas_altos'] += 1
        
        # Média móvel do tempo de análise
        alpha = 0.1
        self.stats['tempo_medio_ms'] = (
            alpha * resultado['tempo_analise_ms'] +
            (1 - alpha) * self.stats['tempo_medio_ms']
        )
    
    def _salvar_alerta(self, resultado, telemetria):
        """Salva alerta em arquivo JSON."""
        alerta = {
            **resultado,
            'telemetria': telemetria
        }
        
        filename = f"alertas/alerta_{resultado['evento_id']}.json"
        with open(filename, 'w') as f:
            json.dump(alerta, f, indent=2)
        
        logger.warning(f"🚨 ALERTA {resultado['priority']}: {filename}")
    
    def get_stats(self):
        """Retorna estatísticas do sistema."""
        return self.stats.copy()
    
    def get_historico_recente(self, n=10):
        """Retorna últimas N detecções."""
        return list(self.historico)[-n:]

# ----------------------------------------------------------------------
# MODO DEMO (Eventos Pré-configurados)
# ----------------------------------------------------------------------

def modo_demo(engine):
    """Executa demonstração com eventos de teste."""
    
    logger.info("\n" + "="*70)
    logger.info("MODO DEMONSTRAÇÃO - Analisando 5 eventos de teste")
    logger.info("="*70 + "\n")
    
    eventos_teste = [
        {
            'nome': 'Atividade Normal de Usuário',
            'telemetria': {
                'process_id_count': 48, 'process_cpu_usage': 14.5,
                'disk_io_rate': 22.3, 'network_connections': 12,
                'file_writes': 6, 'duration_seconds': 1150,
                'memory_usage_mb': 480, 'thread_count': 18,
                'registry_modifications': 1, 'dns_queries': 18,
                'suspicious_ports': 0, 'parent_process_anomaly': 0.0
            }
        },
        {
            'nome': 'Suspeita de Ransomware',
            'telemetria': {
                'process_id_count': 65, 'process_cpu_usage': 78.5,
                'disk_io_rate': 185.0, 'network_connections': 8,
                'file_writes': 95, 'duration_seconds': 45,
                'memory_usage_mb': 1200, 'thread_count': 35,
                'registry_modifications': 3, 'dns_queries': 5,
                'suspicious_ports': 1, 'parent_process_anomaly': 0.3
            }
        },
        {
            'nome': 'Execução Suspeita de PowerShell',
            'telemetria': {
                'process_id_count': 72, 'process_cpu_usage': 45.2,
                'disk_io_rate': 38.5, 'network_connections': 28,
                'file_writes': 12, 'duration_seconds': 320,
                'memory_usage_mb': 890, 'thread_count': 42,
                'registry_modifications': 8, 'dns_queries': 45,
                'suspicious_ports': 4, 'parent_process_anomaly': 0.2
            }
        },
        {
            'nome': 'Comportamento Zero-Day Desconhecido',
            'telemetria': {
                'process_id_count': 8, 'process_cpu_usage': 99.5,
                'disk_io_rate': 8.2, 'network_connections': 250,
                'file_writes': 2, 'duration_seconds': 15,
                'memory_usage_mb': 2800, 'thread_count': 180,
                'registry_modifications': 55, 'dns_queries': 380,
                'suspicious_ports': 22, 'parent_process_anomaly': 0.95
            }
        },
        {
            'nome': 'Tentativa de Credential Dumping',
            'telemetria': {
                'process_id_count': 55, 'process_cpu_usage': 28.3,
                'disk_io_rate': 145.0, 'network_connections': 3,
                'file_writes': 18, 'duration_seconds': 90,
                'memory_usage_mb': 1450, 'thread_count': 25,
                'registry_modifications': 28, 'dns_queries': 8,
                'suspicious_ports': 0, 'parent_process_anomaly': 0.6
            }
        }
    ]
    
    for i, evento in enumerate(eventos_teste, 1):
        logger.info(f"\n{'█'*70}")
        logger.info(f"  EVENTO #{i}: {evento['nome']}")
        logger.info(f"{'█'*70}")
        
        resultado = engine.analisar_evento(evento['telemetria'])
        
        # Exibir resultado
        print(f"\n🔍 STATUS: {resultado['status']}")
        print(f"⚠️  PRIORIDADE: {resultado['priority']}")
        print(f"📌 CLASSIFICAÇÃO: {resultado['classificacao']}")
        print(f"📊 Confiança: {resultado['confidence']:.1%}")
        print(f"📊 Score Anomalia: {resultado['anomaly_score']:.3f}")
        print(f"⚡ AÇÃO: {resultado['action']}")
        print(f"⏱️  Tempo análise: {resultado['tempo_analise_ms']:.2f}ms")
    
    # Estatísticas finais
    logger.info(f"\n{'='*70}")
    logger.info("ESTATÍSTICAS DA DEMONSTRAÇÃO")
    logger.info(f"{'='*70}")
    stats = engine.get_stats()
    print(f"\n📊 Total analisado: {stats['total_analisados']}")
    print(f"🚨 Ameaças detectadas: {stats['ameacas_detectadas']}")
    print(f"🔴 Alertas críticos: {stats['alertas_criticos']}")
    print(f"🟠 Alertas altos: {stats['alertas_altos']}")
    print(f"⚡ Tempo médio: {stats['tempo_medio_ms']:.2f}ms")
    print(f"\n✅ Demonstração concluída!")

# ----------------------------------------------------------------------
# MODO API (REST API com FastAPI)
# ----------------------------------------------------------------------

def modo_api(engine):
    """Inicia servidor de API REST."""
    
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
        from pydantic import BaseModel
        import uvicorn
    except ImportError:
        logger.error("❌ FastAPI não instalado. Execute: pip install fastapi uvicorn")
        sys.exit(1)
    
    app = FastAPI(
        title="EDR Ultra API v4.0",
        description="API de Detecção de Ameaças em Tempo Real",
        version="4.0"
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Modelo de dados
    class TelemetriaEvento(BaseModel):
        process_id_count: int
        process_cpu_usage: float
        disk_io_rate: float
        network_connections: int
        file_writes: int
        duration_seconds: int
        memory_usage_mb: float
        thread_count: int
        registry_modifications: int
        dns_queries: int
        suspicious_ports: int
        parent_process_anomaly: float
    
    @app.get("/")
    def root():
        return {
            "service": "EDR Ultra API",
            "version": "4.0",
            "status": "operational",
            "endpoints": ["/analyze", "/stats", "/history", "/health"]
        }
    
    @app.post("/analyze")
    def analisar(evento: TelemetriaEvento):
        """Analisa um evento de telemetria."""
        try:
            resultado = engine.analisar_evento(evento.dict())
            return resultado
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/stats")
    def estatisticas():
        """Retorna estatísticas do sistema."""
        return engine.get_stats()
    
    @app.get("/history")
    def historico(limit: int = 10):
        """Retorna histórico recente."""
        return engine.get_historico_recente(limit)
    
    @app.get("/health")
    def health():
        """Health check."""
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "stats": engine.get_stats()
        }
    
    logger.info(f"\n🌐 Iniciando API REST na porta {args.port}...")
    logger.info(f"📖 Documentação: http://localhost:{args.port}/docs")
    logger.info(f"✅ API pronta para receber requisições!\n")
    
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")

# ----------------------------------------------------------------------
# MODO DAEMON (Monitoramento Contínuo)
# ----------------------------------------------------------------------

def modo_daemon(engine):
    """Executa monitoramento contínuo do sistema."""
    
    try:
        import psutil
    except ImportError:
        logger.error("❌ psutil não instalado. Execute: pip install psutil")
        sys.exit(1)
    
    logger.info(f"\n🔄 Modo Daemon iniciado (intervalo: {args.interval}s)")
    logger.info("Pressione Ctrl+C para encerrar\n")
    
    while True:
        try:
            # Coletar telemetria do sistema
            telemetria = {
                'process_id_count': len(psutil.pids()),
                'process_cpu_usage': psutil.cpu_percent(interval=1),
                'disk_io_rate': psutil.disk_io_counters().write_bytes / (1024*1024),
                'network_connections': len(psutil.net_connections()),
                'file_writes': psutil.disk_io_counters().write_count,
                'duration_seconds': args.interval,
                'memory_usage_mb': psutil.virtual_memory().used / (1024*1024),
                'thread_count': sum(p.num_threads() for p in psutil.process_iter(['num_threads'])),
                'registry_modifications': 0,
                'dns_queries': 0,
                'suspicious_ports': 0,
                'parent_process_anomaly': 0.0
            }
            
            # Analisar
            resultado = engine.analisar_evento(telemetria)
            
            # Log apenas se anormal
            if resultado['priority'] != 'BAIXA':
                logger.warning(
                    f"⚠️  {resultado['status']} | "
                    f"Prioridade: {resultado['priority']} | "
                    f"Classificação: {resultado['classificacao']}"
                )
            else:
                logger.info("✓ Sistema normal")
            
            # Aguardar próximo ciclo
            time.sleep(args.interval)
            
        except KeyboardInterrupt:
            logger.info("\n\n🛑 Encerrando daemon...")
            break
        except Exception as e:
            logger.error(f"Erro no loop: {e}")
            time.sleep(args.interval)
    
    # Estatísticas finais
    stats = engine.get_stats()
    logger.info(f"\n{'='*70}")
    logger.info("ESTATÍSTICAS FINAIS")
    logger.info(f"{'='*70}")
    logger.info(f"Total analisado: {stats['total_analisados']}")
    logger.info(f"Ameaças detectadas: {stats['ameacas_detectadas']}")
    logger.info(f"Alertas críticos: {stats['alertas_criticos']}")
    logger.info("="*70)

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    """Ponto de entrada principal."""
    
    # Inicializar engine
    engine = EDREngine()
    
    # Executar modo selecionado
    if args.mode == 'demo':
        modo_demo(engine)
    elif args.mode == 'api':
        modo_api(engine)
    elif args.mode == 'daemon':
        modo_daemon(engine)

if __name__ == '__main__':
    main()