"""
EDR ULTRA AGENT v1.0 - AGENTE LEVE
Coleta telemetria local e envia para servidor EDR central
Peso mínimo: ~50MB RAM, ~5% CPU
"""

import psutil
import requests
import time
import json
import platform
import socket
import logging
from datetime import datetime
import argparse
import sys

# ----------------------------------------------------------------------
# CONFIGURAÇÃO
# ----------------------------------------------------------------------

parser = argparse.ArgumentParser(description='EDR Ultra Agent v1.0')
parser.add_argument('--server', type=str, required=True, 
                    help='URL do servidor EDR (ex: http://192.168.1.100:8000)')
parser.add_argument('--interval', type=int, default=60, 
                    help='Intervalo de coleta em segundos')
parser.add_argument('--agent-id', type=str, default=None,
                    help='ID único do agente (gerado automaticamente se não fornecido)')
parser.add_argument('--log-file', type=str, default='edr_agent.log',
                    help='Arquivo de log')
args = parser.parse_args()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(args.log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# CLASSE DO AGENTE
# ----------------------------------------------------------------------

class EDRAgent:
    """Agente leve de coleta de telemetria."""
    
    def __init__(self, server_url, interval=60):
        self.server_url = server_url.rstrip('/')
        self.interval = interval
        self.hostname = socket.gethostname()
        self.sistema_operacional = platform.system()
        self.versao_agente = "1.0"
        self.agente_id = args.agent_id or self._gerar_agent_id()
        self.registrado = False
        self.stats = {
            'eventos_enviados': 0,
            'falhas': 0,
            'ultima_coleta': None
        }
        
        logger.info("="*70)
        logger.info("EDR ULTRA AGENT v1.0 - INICIALIZADO")
        logger.info("="*70)
        logger.info(f"Agente ID: {self.agente_id}")
        logger.info(f"Hostname: {self.hostname}")
        logger.info(f"SO: {self.sistema_operacional}")
        logger.info(f"Servidor: {self.server_url}")
        logger.info(f"Intervalo: {self.interval}s")
        logger.info("="*70 + "\n")
    
    def _gerar_agent_id(self):
        """Gera ID único do agente baseado em hostname e MAC."""
        try:
            mac = ':'.join(['{:02x}'.format((psutil.net_if_addrs()[iface][0].address.replace(':', '')))
                            for iface in psutil.net_if_addrs()][0])
        except:
            mac = 'unknown'
        
        return f"agent_{self.hostname}_{mac[:8]}"
    
    def _obter_ip_local(self):
        """Obtém IP local da máquina."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def registrar(self):
        """Registra o agente no servidor central."""
        logger.info("Registrando agente no servidor...")
        
        payload = {
            "agente_id": self.agente_id,
            "hostname": self.hostname,
            "sistema_operacional": self.sistema_operacional,
            "versao_agente": self.versao_agente,
            "ip_address": self._obter_ip_local()
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/agents/register",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.registrado = True
                logger.info("✓ Agente registrado com sucesso!")
                return True
            else:
                logger.error(f"✗ Falha no registro: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Erro ao conectar ao servidor: {e}")
            return False
    
    def coletar_telemetria(self):
        """Coleta telemetria do sistema local."""
        try:
            # Processos
            process_count = len(psutil.pids())
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memória
            mem = psutil.virtual_memory()
            memory_mb = mem.used / (1024 * 1024)
            
            # Disco
            disk_io = psutil.disk_io_counters()
            disk_io_rate = (disk_io.write_bytes + disk_io.read_bytes) / (1024 * 1024)
            file_writes = disk_io.write_count
            
            # Rede
            try:
                net_conns = len(psutil.net_connections())
            except:
                net_conns = 0
            
            # Threads
            thread_count = 0
            for proc in psutil.process_iter(['num_threads']):
                try:
                    thread_count += proc.info['num_threads']
                except:
                    continue
            
            # Portas suspeitas (scan básico)
            suspicious_ports = self._detectar_portas_suspeitas()
            
            # Processos anômalos
            parent_anomaly = self._detectar_processos_anomalos()
            
            telemetria = {
                'process_id_count': process_count,
                'process_cpu_usage': cpu_percent,
                'disk_io_rate': disk_io_rate,
                'network_connections': net_conns,
                'file_writes': file_writes,
                'duration_seconds': self.interval,
                'memory_usage_mb': memory_mb,
                'thread_count': thread_count,
                'registry_modifications': 0,  # Windows específico
                'dns_queries': 0,  # Requer sniffer
                'suspicious_ports': suspicious_ports,
                'parent_process_anomaly': parent_anomaly
            }
            
            self.stats['ultima_coleta'] = datetime.now().isoformat()
            return telemetria
            
        except Exception as e:
            logger.error(f"Erro ao coletar telemetria: {e}")
            return None
    
    def _detectar_portas_suspeitas(self):
        """Detecta portas não-padrão em uso."""
        portas_suspeitas = 0
        portas_conhecidas = {80, 443, 22, 21, 25, 110, 143, 3306, 5432, 8080}
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.port not in portas_conhecidas:
                    if conn.laddr.port > 1024:  # Portas dinâmicas
                        portas_suspeitas += 1
        except:
            pass
        
        return min(portas_suspeitas, 50)  # Limitar para evitar falsos positivos
    
    def _detectar_processos_anomalos(self):
        """Detecta processos com comportamento anômalo."""
        score_anomalia = 0.0
        
        try:
            for proc in psutil.process_iter(['name', 'ppid', 'cpu_percent']):
                try:
                    # Processos sem parent (órfãos)
                    if proc.info['ppid'] == 0 and proc.info['name'] not in ['System', 'Idle']:
                        score_anomalia += 0.1
                    
                    # CPU muito alto
                    if proc.info['cpu_percent'] > 90:
                        score_anomalia += 0.05
                    
                except:
                    continue
            
        except:
            pass
        
        return min(score_anomalia, 1.0)
    
    def enviar_telemetria(self, telemetria):
        """Envia telemetria para o servidor central."""
        headers = {
            'agente-id': self.agente_id,
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.post(
                f"{self.server_url}/analyze",
                json=telemetria,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                resultado = response.json()
                self.stats['eventos_enviados'] += 1
                
                # Log apenas se for ameaça
                if resultado.get('priority') in ['CRÍTICA', 'ALTA']:
                    logger.warning(
                        f"⚠️  AMEAÇA DETECTADA: {resultado.get('classificacao')} "
                        f"(Confiança: {resultado.get('confidence', 0):.1%})"
                    )
                else:
                    logger.info("✓ Telemetria enviada | Status: Normal")
                
                return resultado
            else:
                logger.error(f"✗ Erro ao enviar: HTTP {response.status_code}")
                self.stats['falhas'] += 1
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Erro de conexão: {e}")
            self.stats['falhas'] += 1
            return None
    
    def executar(self):
        """Loop principal do agente."""
        
        # Registrar no servidor
        if not self.registrar():
            logger.error("Falha ao registrar. Tentando continuar...")
        
        logger.info("\n🔄 Agente em execução. Pressione Ctrl+C para encerrar.\n")
        
        while True:
            try:
                # Coletar telemetria
                logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] Coletando telemetria...")
                telemetria = self.coletar_telemetria()
                
                if telemetria:
                    # Enviar para servidor
                    self.enviar_telemetria(telemetria)
                
                # Aguardar próximo ciclo
                time.sleep(self.interval)
                
            except KeyboardInterrupt:
                logger.info("\n\n🛑 Encerrando agente...")
                break
            except Exception as e:
                logger.error(f"Erro no loop principal: {e}")
                time.sleep(self.interval)
        
        # Estatísticas finais
        self._exibir_estatisticas()
    
    def _exibir_estatisticas(self):
        """Exibe estatísticas do agente."""
        logger.info("\n" + "="*70)
        logger.info("ESTATÍSTICAS DO AGENTE")
        logger.info("="*70)
        logger.info(f"Eventos enviados: {self.stats['eventos_enviados']}")
        logger.info(f"Falhas: {self.stats['falhas']}")
        logger.info(f"Última coleta: {self.stats['ultima_coleta']}")
        logger.info("="*70)

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    """Ponto de entrada principal."""
    
    # Criar agente
    agent = EDRAgent(
        server_url=args.server,
        interval=args.interval
    )
    
    # Executar
    agent.executar()

if __name__ == '__main__':
    main()