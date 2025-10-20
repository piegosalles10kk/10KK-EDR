"""
EDR ULTRA v4.0 - TREINADOR DE PRODUÇÃO
Sistema completo com logging, métricas e otimizações avançadas
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import (IsolationForest, RandomForestClassifier, 
                              GradientBoostingClassifier, VotingClassifier) 
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
import joblib
import json 
import sys 
import os 
import requests
import time
import logging
from datetime import datetime
import argparse
import warnings
warnings.filterwarnings('ignore')

# ----------------------------------------------------------------------
# SETUP INICIAL
# ----------------------------------------------------------------------

if __name__ == '__main__':
    import multiprocessing
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except:
        pass

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Configurar logging profissional
os.makedirs('logs', exist_ok=True)
os.makedirs('modelos', exist_ok=True)
os.makedirs('metricas', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f'logs/treinamento_{datetime.now():%Y%m%d_%H%M%S}.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# ARGUMENTOS DE LINHA DE COMANDO
# ----------------------------------------------------------------------

parser = argparse.ArgumentParser(description='EDR Ultra v4.0 - Treinador Avançado')
parser.add_argument('--dataset', type=str, default=None, help='Dataset customizado (CSV)')
parser.add_argument('--samples', type=int, default=800, help='Amostras por classe')
parser.add_argument('--estimators', type=int, default=100, help='Número de estimadores')
parser.add_argument('--validation', action='store_true', help='Ativar validação cruzada')
parser.add_argument('--quick', action='store_true', help='Modo rápido (menos amostras)')
parser.add_argument('--export-metrics', action='store_true', help='Exportar métricas detalhadas')
args = parser.parse_args()

# Ajustar baseado em argumentos
if args.quick:
    args.samples = 400
    args.estimators = 50
    logger.info("Modo rápido ativado (treino mais rápido)") 

# ----------------------------------------------------------------------
# CONFIGURAÇÕES GLOBAIS
# ----------------------------------------------------------------------

class Config:
    VERSION = "4.0-ultra"
    N_SAMPLES = args.samples
    N_ESTIMATORS = args.estimators
    MAX_DEPTH = 15
    N_JOBS = 2
    RANDOM_STATE = 42
    TEST_SIZE = 0.25
    ENABLE_CV = args.validation
    EXPORT_METRICS = args.export_metrics

CONFIG = Config()

logger.info(f"="*70)
logger.info(f"EDR ULTRA v{CONFIG.VERSION} - SISTEMA DE TREINAMENTO AVANÇADO")
logger.info(f"="*70)
logger.info(f"Configurações:")
logger.info(f"  - Amostras por classe: {CONFIG.N_SAMPLES}")
logger.info(f"  - Estimadores: {CONFIG.N_ESTIMATORS}")
logger.info(f"  - Validação cruzada: {'SIM' if CONFIG.ENABLE_CV else 'NÃO'}")
logger.info(f"  - Dataset customizado: {args.dataset if args.dataset else 'Sintético'}")

# ----------------------------------------------------------------------
# MAPEAMENTO MITRE ATT&CK
# ----------------------------------------------------------------------

MITRE_MAPPING = {
    0: "Normal (No Threat Detected)",
    1: "T1059.001 - Powershell Execution",
    2: "T1055 - Process Injection",
    3: "T1566 - Phishing/Initial Access",
    4: "T1003 - OS Credential Dumping",
    5: "T1070.004 - File Deletion",
    6: "T1027 - Obfuscated Files or Information",
    7: "T1068 - Exploitation for Privilege Escalation", 
    8: "T1021.001 - Remote Desktop Protocol",
    9: "T1486 - Data Encrypted for Impact (Ransomware)",
    10: "T1571 - Non-Standard Port",
    11: "T1036 - Masquerading",
    12: "T1547.001 - Registry Run Keys / Startup Folder",
    13: "T1087 - Account Discovery",
    14: "T1560 - Archive Collected Data (Exfiltration)",
    -1: "ANOMALIA - Alto Desvio Comportamental (Zero-Day)"
}

FEATURES = [
    'process_id_count', 'process_cpu_usage', 'disk_io_rate', 
    'network_connections', 'file_writes', 'duration_seconds',
    'memory_usage_mb', 'thread_count', 'registry_modifications',
    'dns_queries', 'suspicious_ports', 'parent_process_anomaly'
]

# ----------------------------------------------------------------------
# GERADOR DE DADOS SINTÉTICOS MELHORADO (CORRIGIDO)
# ----------------------------------------------------------------------

def create_attack_data(num_samples, attack_label, base_data):
    """Gera dados sintéticos com variação realista."""
    
    data = pd.concat([base_data] * num_samples, ignore_index=True)
    
    # CORREÇÃO FINAL CRÍTICA: Aumenta o fator de ruído para 1.0 (20x mais que o original).
    # Isso treina o modelo para ser robusto a grandes variações de ruído.
    NOISE_FACTOR = 1.0 
    
    for col in data.columns:
        # Aumenta a variância do ruído para forçar a generalização
        noise = np.random.normal(0, NOISE_FACTOR, num_samples) * base_data[col].values[0]
        data[col] = np.abs(data[col] + noise)

    # Lógica de cada ataque (mantida)
    if attack_label == 1:
        data['process_cpu_usage'] *= np.random.uniform(1.8, 3.0, num_samples)
        data['network_connections'] += np.random.randint(8, 20, num_samples)
        data['memory_usage_mb'] *= np.random.uniform(1.5, 2.5, num_samples)
        data['suspicious_ports'] += np.random.randint(2, 5, num_samples)
    elif attack_label == 2:
        data['disk_io_rate'] *= np.random.uniform(2.5, 4.0, num_samples)
        data['file_writes'] *= np.random.uniform(2.0, 4.0, num_samples)
        data['thread_count'] *= np.random.uniform(3.0, 6.0, num_samples)
        data['parent_process_anomaly'] = np.random.uniform(0.7, 1.0, num_samples)
    elif attack_label == 3:
        data['network_connections'] += np.random.randint(30, 60, num_samples)
        data['dns_queries'] += np.random.randint(50, 100, num_samples)
        data['suspicious_ports'] += np.random.randint(5, 10, num_samples)
    elif attack_label == 4:
        data['disk_io_rate'] *= np.random.uniform(4.0, 7.0, num_samples)
        data['memory_usage_mb'] *= np.random.uniform(2.0, 4.0, num_samples)
        data['registry_modifications'] += np.random.randint(10, 30, num_samples)
    elif attack_label == 5:
        data['file_writes'] *= np.random.uniform(8.0, 15.0, num_samples)
        data['duration_seconds'] *= np.random.uniform(0.01, 0.15, num_samples)
    elif attack_label == 6:
        data['process_cpu_usage'] *= np.random.uniform(2.5, 5.0, num_samples)
        data['process_id_count'] *= np.random.uniform(2.0, 4.0, num_samples)
        data['memory_usage_mb'] *= np.random.uniform(1.8, 3.5, num_samples)
    elif attack_label == 7:
        data['process_cpu_usage'] *= np.random.uniform(4.0, 8.0, num_samples)
        data['disk_io_rate'] *= np.random.uniform(5.0, 9.0, num_samples)
        data['registry_modifications'] += np.random.randint(20, 50, num_samples)
    elif attack_label == 8:
        data['network_connections'] += np.random.randint(60, 120, num_samples)
        data['suspicious_ports'] += np.random.randint(8, 15, num_samples)
        data['duration_seconds'] *= np.random.uniform(0.05, 0.3, num_samples)
    elif attack_label == 9:
        data['file_writes'] *= np.random.uniform(10.0, 20.0, num_samples)
        data['disk_io_rate'] *= np.random.uniform(8.0, 15.0, num_samples)
        data['process_cpu_usage'] *= np.random.uniform(5.0, 10.0, num_samples)
    elif attack_label == 10:
        data['suspicious_ports'] += np.random.randint(15, 30, num_samples)
        data['network_connections'] += np.random.randint(40, 80, num_samples)
    elif attack_label == 11:
        data['parent_process_anomaly'] = np.random.uniform(0.8, 1.0, num_samples)
        data['process_id_count'] *= np.random.uniform(1.5, 2.5, num_samples)
    elif attack_label == 12:
        data['registry_modifications'] += np.random.randint(30, 70, num_samples)
        data['file_writes'] *= np.random.uniform(3.0, 6.0, num_samples)
    elif attack_label == 13:
        data['network_connections'] += np.random.randint(80, 150, num_samples)
        data['dns_queries'] += np.random.randint(100, 200, num_samples)
    elif attack_label == 14:
        data['registry_modifications'] += np.random.randint(15, 40, num_samples)
        data['memory_usage_mb'] *= np.random.uniform(1.3, 2.0, num_samples)
    elif attack_label == 15:
        data['disk_io_rate'] *= np.random.uniform(6.0, 10.0, num_samples)
        data['network_connections'] += np.random.randint(20, 50, num_samples)

    data['target'] = attack_label
    return data[FEATURES + ['target']]

# ----------------------------------------------------------------------
# GERAÇÃO OU CARREGAMENTO DE DATASET (RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

def load_or_generate_dataset():
    """Carrega dataset customizado ou gera sintético."""
    
    if args.dataset and os.path.exists(args.dataset):
        logger.info(f"Carregando dataset customizado: {args.dataset}") 
        df = pd.read_csv(args.dataset)
        
        if 'source' in df.columns:
            df = df.drop(['source', 'confidence'], axis=1, errors='ignore')
        
        logger.info(f"Concluído: Dataset carregado com {len(df):,} eventos")
        return df
    
    else:
        logger.info("Gerando dataset sintético...")
        
        base_normal = pd.DataFrame({
            'process_id_count': [50],
            'process_cpu_usage': [12.0],
            'disk_io_rate': [25.0],
            'network_connections': [10],
            'file_writes': [5],
            'duration_seconds': [600],
            'memory_usage_mb': [512],
            'thread_count': [20],
            'registry_modifications': [2],
            'dns_queries': [15],
            'suspicious_ports': [0],
            'parent_process_anomaly': [0.0]
        })
        
        all_data = []
        
        # Normal (70%)
        normal_data = create_attack_data(CONFIG.N_SAMPLES * 5, 0, base_normal)
        all_data.append(normal_data)
        
        # Ataques (30%)
        for label in range(1, len(MITRE_MAPPING) - 1):
            attack_data = create_attack_data(CONFIG.N_SAMPLES, label, base_normal)
            all_data.append(attack_data)
        
        df = pd.concat(all_data, ignore_index=True)
        logger.info(f"Concluído: Dataset sintético com {len(df):,} eventos")
        
        return df

df = load_or_generate_dataset()

logger.info(f"\nDistribuicao de classes:")
for idx, count in df['target'].value_counts().sort_index().items():
    logger.info(f"  {MITRE_MAPPING.get(idx, f'Classe {idx}')}: {count:,}")

# ----------------------------------------------------------------------
# FEATURE ENGINEERING
# ----------------------------------------------------------------------

def advanced_feature_engineering(df):
    """Feature engineering completo."""
    
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

logger.info("\nAplicando feature engineering...") 
df = advanced_feature_engineering(df)
X = df.drop('target', axis=1)
y = df['target']
FEATURE_COLUMNS = X.columns

logger.info(f"Concluído: Features: {len(FEATURE_COLUMNS)} (12 base + 7 derivadas)")

# ----------------------------------------------------------------------
# DIVISÃO E NORMALIZAÇÃO
# ----------------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=CONFIG.TEST_SIZE, random_state=CONFIG.RANDOM_STATE, stratify=y
)

logger.info(f"\nDivisão dos dados:")
logger.info(f"  - Treino: {len(X_train):,} eventos ({len(X_train)/len(df)*100:.1f}%)")
logger.info(f"  - Teste: {len(X_test):,} eventos ({len(X_test)/len(df)*100:.1f}%)")

scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

logger.info("Concluído: Normalização aplicada (RobustScaler)")

# ----------------------------------------------------------------------
# TREINAMENTO DO ENSEMBLE (RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

logger.info(f"\n{'='*70}")
logger.info("TREINAMENTO DO ENSEMBLE MULTI-ALGORITMO") 
logger.info(f"{'='*70}")

# Random Forest
logger.info("\n[1/3] Treinando Random Forest...")
# ADICIONADA: Regularização leve para forçar a generalização
rf_clf = RandomForestClassifier(
    n_estimators=CONFIG.N_ESTIMATORS,
    max_depth=CONFIG.MAX_DEPTH,
    min_samples_split=5,
    min_samples_leaf=3, # Aumenta a regularização
    random_state=CONFIG.RANDOM_STATE,
    class_weight='balanced',
    n_jobs=CONFIG.N_JOBS,
    verbose=0
)

# Gradient Boosting
logger.info("[2/3] Treinando Gradient Boosting...")
gb_clf = GradientBoostingClassifier(
    n_estimators=CONFIG.N_ESTIMATORS,
    learning_rate=0.1,
    max_depth=8,
    random_state=CONFIG.RANDOM_STATE,
    verbose=0
)

# Neural Network
logger.info("[3/3] Treinando Neural Network...")
# ADICIONADA: Regularização L2 (alpha) aumentada para evitar overfitting
mlp_clf = MLPClassifier(
    hidden_layer_sizes=(64, 32),
    activation='relu',
    solver='adam',
    alpha=0.01, # Aumentado de 0.001 para 0.01
    max_iter=300,
    random_state=CONFIG.RANDOM_STATE,
    verbose=False
)

# Voting Ensemble
logger.info("\nCombinando modelos em Voting Ensemble...") 
ensemble_clf = VotingClassifier(
    estimators=[
        ('rf', rf_clf),
        ('gb', gb_clf),
        ('mlp', mlp_clf)
    ],
    voting='soft',
    n_jobs=1
)

start_time = time.time()
ensemble_clf.fit(X_train_scaled, y_train)
train_time = time.time() - start_time

logger.info(f"Concluído: Ensemble treinado em {train_time:.2f}s")

# Avaliação
y_pred_ensemble = ensemble_clf.predict(X_test_scaled)
y_proba_ensemble = ensemble_clf.predict_proba(X_test_scaled)
accuracy_ensemble = accuracy_score(y_test, y_pred_ensemble)

logger.info(f"Concluído: Acurácia do Ensemble: {accuracy_ensemble:.4f}")

# Validação cruzada (opcional)
if CONFIG.ENABLE_CV:
    logger.info("\nExecutando validação cruzada (5-fold)...") 
    from sklearn.model_selection import cross_val_score
    cv_scores = cross_val_score(rf_clf, X_train_scaled, y_train, cv=5, n_jobs=CONFIG.N_JOBS)
    logger.info(f"Concluído: CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# ----------------------------------------------------------------------
# TREINAMENTO DO DETECTOR DE ANOMALIAS (RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

logger.info(f"\n{'='*70}")
logger.info("TREINAMENTO DO DETECTOR DE ANOMALIAS") 
logger.info(f"{'='*70}")

X_train_normal = X_train[y_train == 0]
X_train_normal_scaled = scaler.transform(X_train_normal)

logger.info(f"\nTreinando Isolation Forest com {len(X_train_normal):,} eventos normais...")

iso_forest = IsolationForest(
    contamination=0.02,
    n_estimators=150,
    max_samples=256,
    random_state=CONFIG.RANDOM_STATE,
    n_jobs=1,
    verbose=0
)
iso_forest.fit(X_train_normal_scaled)

y_pred_if = iso_forest.predict(X_test_scaled)
y_test_anomaly = np.where(y_test != 0, -1, 1)
anom_accuracy = accuracy_score(y_test_anomaly, y_pred_if)

logger.info(f"Concluído: Acurácia Isolation Forest: {anom_accuracy:.4f}")

# ----------------------------------------------------------------------
# MÉTRICAS DETALHADAS (RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

logger.info(f"\n{'='*70}")
logger.info("RELATÓRIO DE CLASSIFICAÇÃO DETALHADO") 
logger.info(f"{'='*70}\n")

target_names = [MITRE_MAPPING[i] for i in sorted(y.unique()) if i >= 0]
report = classification_report(y_test, y_pred_ensemble, target_names=target_names, zero_division=0)
print(report)

# Matriz de confusão
conf_matrix = confusion_matrix(y_test, y_pred_ensemble)
logger.info(f"\nMatriz de Confusão salva em: metricas/confusion_matrix.npy") 
np.save('metricas/confusion_matrix.npy', conf_matrix)

# Exportar métricas detalhadas
if CONFIG.EXPORT_METRICS:
    logger.info("\nExportando métricas detalhadas...") 
    
    metricas = {
        'timestamp': datetime.now().isoformat(),
        'version': CONFIG.VERSION,
        'dataset_size': len(df),
        'train_size': len(X_train),
        'test_size': len(X_test),
        'training_time': train_time,
        'ensemble_accuracy': float(accuracy_ensemble),
        'anomaly_accuracy': float(anom_accuracy),
        'n_features': len(FEATURE_COLUMNS),
        'n_classes': len(y.unique()),
        'config': vars(CONFIG)
    }
    
    with open(f'metricas/training_metrics_{datetime.now():%Y%m%d_%H%M%S}.json', 'w') as f:
        json.dump(metricas, f, indent=2)
    
    logger.info("Concluído: Métricas exportadas")

# ----------------------------------------------------------------------
# SALVAR MODELOS (RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

logger.info(f"\n{'='*70}")
logger.info("SALVANDO ARTEFATOS") 
logger.info(f"{'='*70}")

# Salvar dataset de treino
df.to_csv('modelos/training_base_v4.csv', index=False)
logger.info("Concluído: Base de treinamento: modelos/training_base_v4.csv")

# Salvar modelos
joblib.dump(scaler, 'modelos/scaler_v4.joblib')
joblib.dump(ensemble_clf, 'modelos/ensemble_v4.joblib')
joblib.dump(iso_forest, 'modelos/anomaly_v4.joblib')
joblib.dump(FEATURE_COLUMNS, 'modelos/features_v4.joblib')
joblib.dump(MITRE_MAPPING, 'modelos/mitre_mapping_v4.joblib')

logger.info("Concluído: Scaler: modelos/scaler_v4.joblib")
logger.info("Concluído: Ensemble: modelos/ensemble_v4.joblib")
logger.info("Concluído: Anomaly Detector: modelos/anomaly_v4.joblib")
logger.info("Concluído: Features: modelos/features_v4.joblib")
logger.info("Concluído: MITRE Mapping: modelos/mitre_mapping_v4.joblib")

# Criar arquivo de versão
version_info = {
    'version': CONFIG.VERSION,
    'created_at': datetime.now().isoformat(),
    'accuracy': float(accuracy_ensemble),
    'samples': len(df),
    'features': list(FEATURE_COLUMNS),
    'mitre_techniques': len(MITRE_MAPPING) - 2
}

with open('modelos/version_info.json', 'w') as f:
    json.dump(version_info, f, indent=2)

logger.info("Concluído: Informações de versão: modelos/version_info.json")

# ----------------------------------------------------------------------
# DOWNLOAD MITRE ATT&CK (Opcional - RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

logger.info(f"\n{'='*70}")
logger.info("DOWNLOAD MITRE ATT&CK") 
logger.info(f"{'='*70}")

ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
ATTACK_FILE = 'modelos/enterprise-attack.json'

max_retries = 2
for attempt in range(max_retries):
    try:
        if os.path.exists(ATTACK_FILE):
            os.remove(ATTACK_FILE)
        
        response = requests.get(ATTACK_URL, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(ATTACK_FILE, 'wb') as f:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
        
        file_size_mb = os.path.getsize(ATTACK_FILE) / (1024 * 1024)
        logger.info(f"Concluído: Download completo: {file_size_mb:.2f} MB")
        
        # Validar JSON
        with open(ATTACK_FILE, 'r', encoding='utf-8') as f:
            stix_data = json.load(f)
        
        logger.info(f"Concluído: JSON validado: {len(stix_data.get('objects', []))} objetos")
        
        # Extrair contexto
        mitre_context = {}
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                tech_id = obj.get('external_references', [{}])[0].get('external_id', '')
                if any(tech_id in v for v in MITRE_MAPPING.values()):
                    mitre_context[tech_id] = {
                        'name': obj.get('name'),
                        'description': obj.get('description', '')[:200] + '...',
                        'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', [])]
                    }
        
        with open('modelos/mitre_context_v4.json', 'w', encoding='utf-8') as f:
            json.dump(mitre_context, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Concluído: Contexto MITRE: {len(mitre_context)} técnicas")
        break
        
    except Exception as e:
        logger.warning(f"Tentativa {attempt+1} falhou: {str(e)[:50]}") 
        if attempt < max_retries - 1:
            time.sleep(3)
else:
    logger.warning("MITRE ATT&CK não baixado (não crítico)") 

# ----------------------------------------------------------------------
# RESUMO FINAL (RESTANTE DO CÓDIGO)
# ----------------------------------------------------------------------

logger.info(f"\n{'='*70}")
logger.info("TREINAMENTO CONCLUÍDO COM SUCESSO!") 
logger.info(f"{'='*70}")
logger.info(f"\nRESUMO EXECUTIVO:") 
logger.info(f"  - Versão: EDR Ultra v{CONFIG.VERSION}")
logger.info(f"  - Dataset: {len(df):,} eventos")
logger.info(f"  - Features: {len(FEATURE_COLUMNS)}")
logger.info(f"  - Técnicas ATT&CK: {len(MITRE_MAPPING)-2}")
logger.info(f"  - Acurácia Ensemble: {accuracy_ensemble:.2%}")
logger.info(f"  - Acurácia Anomalia: {anom_accuracy:.2%}")
logger.info(f"  - Tempo de Treino: {train_time:.2f}s")
logger.info(f"\nArquivos gerados:") 
logger.info(f"  - modelos/*.joblib (5 arquivos)")
logger.info(f"  - modelos/training_base_v4.csv")
logger.info(f"  - modelos/version_info.json")
logger.info(f"  - logs/treinamento_*.log")
logger.info(f"\nProximo passo:") 
logger.info(f"  python jogador-v4-operacional.py")
logger.info(f"{'='*70}\n")

logger.info(f"Finalizado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")