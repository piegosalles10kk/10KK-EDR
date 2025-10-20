import pandas as pd
import numpy as np
import joblib

# --- Função de Feature Engineering (DEVE ser a mesma usada no treino) ---
def feature_engineering(df):
    df['net_conn_per_proc'] = df['network_connections'] / (df['process_id_count'] + 1e-6)
    df['file_write_rate'] = df['file_writes'] / (df['duration_seconds'] + 1e-6)
    return df

# --- Mapeamento (para interpretar o resultado da classificação) ---
MITRE_MAPPING = {
    0: "Normal (No Threat Detected)",
    1: "T1059.001 - Powershell Execution",
    2: "T1055 - Process Injection",
    3: "T1566 - Phishing/Initial Access",
    -1: "ANOMALIA - Alto Desvio Comportamental (Potential Zero-Day)" 
}

# ----------------------------------------------------------------------
# 1. Carregar os artefatos de treinamento
# ----------------------------------------------------------------------
try:
    scaler = joblib.load('scaler_edr.joblib')
    iso_forest_model = joblib.load('model_anomaly_if.joblib')
    rf_classifier = joblib.load('model_classifier_rf.joblib')
    print("Modelos e Scaler carregados com sucesso.")
except FileNotFoundError:
    print("ERRO: Certifique-se de que os arquivos .joblib (modelos e scaler) estão no diretório correto.")
    exit()

# ----------------------------------------------------------------------
# 2. Novos Dados de Telemetria (Simulação de 3 eventos reais)
# ----------------------------------------------------------------------
new_data = pd.DataFrame({
    # Evento 1: Normal
    'process_id_count': [45],
    'process_cpu_usage': [15.2],
    'disk_io_rate': [25.1],
    'network_connections': [5],
    'file_writes': [2],
    'duration_seconds': [1200],
    
    # Evento 2: Suspeita de Injeção de Processo (T1055)
    'process_id_count': [70],
    'process_cpu_usage': [10.5],
    'disk_io_rate': [95.0],  # Alto I/O de disco
    'network_connections': [1],
    'file_writes': [40],     # Muitas escritas
    'duration_seconds': [80],
    
    # Evento 3: Comportamento Anômalo (Desconhecido)
    'process_id_count': [5],
    'process_cpu_usage': [98.0], # Uso de CPU muito alto
    'disk_io_rate': [5.0],
    'network_connections': [100], # Muitas conexões de rede
    'file_writes': [1],
    'duration_seconds': [10]
})

# ----------------------------------------------------------------------
# 3. Pré-processamento e Previsão
# ----------------------------------------------------------------------

# A. Aplicar a mesma Feature Engineering do treino
data_processed = feature_engineering(new_data)

# B. Aplicar o mesmo Scaler do treino
data_scaled = scaler.transform(data_processed)

# C. Fazer Previsões com os dois modelos
anomaly_pred = iso_forest_model.predict(data_scaled)  # -1 (anomalia) ou 1 (normal)
class_pred = rf_classifier.predict(data_scaled)      # 0 (normal) ou 1, 2, 3... (ataque ATT&CK)

# ----------------------------------------------------------------------
# 4. Avaliação Final (Lógica de Decisão do EDR)
# ----------------------------------------------------------------------
print("\n--- Análise de Detecção EDR ---")
for i in range(len(new_data)):
    print(f"\n[EVENTO {i+1}]")
    
    is_anomaly = anomaly_pred[i] == -1
    attack_label = class_pred[i]
    
    if attack_label != 0:
        # Prioriza a classificação específica do ATT&CK se detectada
        mitre_tactic = MITRE_MAPPING.get(attack_label, "Classificação Desconhecida")
        print(f"**ALERTA DE SEGURANÇA (CLASSIFICADO):** Tática/Técnica: {mitre_tactic}")
        print("Prioridade: ALTA")
    elif is_anomaly:
        # Se não for classificado, mas for anômalo
        print(f"**ALERTA DE ANOMALIA (COMPORTAMENTAL):** {MITRE_MAPPING[-1]}")
        print("Prioridade: ALTA (Requer Investigação Manual)")
    else:
        print(f"Status: {MITRE_MAPPING[0]}")
        print("Prioridade: Baixa")