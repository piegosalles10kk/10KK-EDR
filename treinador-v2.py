import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from pyattck import Attck # Biblioteca para Inteligência de Ameaças
import json 
import sys 
import os 
import requests # Importação necessária para o novo bloco de download

# ----------------------------------------------------------------------
# Configuração de Ambiente
# ----------------------------------------------------------------------
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ----------------------------------------------------------------------
# 1. Mapeamento MITRE ATT&CK (8 Ataques + Normal)
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
    -1: "ANOMALIA - Alto Desvio Comportamental (Zero-Day)"
}
print("Mapeamento ATT&CK carregado e expandido.")

# ----------------------------------------------------------------------
# 2. Geração de Dados Sintéticos 
# ----------------------------------------------------------------------

FEATURES = ['process_id_count', 'process_cpu_usage', 'disk_io_rate', 
            'network_connections', 'file_writes', 'duration_seconds']

def create_attack_data(num_samples, attack_label, base_data):
    """Gera dados sintéticos para um cenário de ataque específico."""
    
    data = pd.concat([base_data] * num_samples, ignore_index=True)

    # Adiciona aleatoriedade (ruído)
    for col in data.columns:
        data[col] = data[col] + np.random.uniform(-0.1, 0.1, num_samples) * base_data[col].values[0]

    # --- Lógica para os 8 Cenários de Ataque (MITRE TTPs) ---
    
    if attack_label == 1: # T1059.001 (Powershell Execution)
        data['process_cpu_usage'] = data['process_cpu_usage'] * np.random.uniform(1.5, 2.5, num_samples)
        data['network_connections'] = data['network_connections'] + np.random.randint(5, 15, num_samples)
    elif attack_label == 2: # T1055 (Process Injection)
        data['disk_io_rate'] = data['disk_io_rate'] * np.random.uniform(2.0, 3.5, num_samples)
        data['file_writes'] = data['file_writes'] * np.random.uniform(1.5, 3.0, num_samples)
    elif attack_label == 3: # T1566 (Phishing/Initial Access)
        data['network_connections'] = data['network_connections'] + np.random.randint(20, 50, num_samples)
        data['duration_seconds'] = data['duration_seconds'] * np.random.uniform(0.5, 1.0, num_samples)
    elif attack_label == 4: # T1003 (Credential Dumping)
        data['network_connections'] = data['network_connections'] * np.random.uniform(0.1, 0.5, num_samples)
        data['disk_io_rate'] = data['disk_io_rate'] * np.random.uniform(3.0, 5.0, num_samples)
    elif attack_label == 5: # T1070.004 (File Deletion)
        data['file_writes'] = data['file_writes'] * np.random.uniform(5.0, 10.0, num_samples)
        data['duration_seconds'] = data['duration_seconds'] * np.random.uniform(0.01, 0.1, num_samples)
    elif attack_label == 6: # T1027 (Obfuscated)
        data['process_cpu_usage'] = data['process_cpu_usage'] * np.random.uniform(2.0, 4.0, num_samples)
        data['process_id_count'] = data['process_id_count'] * np.random.uniform(1.5, 3.0, num_samples)
    elif attack_label == 7: # T1068 (Escalonamento de Privilégios - Vertical)
        data['process_cpu_usage'] = data['process_cpu_usage'] * np.random.uniform(3.0, 6.0, num_samples)
        data['disk_io_rate'] = data['disk_io_rate'] * np.random.uniform(4.0, 7.0, num_samples)
    elif attack_label == 8: # T1021.001 (Movimento Lateral - RDP)
        data['network_connections'] = data['network_connections'] + np.random.randint(50, 100, num_samples)
        data['duration_seconds'] = data['duration_seconds'] * np.random.uniform(0.1, 0.5, num_samples)

    data['target'] = attack_label
    return data[FEATURES + ['target']]

# Dados de base normais
base_normal = pd.DataFrame({
    'process_id_count': [50],
    'process_cpu_usage': [10.0],
    'disk_io_rate': [20.0],
    'network_connections': [10],
    'file_writes': [5],
    'duration_seconds': [600]
})

N_SAMPLES = 1000  
all_data = []

# Gerar dados normais (Rótulo 0)
normal_data = create_attack_data(N_SAMPLES * 5, 0, base_normal) 
all_data.append(normal_data)

# Gerar dados para cada cenário de ataque rotulado (Rótulos 1 a 8)
for label in range(1, len(MITRE_MAPPING) - 1):
    attack_data = create_attack_data(N_SAMPLES, label, base_normal)
    all_data.append(attack_data)

df = pd.concat(all_data, ignore_index=True)
print(f"Dataset sintético gerado. Total de amostras: {len(df)}")
print(f"Distribuição de classes:\n{df['target'].value_counts()}")

# ----------------------------------------------------------------------
# 3. Pré-processamento e Feature Engineering
# ----------------------------------------------------------------------

def feature_engineering(df):
    df['net_conn_per_proc'] = df['network_connections'] / (df['process_id_count'] + 1e-6)
    df['file_write_rate'] = df['file_writes'] / (df['duration_seconds'] + 1e-6)
    return df

df = feature_engineering(df)
X = df.drop('target', axis=1)
y = df['target']
FEATURE_COLUMNS = X.columns 

# Dividir em treino e teste
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
print(f"Conjunto de treinamento: {len(X_train)} amostras.")

# Padronizar os dados (Scaler)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ----------------------------------------------------------------------
# 4. Treinamento do Modelo de CLASSIFICAÇÃO (Random Forest)
# ----------------------------------------------------------------------
print("\n[TREINANDO] Random Forest Classifier (Classificação de Ataque)...")
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
rf_classifier.fit(X_train_scaled, y_train)

y_pred_rf = rf_classifier.predict(X_test_scaled)
accuracy_rf = accuracy_score(y_test, y_pred_rf)

print(f"Acurácia do Random Forest: {accuracy_rf:.4f}")

target_names = [MITRE_MAPPING[i] for i in sorted(y.unique()) if i >= 0]
print("Relatório de Classificação (RF):\n", classification_report(y_test, y_pred_rf, target_names=target_names, zero_division=0))

# ----------------------------------------------------------------------
# 5. Treinamento do Modelo de ANOMALIA (Isolation Forest)
# ----------------------------------------------------------------------
X_train_normal = X_train[y_train == 0]
X_train_normal_scaled = scaler.transform(X_train_normal)

print("\n[TREINANDO] Isolation Forest (Detecção de Anomalias)...")
iso_forest_model = IsolationForest(contamination=0.01, random_state=42) 
iso_forest_model.fit(X_train_normal_scaled)

y_pred_if = iso_forest_model.predict(X_test_scaled)
y_test_anomaly = np.where(y_test != 0, -1, 1) 
anom_accuracy = accuracy_score(y_test_anomaly, y_pred_if)

print(f"Acurácia do Isolation Forest (vs. Ataques): {anom_accuracy:.4f}")

# ----------------------------------------------------------------------
# 6. SALVAR ARTEFATOS E BASE DE TREINAMENTO
# ----------------------------------------------------------------------
print("\n[SALVANDO ARTEFATOS] Modelos, Scaler e Base de Treinamento...")

# Salva a base de dados completa para auditoria
df.to_csv('training_base_edr.csv', index=False)
print("-> Base de treinamento salva como 'training_base_edr.csv'.")

# Salva os modelos e o scaler
joblib.dump(scaler, 'scaler_edr.joblib')
joblib.dump(iso_forest_model, 'model_anomaly_if.joblib')
joblib.dump(rf_classifier, 'model_classifier_rf.joblib')
joblib.dump(FEATURE_COLUMNS, 'feature_columns.joblib') 

# ----------------------------------------------------------------------
# 7. GERAÇÃO DE CONTEXTO DE SEGURANÇA (MITRE ATT&CK) - COM DOWNLOAD FORÇADO
# ----------------------------------------------------------------------

ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
ATTACK_FILE = 'enterprise-attack.json' 

print(f"\n[PREPARANDO CONTEXTO MITRE] Garantindo o download de '{ATTACK_FILE}'...")

try:
    # 1. Tenta excluir o arquivo corrompido, se existir
    if os.path.exists(ATTACK_FILE):
        os.remove(ATTACK_FILE)
        print(f"-> Arquivo existente '{ATTACK_FILE}' excluído para garantir integridade.")

    # 2. Baixa o arquivo de forma limpa e completa
    response = requests.get(ATTACK_URL, stream=True)
    response.raise_for_status() # Lança um erro para códigos de status ruins (4xx ou 5xx)
    
    with open(ATTACK_FILE, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
            
    print(f"-> Download concluído e salvo como '{ATTACK_FILE}'. Tamanho: {os.path.getsize(ATTACK_FILE) / (1024 * 1024):.2f} MB.")
    
    
    # 3. Carrega o JSON do arquivo local
    with open(ATTACK_FILE, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)
    
    # Inicializa o Attck passando os dados STIX diretamente
    attack = Attck(stix_data) 
    
    mitre_context = {}
    attack_labels = {k: v for k, v in MITRE_MAPPING.items() if k > 0} 

    for label_id, label_name in attack_labels.items():
        technique_id = label_name.split(' - ')[0] 
        tech = attack.enterprise.get_technique(technique_id)
        
        if tech:
            context = {
                'id': tech.id,
                'name': tech.name,
                'description': tech.description.strip() if tech.description else "N/A",
                'platforms': [p.name for p in tech.platforms] if tech.platforms else [],
                'groups_using': [g.name for g in tech.groups] if tech.groups else [],
                'tactic': [t.name for t in tech.tactics] if tech.tactics else []
            }
            mitre_context[str(label_id)] = context
        else:
            mitre_context[str(label_id)] = {'error': f'Technique {technique_id} not found in pyattck data.'}
            
    # Salva o dicionário de contexto em um arquivo JSON
    with open('mitre_context.json', 'w', encoding='utf-8') as f:
        json.dump(mitre_context, f, indent=4, ensure_ascii=False)

    print("-> Arquivo 'mitre_context.json' (Contexto de Segurança) salvo com sucesso, usando base recém-baixada.")

except requests.exceptions.RequestException as e:
    # Captura erros de rede/HTTP durante o download
    print(f"\nERRO CRÍTICO (Rede): Falha ao baixar o arquivo MITRE ATT&CK. Verifique sua conexão ou proxy. Detalhe: {e}")
except json.JSONDecodeError as e:
    # Captura o erro de parsing (que é o que estávamos vendo, mas agora ele só deve ocorrer se o download falhar silenciosamente)
    print(f"\nERRO CRÍTICO (JSON Corrompido): O arquivo '{ATTACK_FILE}' está corrompido mesmo após o download. Detalhe: {e}")
except Exception as e:
    # Captura outros erros, incluindo problemas de inicialização do Attck
    print(f"\nERRO CRÍTICO FINAL: Falha ao processar o contexto MITRE. Detalhe: {e}")


print("\n--- FIM DO TREINADOR ---\nTodos os artefatos de ML (modelos, scaler e base) foram salvos com sucesso.")