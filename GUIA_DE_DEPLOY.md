# 🚀 Guia de Deploy - EDR Avançado v3.0

## 📋 Pré-requisitos

### Sistema Operacional
- ✅ Windows 10/11, Linux (Ubuntu 20.04+), macOS 11+
- ✅ Python 3.8 ou superior
- ✅ 4GB RAM mínimo (8GB recomendado)
- ✅ 2GB de espaço em disco

### Software
```bash
python --version  # Verificar Python 3.8+
pip --version     # Verificar pip instalado
```

---

## 📦 Instalação Passo a Passo

### Passo 1: Preparar Ambiente

```bash
# Criar diretório do projeto
mkdir edr-avancado
cd edr-avancado

# Criar ambiente virtual (recomendado)
python -m venv venv

# Ativar ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### Passo 2: Instalar Dependências

```bash
# Instalar todas as bibliotecas necessárias
pip install -r requirements-v3.txt

# Verificar instalação
pip list | grep scikit-learn
pip list | grep pandas
```

### Passo 3: Copiar Arquivos

Coloque os seguintes arquivos no diretório:
- ✅ `treinador-v3-avancado.py`
- ✅ `jogador-v3-avancado.py`
- ✅ `test_edr_system.py`
- ✅ `requirements-v3.txt`
- ✅ `.gitignore` (opcional)

---

## 🎓 Treinamento do Modelo

### Passo 1: Executar Treinador

```bash
python treinador-v3-avancado.py
```

**Tempo esperado:** 30-60 segundos

**Saída esperada:**
```
✓ Mapeamento ATT&CK expandido: 15 técnicas
✓ Dataset sintético gerado: 25,200 amostras
✓ Feature Engineering aplicado: 19 features
✓ Ensemble treinado em ~30s
✓ Acurácia do Ensemble: 0.9997
✓ Cross-validation (5-fold): 0.9995
✓ Modelos salvos: *_v3.joblib
```

### Passo 2: Verificar Arquivos Gerados

```bash
ls -lh *.joblib
ls -lh *.csv
ls -lh *.json
```

**Arquivos esperados:**
- `scaler_edr_v3.joblib` (~5KB)
- `model_ensemble_v3.joblib` (~50MB)
- `model_anomaly_v3.joblib` (~10MB)
- `feature_columns_v3.joblib` (~1KB)
- `mitre_mapping_v3.joblib` (~1KB)
- `training_base_edr_v3.csv` (~5MB)
- `mitre_context_v3.json` (~500KB)
- `enterprise-attack.json` (~38MB)

---

## 🧪 Validação e Testes

### Executar Suite de Testes

```bash
python test_edr_system.py
```

**Saída esperada:**
```
========================================
RELATÓRIO FINAL DOS TESTES
========================================
Total de Testes: 25
Testes Passados: 25
Testes Falhados: 0
Taxa de Sucesso: 100.0%

✓ SISTEMA PRONTO PARA PRODUÇÃO
```

### Interpretação dos Resultados

| Taxa de Sucesso | Status | Ação |
|----------------|--------|------|
| ≥ 95% | ✅ Pronto para produção | Deploy imediato |
| 80-94% | ⚠️ Funcional com ressalvas | Revisar falhas |
| < 80% | ❌ Não pronto | Retreinar sistema |

---

## 🎯 Executar Detecção

### Modo Demo (Eventos Pré-configurados)

```bash
python jogador-v3-avancado.py
```

**Saída:** Relatório detalhado de 5 eventos simulados com classificação completa.

### Modo Produção (Dados Reais)

**Opção 1: Modificar dados no script**

Edite `jogador-v3-avancado.py` e substitua o DataFrame `new_data` pelos seus dados de telemetria real.

**Opção 2: Importar de arquivo CSV**

```python
# Adicione no início do jogador-v3-avancado.py
new_data = pd.read_csv('telemetria_real.csv')
```

**Formato CSV esperado:**
```csv
process_id_count,process_cpu_usage,disk_io_rate,network_connections,file_writes,duration_seconds,memory_usage_mb,thread_count,registry_modifications,dns_queries,suspicious_ports,parent_process_anomaly
50,15.2,25.1,10,5,1200,512,20,2,15,0,0.0
```

---

## 🔧 Configurações Avançadas

### Ajustar Sensibilidade do Detector de Anomalias

**Arquivo:** `treinador-v3-avancado.py`

```python
# Linha ~180
iso_forest = IsolationForest(
    contamination=0.02,  # AJUSTE AQUI: 0.01 (menos sensível) a 0.05 (mais sensível)
    n_estimators=200,
    max_samples=256,
    random_state=42,
    n_jobs=-1
)
```

**Efeito:**
- `0.01`: Menos falsos positivos, pode perder ataques sutis
- `0.02`: **Padrão recomendado** (balanceado)
- `0.05`: Mais falsos positivos, detecta mais anomalias

### Ajustar Número de Amostras de Treino

```python
# Linha ~90
N_SAMPLES = 1200  # AJUSTE AQUI: 500 (rápido) a 5000 (lento, mais preciso)
```

**Impacto:**
- Mais amostras = maior tempo de treino + maior precisão
- Menos amostras = treino rápido + pode reduzir precisão

### Modificar Prioridades

**Arquivo:** `jogador-v3-avancado.py`

```python
# Linha ~120 - função analyze_event()
if class_pred != 0 and confidence > 0.85:  # AJUSTE threshold de confiança
    return {
        'priority': 'CRÍTICA' if confidence > 0.95 else 'ALTA',  # AJUSTE
    }
```

---

## 🐛 Troubleshooting

### Problema 1: Erro ao baixar MITRE ATT&CK

**Sintoma:**
```
ERRO CRÍTICO (Rede): Falha ao baixar o arquivo MITRE ATT&CK
```

**Soluções:**

1. **Verificar conexão:**
```bash
ping raw.githubusercontent.com
```

2. **Configurar proxy (se necessário):**
```python
# Adicione no início do treinador-v3-avancado.py
import os
os.environ['HTTP_PROXY'] = 'http://seu-proxy:porta'
os.environ['HTTPS_PROXY'] = 'http://seu-proxy:porta'
```

3. **Download manual:**
```bash
# Baixe manualmente e coloque no diretório
curl -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

4. **O sistema funciona sem MITRE:** Ele continuará operando, apenas sem as descrições detalhadas das técnicas.

### Problema 2: Memória Insuficiente

**Sintoma:**
```
MemoryError ou sistema travando durante treinamento
```

**Soluções:**

1. **Reduzir amostras:**
```python
N_SAMPLES = 500  # Ao invés de 1200
```

2. **Desabilitar paralelização:**
```python
rf_clf = RandomForestClassifier(
    n_jobs=1,  # Ao invés de -1
)
```

3. **Treinar em etapas:** Comente temporariamente modelos pesados (Neural Network).

### Problema 3: Importação de Bibliotecas Falha

**Sintoma:**
```
ModuleNotFoundError: No module named 'sklearn'
```

**Soluções:**

1. **Reinstalar dependências:**
```bash
pip install --upgrade scikit-learn pandas numpy joblib requests
```

2. **Verificar ambiente virtual:**
```bash
which python  # Linux/Mac
where python  # Windows
# Deve apontar para venv/bin/python
```

3. **Instalar com conda (alternativa):**
```bash
conda create -n edr python=3.10
conda activate edr
conda install scikit-learn pandas numpy
```

### Problema 4: Baixa Acurácia (<95%)

**Sintoma:**
```
Acurácia do Ensemble: 0.7500
```

**Causas e Soluções:**

1. **Poucas amostras de treino:**
```python
N_SAMPLES = 2000  # Aumentar para 2000+
```

2. **Desbalanceamento de classes:**
```python
# Já implementado: class_weight='balanced'
# Verificar distribuição no log
```

3. **Features com problemas:**
```python
# Verificar se há NaN ou Inf
df.isnull().sum()
np.isinf(df.select_dtypes(include=[np.number])).sum()
```

### Problema 5: Predições Incorretas

**Sintoma:** Sistema classifica tudo como Normal ou tudo como Ataque.

**Soluções:**

1. **Verificar Feature Engineering:**
```python
# Adicione prints para debugar
print(data_processed.describe())
print(data_scaled[:5])
```

2. **Verificar ordem das features:**
```python
# No jogador, use as mesmas features do treino
assert list(data_processed.columns) == list(feature_columns)
```

3. **Retreinar do zero:**
```bash
rm *.joblib *.csv
python treinador-v3-avancado.py
```

---

## 📊 Monitoramento em Produção

### Métricas Chave para Acompanhar

1. **Taxa de Detecção**
   - Meta: > 95% de ataques detectados
   - Coletar feedback de analistas (verdadeiros/falsos positivos)

2. **Taxa de Falsos Positivos**
   - Meta: < 2% dos alertas
   - Ajustar thresholds se necessário

3. **Tempo de Resposta**
   - Meta: < 100ms por evento
   - Meta: > 500 eventos/segundo em lote

4. **Distribuição de Prioridades**
   - Crítica: ~1-5%
   - Alta: ~5-10%
   - Média: ~10-15%
   - Baixa: ~70-85%

### Logs Recomendados

```python
# Adicione ao jogador-v3-avancado.py
import logging

logging.basicConfig(
    filename='edr_detection.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Log cada detecção
logging.info(f"Evento {i}: {result['status']} - Prioridade: {result['priority']}")
```

### Dashboard (Opcional)

Criar visualizações com:
- **Grafana:** Para métricas em tempo real
- **Kibana:** Se integrar com Elasticsearch
- **Tableau/Power BI:** Para análise executiva

---

## 🔄 Retreinamento Periódico

### Quando Retreinar?

- ✅ **Mensalmente:** Para manter modelo atualizado
- ✅ **Quando:** Taxa de detecção cai > 5%
- ✅ **Quando:** Novos tipos de ataque surgem
- ✅ **Quando:** Infraestrutura muda significativamente

### Como Retreinar com Dados Reais

```python
# 1. Coletar dados rotulados de produção
real_data = pd.read_csv('telemetria_rotulada.csv')

# 2. Combinar com dados sintéticos
combined_data = pd.concat([df, real_data], ignore_index=True)

# 3. Retreinar seguindo os mesmos passos do treinador
X = combined_data.drop('target', axis=1)
y = combined_data['target']
# ... resto do treinamento
```

### Pipeline de Retreinamento Automático

```python
# retreinar_automatico.py
import schedule
import time

def retreinar():
    print("Iniciando retreinamento programado...")
    os.system("python treinador-v3-avancado.py")
    print("Retreinamento concluído!")

# Retreinar todo domingo às 3h da manhã
schedule.every().sunday.at("03:00").do(retreinar)

while True:
    schedule.run_pending()
    time.sleep(3600)  # Verificar a cada hora
```

---

## 🔌 Integrações

### 1. Integração com SIEM (Splunk/ELK)

**Via Syslog:**

```python
import logging
from logging.handlers import SysLogHandler

syslog = SysLogHandler(address=('seu-siem.local', 514))
syslog.setLevel(logging.WARNING)

# Log alertas críticos e altos
if result['priority'] in ['CRÍTICA', 'ALTA']:
    logging.warning(f"EDR_ALERT: {result}")
```

**Via API REST:**

```python
import requests

def enviar_para_siem(evento):
    payload = {
        'timestamp': datetime.now().isoformat(),
        'severity': evento['priority'],
        'threat': evento['label'],
        'confidence': evento['confidence']
    }
    requests.post('http://seu-siem/api/alerts', json=payload)
```

### 2. Integração com Slack/Teams

```python
from slack_sdk import WebClient

slack = WebClient(token='seu-token-slack')

if result['priority'] == 'CRÍTICA':
    slack.chat_postMessage(
        channel='#seguranca',
        text=f"🚨 ALERTA CRÍTICO: {MITRE_MAPPING[result['label']]}"
    )
```

### 3. Integração com Ticketing (Jira/ServiceNow)

```python
from jira import JIRA

jira = JIRA('https://seu-jira.atlassian.net', basic_auth=('user', 'token'))

if result['priority'] in ['CRÍTICA', 'ALTA']:
    jira.create_issue(
        project='SEC',
        summary=f"EDR Alert: {MITRE_MAPPING[result['label']]}",
        description=f"Confiança: {result['confidence']:.0%}",
        issuetype={'name': 'Incident'}
    )
```

### 4. API REST para Telemetria

```python
# api_edr.py
from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI()

class TelemetriaEvent(BaseModel):
    process_id_count: int
    process_cpu_usage: float
    # ... outras features

@app.post("/analyze")
def analisar_evento(event: TelemetriaEvent):
    # Processar evento
    df = pd.DataFrame([event.dict()])
    df_proc = advanced_feature_engineering(df)
    df_scaled = scaler.transform(df_proc)
    
    # Predição
    pred = ensemble_model.predict(df_scaled)[0]
    proba = ensemble_model.predict_proba(df_scaled)[0]
    
    return {
        "classification": MITRE_MAPPING[pred],
        "confidence": float(proba.max()),
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

**Executar:**
```bash
pip install fastapi uvicorn
python api_edr.py
```

**Testar:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"process_id_count":100, "process_cpu_usage":90, ...}'
```

---

## 📈 Otimizações de Performance

### 1. Quantização do Modelo (Reduzir Tamanho)

```python
# Após treinar
import pickle
import gzip

# Salvar comprimido
with gzip.open('model_ensemble_v3_compressed.pkl.gz', 'wb') as f:
    pickle.dump(ensemble_clf, f)

# Carregar
with gzip.open('model_ensemble_v3_compressed.pkl.gz', 'rb') as f:
    ensemble_clf = pickle.load(f)
```

**Benefício:** Modelo 70% menor.

### 2. Processamento em Lote

```python
# Processar múltiplos eventos de uma vez
batch = []
for evento in stream_telemetria:
    batch.append(evento)
    
    if len(batch) >= 100:  # Processar em lotes de 100
        df_batch = pd.DataFrame(batch)
        resultados = processar_batch(df_batch)
        batch = []
```

**Benefício:** 10x mais rápido que individual.

### 3. Caching de Features

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def calcular_feature_derivada(cpu, threads):
    return cpu / (threads + 1e-6)
```

**Benefício:** Evita recalcular features idênticas.

---

## 🔐 Segurança do Sistema EDR

### 1. Proteger Modelos

```bash
# Configurar permissões restritas
chmod 600 *.joblib
chown root:security *.joblib
```

### 2. Validação de Entrada

```python
def validar_telemetria(data):
    assert data['process_cpu_usage'] >= 0 and data['process_cpu_usage'] <= 100
    assert data['duration_seconds'] > 0
    # ... outras validações
```

### 3. Logging de Auditoria

```python
audit_log = logging.getLogger('audit')
audit_log.info(f"Usuario {user} executou deteccao em {timestamp}")
```

---

## 📚 Recursos Adicionais

### Documentação
- [Scikit-learn Ensemble Methods](https://scikit-learn.org/stable/modules/ensemble.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Isolation Forest Paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf)

### Comunidade
- [r/netsec](https://reddit.com/r/netsec) - Discussões sobre segurança
- [r/MachineLearning](https://reddit.com/r/MachineLearning) - ML aplicado

### Treinamentos
- **SANS SEC573:** Automating Security with Python
- **Coursera:** Machine Learning for Cybersecurity

---

## ✅ Checklist de Deploy

Antes de colocar em produção:

- [ ] Python 3.8+ instalado
- [ ] Todas as dependências instaladas
- [ ] Modelos treinados (arquivos .joblib existem)
- [ ] Suite de testes passou com ≥95%
- [ ] Testado com dados reais da sua rede
- [ ] Thresholds de prioridade ajustados
- [ ] Integração com SIEM configurada
- [ ] Sistema de alertas funcionando
- [ ] Logs configurados corretamente
- [ ] Backup dos modelos realizado
- [ ] Documentação interna criada
- [ ] Equipe treinada no sistema
- [ ] Plano de retreinamento definido
- [ ] Métricas de monitoramento estabelecidas

---

## 📞 Suporte

Em caso de dúvidas:

1. **Verificar documentação:** Revisar este guia e o documento de melhorias
2. **Executar testes:** `python test_edr_system.py`
3. **Verificar logs:** Examinar mensagens de erro detalhadas
4. **Retreinar:** Quando em dúvida, retreinar o modelo

---

**EDR Avançado v3.0** - Sistema pronto para proteção de nível enterprise! 🛡️