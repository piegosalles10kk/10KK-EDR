"""
Test Suite para EDR Avançado v3.0
Valida todos os componentes do sistema antes do deploy em produção
"""

import pandas as pd
import numpy as np
import joblib
import os
import sys
from datetime import datetime

# Configuração
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*70}")
    print(f"{text}")
    print(f"{'='*70}{Colors.END}\n")

def print_test(name, passed, message=""):
    status = f"{Colors.GREEN}✓ PASSOU{Colors.END}" if passed else f"{Colors.RED}✗ FALHOU{Colors.END}"
    print(f"[{status}] {name}")
    if message and not passed:
        print(f"    → {Colors.YELLOW}{message}{Colors.END}")

def advanced_feature_engineering(df):
    """Mesma função do sistema principal."""
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

# ===================================================================
# TESTES
# ===================================================================

print_header("EDR AVANÇADO v3.0 - SUITE DE TESTES")
print(f"Iniciado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

total_tests = 0
passed_tests = 0

# -------------------------------------------------------------------
# TESTE 1: Verificar Arquivos de Modelo
# -------------------------------------------------------------------
print_header("TESTE 1: Integridade dos Arquivos")

required_files = {
    'scaler_edr_v3.joblib': 'Scaler (normalizador)',
    'model_ensemble_v3.joblib': 'Modelo Ensemble',
    'model_anomaly_v3.joblib': 'Detector de Anomalias',
    'feature_columns_v3.joblib': 'Colunas de Features',
    'mitre_mapping_v3.joblib': 'Mapeamento MITRE ATT&CK'
}

for filename, description in required_files.items():
    total_tests += 1
    exists = os.path.exists(filename)
    print_test(
        f"{description} ({filename})",
        exists,
        f"Arquivo não encontrado. Execute: python treinador-v3-avancado.py"
    )
    if exists:
        passed_tests += 1

# -------------------------------------------------------------------
# TESTE 2: Carregar Modelos
# -------------------------------------------------------------------
print_header("TESTE 2: Carregamento dos Modelos")

models_loaded = True
try:
    scaler = joblib.load('scaler_edr_v3.joblib')
    ensemble_model = joblib.load('model_ensemble_v3.joblib')
    anomaly_model = joblib.load('model_anomaly_v3.joblib')
    feature_columns = joblib.load('feature_columns_v3.joblib')
    mitre_mapping = joblib.load('mitre_mapping_v3.joblib')
    
    total_tests += 5
    passed_tests += 5
    
    print_test("Scaler carregado", True)
    print_test("Ensemble carregado", True)
    print_test("Anomaly Detector carregado", True)
    print_test("Feature Columns carregadas", True)
    print_test("MITRE Mapping carregado", True)
    
except Exception as e:
    models_loaded = False
    total_tests += 5
    print_test("Carregar modelos", False, str(e))

# -------------------------------------------------------------------
# TESTE 3: Validar Estrutura dos Modelos
# -------------------------------------------------------------------
if models_loaded:
    print_header("TESTE 3: Validação da Estrutura")
    
    # Teste 3.1: Número de features
    total_tests += 1
    expected_features = 19  # 12 base + 7 derivadas
    actual_features = len(feature_columns)
    test_passed = actual_features == expected_features
    print_test(
        f"Número de features (esperado: {expected_features}, atual: {actual_features})",
        test_passed,
        f"Features esperadas: {expected_features}, encontradas: {actual_features}"
    )
    if test_passed:
        passed_tests += 1
    
    # Teste 3.2: Técnicas MITRE
    total_tests += 1
    expected_techniques = 17  # 15 ataques + normal + anomalia
    actual_techniques = len(mitre_mapping)
    test_passed = actual_techniques == expected_techniques
    print_test(
        f"Técnicas MITRE (esperado: {expected_techniques}, atual: {actual_techniques})",
        test_passed,
        f"Técnicas esperadas: {expected_techniques}, encontradas: {actual_techniques}"
    )
    if test_passed:
        passed_tests += 1
    
    # Teste 3.3: Tipo do Ensemble
    total_tests += 1
    try:
        has_estimators = hasattr(ensemble_model, 'estimators_')
        print_test(
            f"Ensemble possui múltiplos estimadores",
            has_estimators,
            "Modelo não é um ensemble válido"
        )
        if has_estimators:
            passed_tests += 1
            print(f"    → Estimadores: {len(ensemble_model.estimators_)}")
    except Exception as e:
        print_test("Verificar tipo do Ensemble", False, str(e))

# -------------------------------------------------------------------
# TESTE 4: Predições com Dados Sintéticos
# -------------------------------------------------------------------
if models_loaded:
    print_header("TESTE 4: Predições em Dados de Teste")
    
    # Criar dados de teste
    test_normal = pd.DataFrame({
        'process_id_count': [50],
        'process_cpu_usage': [15.0],
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
    
    test_attack = pd.DataFrame({
        'process_id_count': [70],
        'process_cpu_usage': [85.0],
        'disk_io_rate': [200.0],
        'network_connections': [150],
        'file_writes': [100],
        'duration_seconds': [30],
        'memory_usage_mb': [2000],
        'thread_count': [80],
        'registry_modifications': [50],
        'dns_queries': [200],
        'suspicious_ports': [15],
        'parent_process_anomaly': [0.9]
    })
    
    try:
        # Teste 4.1: Processar dados normais
        total_tests += 1
        test_normal_proc = advanced_feature_engineering(test_normal.copy())
        test_normal_scaled = scaler.transform(test_normal_proc)
        pred_normal = ensemble_model.predict(test_normal_scaled)[0]
        
        test_passed = pred_normal == 0
        print_test(
            f"Evento NORMAL classificado corretamente (predição: {mitre_mapping.get(pred_normal, 'Desconhecido')})",
            test_passed,
            f"Esperado: Normal (0), Obtido: {pred_normal}"
        )
        if test_passed:
            passed_tests += 1
        
        # Teste 4.2: Processar dados de ataque
        total_tests += 1
        test_attack_proc = advanced_feature_engineering(test_attack.copy())
        test_attack_scaled = scaler.transform(test_attack_proc)
        pred_attack = ensemble_model.predict(test_attack_scaled)[0]
        
        test_passed = pred_attack != 0
        print_test(
            f"Evento MALICIOSO detectado (predição: {mitre_mapping.get(pred_attack, 'Desconhecido')})",
            test_passed,
            f"Esperado: != 0, Obtido: {pred_attack}"
        )
        if test_passed:
            passed_tests += 1
        
        # Teste 4.3: Detector de anomalias
        total_tests += 1
        anom_pred_normal = anomaly_model.predict(test_normal_scaled)[0]
        test_passed = anom_pred_normal == 1  # 1 = normal, -1 = anomalia
        print_test(
            f"Anomaly Detector classifica normal corretamente (predição: {anom_pred_normal})",
            test_passed,
            f"Esperado: 1 (normal), Obtido: {anom_pred_normal}"
        )
        if test_passed:
            passed_tests += 1
        
        total_tests += 1
        anom_pred_attack = anomaly_model.predict(test_attack_scaled)[0]
        test_passed = anom_pred_attack == -1  # -1 = anomalia
        print_test(
            f"Anomaly Detector detecta anomalia (predição: {anom_pred_attack})",
            test_passed,
            f"Esperado: -1 (anomalia), Obtido: {anom_pred_attack}"
        )
        if test_passed:
            passed_tests += 1
            
    except Exception as e:
        total_tests += 4
        print_test("Realizar predições", False, str(e))

# -------------------------------------------------------------------
# TESTE 5: Validar Probabilidades
# -------------------------------------------------------------------
if models_loaded:
    print_header("TESTE 5: Probabilidades e Confiança")
    
    try:
        total_tests += 1
        proba_normal = ensemble_model.predict_proba(test_normal_scaled)[0]
        confidence_normal = proba_normal.max()
        
        test_passed = 0.5 <= confidence_normal <= 1.0
        print_test(
            f"Confiança em dados normais ({confidence_normal:.2%})",
            test_passed,
            f"Confiança fora do esperado: {confidence_normal:.2%}"
        )
        if test_passed:
            passed_tests += 1
        
        total_tests += 1
        proba_attack = ensemble_model.predict_proba(test_attack_scaled)[0]
        confidence_attack = proba_attack.max()
        
        test_passed = 0.5 <= confidence_attack <= 1.0
        print_test(
            f"Confiança em dados maliciosos ({confidence_attack:.2%})",
            test_passed,
            f"Confiança fora do esperado: {confidence_attack:.2%}"
        )
        if test_passed:
            passed_tests += 1
            
    except Exception as e:
        total_tests += 2
        print_test("Validar probabilidades", False, str(e))

# -------------------------------------------------------------------
# TESTE 6: Feature Engineering
# -------------------------------------------------------------------
if models_loaded:
    print_header("TESTE 6: Feature Engineering")
    
    try:
        # Teste 6.1: Features derivadas criadas
        total_tests += 1
        test_df = pd.DataFrame({
            'process_id_count': [50],
            'process_cpu_usage': [20.0],
            'disk_io_rate': [30.0],
            'network_connections': [10],
            'file_writes': [5],
            'duration_seconds': [100],
            'memory_usage_mb': [500],
            'thread_count': [20],
            'registry_modifications': [2],
            'dns_queries': [15],
            'suspicious_ports': [1],
            'parent_process_anomaly': [0.1]
        })
        
        result_df = advanced_feature_engineering(test_df.copy())
        
        expected_derived = [
            'net_conn_per_proc', 'file_write_rate', 'cpu_per_thread',
            'io_intensity', 'network_intensity', 'anomaly_score', 'resource_pressure'
        ]
        
        all_present = all(col in result_df.columns for col in expected_derived)
        print_test(
            f"Todas as features derivadas criadas ({len(expected_derived)} features)",
            all_present,
            f"Features faltando: {[c for c in expected_derived if c not in result_df.columns]}"
        )
        if all_present:
            passed_tests += 1
        
        # Teste 6.2: Valores sem NaN ou Inf
        total_tests += 1
        has_invalid = result_df.isnull().any().any() or np.isinf(result_df.select_dtypes(include=[np.number])).any().any()
        print_test(
            "Features sem valores NaN ou Infinito",
            not has_invalid,
            "Encontrados valores NaN ou Infinito nas features"
        )
        if not has_invalid:
            passed_tests += 1
            
    except Exception as e:
        total_tests += 2
        print_test("Feature Engineering", False, str(e))

# -------------------------------------------------------------------
# TESTE 7: Performance e Tempo de Resposta
# -------------------------------------------------------------------
if models_loaded:
    print_header("TESTE 7: Performance e Latência")
    
    try:
        import time
        
        # Teste 7.1: Tempo de predição individual
        total_tests += 1
        start_time = time.time()
        _ = ensemble_model.predict(test_normal_scaled)
        prediction_time = time.time() - start_time
        
        max_acceptable_time = 0.1  # 100ms
        test_passed = prediction_time < max_acceptable_time
        print_test(
            f"Tempo de predição individual ({prediction_time*1000:.2f}ms)",
            test_passed,
            f"Tempo muito alto: {prediction_time*1000:.2f}ms > {max_acceptable_time*1000}ms"
        )
        if test_passed:
            passed_tests += 1
        
        # Teste 7.2: Throughput em lote
        total_tests += 1
        batch_size = 100
        batch_data = pd.concat([test_normal] * batch_size, ignore_index=True)
        batch_processed = advanced_feature_engineering(batch_data)
        batch_scaled = scaler.transform(batch_processed)
        
        start_time = time.time()
        _ = ensemble_model.predict(batch_scaled)
        batch_time = time.time() - start_time
        events_per_second = batch_size / batch_time
        
        min_throughput = 500  # eventos/segundo
        test_passed = events_per_second > min_throughput
        print_test(
            f"Throughput em lote ({events_per_second:.0f} eventos/segundo)",
            test_passed,
            f"Throughput baixo: {events_per_second:.0f} < {min_throughput}"
        )
        if test_passed:
            passed_tests += 1
            
    except Exception as e:
        total_tests += 2
        print_test("Testes de performance", False, str(e))

# -------------------------------------------------------------------
# TESTE 8: Robustez com Dados Extremos
# -------------------------------------------------------------------
if models_loaded:
    print_header("TESTE 8: Robustez e Casos Extremos")
    
    try:
        # Teste 8.1: Valores zeros
        total_tests += 1
        test_zeros = pd.DataFrame({
            'process_id_count': [0],
            'process_cpu_usage': [0],
            'disk_io_rate': [0],
            'network_connections': [0],
            'file_writes': [0],
            'duration_seconds': [1],  # Evitar divisão por zero
            'memory_usage_mb': [0],
            'thread_count': [1],  # Evitar divisão por zero
            'registry_modifications': [0],
            'dns_queries': [0],
            'suspicious_ports': [0],
            'parent_process_anomaly': [0]
        })
        
        test_zeros_proc = advanced_feature_engineering(test_zeros.copy())
        test_zeros_scaled = scaler.transform(test_zeros_proc)
        pred_zeros = ensemble_model.predict(test_zeros_scaled)
        
        test_passed = True  # Se não crashou, passou
        print_test(
            "Processamento de valores zeros",
            test_passed
        )
        passed_tests += 1
        
        # Teste 8.2: Valores extremamente altos
        total_tests += 1
        test_extreme = pd.DataFrame({
            'process_id_count': [10000],
            'process_cpu_usage': [100],
            'disk_io_rate': [10000],
            'network_connections': [10000],
            'file_writes': [10000],
            'duration_seconds': [10000],
            'memory_usage_mb': [100000],
            'thread_count': [10000],
            'registry_modifications': [10000],
            'dns_queries': [10000],
            'suspicious_ports': [1000],
            'parent_process_anomaly': [1.0]
        })
        
        test_extreme_proc = advanced_feature_engineering(test_extreme.copy())
        test_extreme_scaled = scaler.transform(test_extreme_proc)
        pred_extreme = ensemble_model.predict(test_extreme_scaled)
        
        test_passed = True
        print_test(
            "Processamento de valores extremos",
            test_passed
        )
        passed_tests += 1
        
    except Exception as e:
        total_tests += 2
        print_test("Robustez com dados extremos", False, str(e))

# -------------------------------------------------------------------
# RELATÓRIO FINAL
# -------------------------------------------------------------------
print_header("RELATÓRIO FINAL DOS TESTES")

success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

print(f"Total de Testes: {total_tests}")
print(f"Testes Passados: {Colors.GREEN}{passed_tests}{Colors.END}")
print(f"Testes Falhados: {Colors.RED}{total_tests - passed_tests}{Colors.END}")
print(f"Taxa de Sucesso: {Colors.GREEN if success_rate >= 90 else Colors.YELLOW}{success_rate:.1f}%{Colors.END}\n")

if success_rate >= 95:
    print(f"{Colors.GREEN}✓ SISTEMA PRONTO PARA PRODUÇÃO{Colors.END}")
    print("  Todos os testes críticos passaram com sucesso.")
    print("  O EDR pode ser deployado com confiança.\n")
    exit_code = 0
elif success_rate >= 80:
    print(f"{Colors.YELLOW}⚠ SISTEMA FUNCIONAL COM RESSALVAS{Colors.END}")
    print("  A maioria dos testes passou, mas existem problemas menores.")
    print("  Revisar testes falhados antes do deploy em produção.\n")
    exit_code = 0
else:
    print(f"{Colors.RED}✗ SISTEMA NÃO ESTÁ PRONTO{Colors.END}")
    print("  Muitos testes falharam. Não deploy em produção.")
    print("  Revisar erros e retreinar o sistema.\n")
    exit_code = 1

print(f"Finalizado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*70)

sys.exit(exit_code)