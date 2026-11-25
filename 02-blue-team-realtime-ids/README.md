# 🔵 Módulo 02 — Blue Team: IDS com Machine Learning em Tempo Real

Este módulo implementa a resposta defensiva ao polimorfismo: um **Sistema de Detecção de Intrusões (IDS)** baseado em **Machine Learning (`RandomForestClassifier`)** capaz de detectar as variantes polimórficas que passaram despercebidas pelo antivírus tradicional.

---

## 📐 Fundamentos Técnicos Utilizados

### 1. Entropia de Shannon ($H(X)$)
Na Teoria da Informação, a **Entropia de Shannon** mede o grau de incerteza ou aleatoriedade dos bytes de um arquivo, variando de `0.0` (arquivo totalmente repetitivo) até `8.0` bits/byte (distribuição perfeitamente uniforme de todos os 256 valores possíveis de byte):

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

- **Código-fonte comum / texto legível:** geralmente entre **3.8 e 4.9 bits/byte** (muitas palavras repetidas, espaços e sintaxe previsível).
- **Artefatos polimórficos, criptografados ou empacotados:** sobem tipicamente para **5.7 a 7.9 bits/byte**, pois chaves XOR, Base85/Base64 e compressão destroem a redundância natural do código.

> ⚠️ **Por que a entropia sozinha não basta?**
> Arquivos perfeitamente legítimos — como instaladores compactados (`.zip`, `.pkg`), vídeos ou binários empacotados comercialmente — também possuem alta entropia! Se um IDS bloqueasse tudo que tem entropia alta, causaria uma enxurrada de **falsos positivos**. Por isso, combinamos entropia com **heurística** e **telemetria comportamental**.

---

### 2. Análise Heurística Estática + Telemetria Comportamental (EDR/NDR)

O modelo avalia **6 sinais complementares** simultaneamente:

| Feature | Origem na Demo | O que revela |
| :--- | :--- | :--- |
| `file_entropy` | **Calculada em tempo real dos arquivos gerados** | Presença de criptografia, compressão ou empacotamento |
| `obfuscation_score` | **Calculada em tempo real do código gerado** | Rotinas de decodificação (`b85decode`, `zlib`, XOR) e variáveis aleatórias |
| `process_spawn_rate` | Telemetria simulada de SO (EDR) | Criação anômala de subprocessos encadeados |
| `suspicious_api_calls` | Telemetria simulada de SO (EDR) | Invocação atípica de APIs sensíveis de memória/execução |
| `anomalous_net_connections` | Telemetria simulada de Rede (NDR) | Comunicação com destinos ou portas fora da linha de base |
| `cpu_burst_ratio` | Telemetria simulada de SO (EDR) | Picos curtos de CPU típicos da rotina de desempacotamento |

---

### 3. Por que `RandomForestClassifier`?

Em ambientes reais de segurança (SOC/EDR), modelos baseados em árvores (*Random Forest*, *XGBoost*, *LightGBM*) são amplamente adotados para telemetria tabular porque:
1. **Inferência ultrarrápida (milissegundos):** viável para detecção em tempo real sem travar o endpoint;
2. **Não exige escalonamento pesado:** lida naturalmente com escalas distintas (entropia `0–8` vs. contagem de APIs `0–50`);
3. **Explicabilidade (XAI):** permite mostrar ao analista do SOC **exatamente quais features** dispararam o alerta, evitando decisões cegas em "caixa-preta".

---

## ▶️ Como Executar Este Módulo

Certifique-se de ter executado o **Módulo 01** antes (para criar as 5 variantes reais em `01-red-team-polymorphic/generated_variants/`):

```bash
# 1. (Opcional) Gera e inspeciona o dataset sintético de telemetria
python3 02-blue-team-realtime-ids/generate_telemetry_data.py

# 2. Treina o RandomForest e inicia o monitoramento em tempo real das variantes
python3 02-blue-team-realtime-ids/train_and_detect_ids.py
```

*(Adicione `--auto` para rodar sem pausas interativas.)*
