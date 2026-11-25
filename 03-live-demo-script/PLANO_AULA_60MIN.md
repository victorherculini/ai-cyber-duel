# 🎓 Plano de Aula & Roteiro Cronometrado de 1 Hora (`50–60 min`) — `ai-cyber-duel`

> **Disciplina:** Sistemas de Segurança da Informação (Seminário Universitário Prático)
> **Duração Total:** 50 a 60 minutos (5 atos estruturados + demonstrações ao vivo sem slides)
> **Ambiente Alvo:** **Linux Mint 100% sem `sudo`** (espaço de usuário) ou GitHub Codespaces (Plano B)

---

## 🛠️ Pré-Voo no Laboratório (3 Minutos Antes — Linux Mint sem `sudo`)

Execute exatamente este bloco no terminal do Linux Mint da sala (zero privilégios administrativos necessários):

```bash
git clone https://github.com/victorherculini/ai-cyber-duel.git
cd ai-cyber-duel
python3 -m venv .venv || (python3 -m pip install --user virtualenv && python3 -m virtualenv .venv)
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
export TERM=xterm-256color
clear
python3 apresentar.py
```

- **Se o `pip` não vier instalado na máquina:** execute antes de criar o `.venv`:
  ```bash
  curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - --user
  ```
- **Plano B (Emergência em 1 Clique):** no repositório do GitHub, clique em **`<> Code → Codespaces → Create codespace on main`** — tudo sobe pronto em ~1 minuto no navegador.
- **Ajuste de projetor:** aumente a fonte do terminal com `Ctrl + Shift + +` até ficar legível no fundo da sala (mantenha largura `>= 96` colunas no topo do `apresentar.py` para o Split-Screen lado a lado).

---

## ⏱️ Visão Geral do Cronograma (59 Minutos)

| Ato | Tempo | Foco Principal | Ferramenta / Teclas no Projetor |
| :---: | :---: | :--- | :--- |
| **Ato 1** | `00–10 min` *(10m)* | Fundamentos, Efeito Avalanche & Arquitetura | Navegador no GitHub ([`README.md`](../README.md)) |
| **Ato 2** | `10–22 min` *(12m)* | Red Team no Terminal + Inspeção de AST Real | `apresentar.py` → `[1]`, `[2]`, `[4]` + inspeção em `generated_variants/` |
| **Ato 3** | `22–34 min` *(12m)* | Blue Team, Telemetria Real SO & Gráficos SOC | `apresentar.py` → `[3]`, `[5]`, `[6]`, `[7]` (`dashboard_soc.png`) |
| **Ato 4** | `34–49 min` *(15m)* | Grand Finale: Arena Tática Web SOC | `apresentar.py` → `[8]` (`http://127.0.0.1:8080`, `[F]`, `[6]`, `[1]`–`[7]`, `[C]`) |
| **Ato 5** | `49–59 min` *(10m)* | Debate Técnico, Ética em Sandbox & Banca | Q&A + [`PERGUNTAS_PROFESSOR.md`](./PERGUNTAS_PROFESSOR.md) + `[0]` Limpeza |

---

## 🗺️ Ato 1 (00–10 min) — Teoria Visual no GitHub (`README.md`)

**Objetivo pedagógico:** Nivelar a turma sobre por que assinaturas estáticas quebram diante de polimorfismo/LLMs e introduzir a mudança de paradigma para detecção estatística e comportamental.

### Roteiro na Tela
1. **(00–03 min) Abertura & Escopo Ético:** apresente o repositório aberto no GitHub (`Ctrl + +` para 125%–150%) explicando que não haverá slides — todo o conceito será provado ao vivo com código 100% benigno em sandbox local (`./sandbox_env/` e loopback `127.0.0.1`).
2. **(03–06 min) Tabela Comparativa:** percorra linha a linha **Antivírus Tradicional (SHA-256)** vs. **IDS/EDR com IA (Entropia + Comportamento)**, destacando:
   - *Efeito avalanche:* 1 único bit alterado gera um hash completamente inédito.
   - *Falsos positivos:* por que olhar apenas entropia bloquearia instaladores `.zip`/`.pkg` legítimos.
   - *XAI (Explicabilidade):* por que um analista SOC precisa saber *quais features* dispararam o alerta.
3. **(06–10 min) Diagrama Mermaid ("Arquitetura do Duelo"):** trace com o cursor o fluxo **Red Team → Defesa Legada (0% detecção nas variantes) → Blue Team com Machine Learning (100% detecção)** e faça a transição para o terminal.

---

## 🔴 Ato 2 (10–22 min) — Red Team no Terminal & Árvore Sintática Real (`[1]`, `[2]`, `[4]`)

**Objetivo pedagógico:** Provar empiricamente que polimorfismo e metamorfismo AST destroem a detecção estática preservando exatamente o mesmo comportamento.

### Passo a Passo no Terminal (`python3 apresentar.py`)
1. **(10–14 min) Tecla `[1]` — Gerador Polimórfico Básico (`polymorphic_simulator.py`):**
   - **Pausa 1 (`payload_original.py`):** aponte o SHA-256 determinístico e a Entropia de Shannon normal (`~4.73 bits/B`).
   - **Pausa 2 (5 Variantes):** destaque os 6 hashes 100% únicos (XOR simples/duplo/rotativo, *junk code*, renomeação, Zlib + Base85) e o salto de entropia (`> 6.0 bits/B`).
   - **Pausa 3 (Equivalência Funcional):** mostre o trecho ofuscado da Variante 5 gerando exatamente a mesma saída `"Simulacao de Payload Ativo"` do original.
2. **(14–17 min) Tecla `[2]` — Antivírus Tradicional SHA-256 (`static_av_bypass_demo.py`):**
   - Mostre o banco de assinaturas carregado com o hash do `payload_original.py`.
   - Rode a varredura e deixe o veredito em tela: **Original 1/1 bloqueado (100%)** vs. **Variantes Polimórficas 0/5 (0% — evasão total)**.
3. **(17–22 min) Tecla `[4]` — Motor Avançado de Mutação AST (`ast_transform_engine.py`) + Inspeção Real em Disco:**
   - Execute `[4]` para gerar as ondas AST (`wave_01_variant_01.py` até `wave_03_variant_02.py`).
   - **Destaque científico crucial:** aponte que nas ondas ímpares (`AST Shuffle + For->While + Opaque Predicates`), a entropia cai de volta para **`~4.93 bits/B`** (faixa de código comum!) enquanto o SHA-256 continua 100% inédito — mostrando exatamente o tipo de reescrita semântica que **LLMs** automatizam hoje.
   - *(Momento "prova real" no terminal — abra um 2º terminal ou após `[4]`):* exiba um arquivo mutado real gerado em `generated_variants/`:
     ```bash
     head -n 45 01-red-team-polymorphic/generated_variants/wave_01_variant_01.py
     ```
   - Aponte diretamente para a turma no código projetado:
     - Funções renomeadas dinamicamente (`stage_xxxxxx`) e reordenadas na árvore;
     - O laço `for idx in range(3):` reescrito pelo `ast.NodeTransformer` para `idx = 0; while idx < 3: ... idx += 1`;
     - Os blocos de predicados opacos (`chk_xxxxxx = (val * 2) - val; if chk_xxxxxx < 0: ...`).

---

## 🔵 Ato 3 (22–34 min) — Blue Team, Telemetria Real de SO e Visual Analytics (`[3]`, `[5]`, `[6]`, `[7]`)

**Objetivo pedagógico:** Demonstrar como Machine Learning + telemetria real de sistema operacional (`watchdog`, `psutil`, loopback) neutralizam tanto polimorfismo de alta entropia quanto metamorfismo AST de baixa entropia, sem gerar falsos positivos.

### Passo a Passo no Terminal (`python3 apresentar.py`)
*(Dica: se quiser rodar `[3]` logo após `[4]`, pressione `[1]` rapidamente antes ou rode `[3]` logo após `[2]` para que `variante_01..05.py` estejam em `generated_variants/`.)*

1. **(22–26 min) Tecla `[3]` — IDS Defensivo com IA (`train_and_detect_ids.py`):**
   - Explique o treino ao vivo do `RandomForestClassifier` (80% treino / 20% teste estratificado, ~98,5% acurácia, ROC-AUC > 99,6%) e o gráfico de **Importância das Features (XAI)**.
   - Destaque os dois controles verdes antes das ameaças:
     - `backup_diario.py` (normal) → liberado;
     - **`instalador_compactado.pkg`** (entropia `6.24`, comportamento limpo) → **0 falsos positivos!**
   - Mostre as 5 variantes polimórficas reais sendo interceptadas (5/5 = 100%) com a tabela XAI de cada evento.
2. **(26–30 min) Tecla `[5]` — Arena Ao Vivo Split-Screen (`arena_duel_live.py`):**
   - Explique os 3 sensores reais atuando simultaneamente:
     - **`watchdog`** (`inotify` no Linux Mint) detectando criação de arquivos no disco;
     - **`psutil`** medindo I/O real de escrita + servidor TCP em **`127.0.0.1:59999`** capturando os 10 pings reais enviados pelas variantes AST no sandbox;
     - **Ensemble `RandomForest + IsolationForest`** isolando automaticamente **10/10** variantes na pasta `quarantine/` com latência média de ~13 ms.
3. **(30–34 min) Teclas `[6]` e `[7]` — Relatório SOC & Dashboard Dark Mode (`dashboard_soc.png`):**
   - **`[6]`** mostra o relatório técnico **`RELATORIO_INCIDENTE_SOC.md`** gerado automaticamente com as métricas reais da rodada.
   - **`[7]`** projeta os gráficos em barras Unicode no terminal e abre automaticamente **`dashboard_soc.png`** no visualizador do Linux Mint (`xdg-open`). Analise os 3 subplots com a turma:
     1. **Curva ROC (`AUC ≈ 0.9969`) + Matriz de Confusão:** quase zero erros (`FP=5`, `FN=1` em 400 eventos inéditos).
     2. **Distribuição de Entropia de Shannon:** mostre a linha tracejada do limiar (`5.50 bits/B`) e os pontos **AST Opaque** à esquerda (`~4.93`) — prova visual de por que entropia sozinha não basta e telemetria comportamental é indispensável.
     3. **Latência de Inferência por Onda AST (~13 ms):** viabilidade prática em tempo real no endpoint.

---

## 🎮 Ato 4 (34–49 min) — Grand Finale: Arena Tática Web SOC (`[8]` — `http://127.0.0.1:8080`)

**Objetivo pedagógico:** Consolidar visualmente todo o seminário em uma batalha interativa em tempo real (estilo Tower Defense / Radar SOC) conectada **100% ao backend real de AST, sandbox e `scikit-learn`** (zero dados mockados no navegador).

### Coreografia Ao Vivo no Navegador
1. **(34–36 min) Abertura e Preparação Visual:**
   - No terminal, pressione **`[8]`** → o navegador abre automaticamente em `http://127.0.0.1:8080` (fallback `8081`).
   - Pressione **`[F]`** para ativar **Tela Cheia no Projetor**, **`[T]`** sempre que quiser abrir a gaveta do **Guia Teórico da Apresentação** (4 cartões didáticos com botões de disparo integrados) e opcionalmente **`[M]`** para ativar os bips táticos via Web Audio API.
   - Aponte as 3 zonas do Canvas: **Fábrica Polimórfica (Esquerda)** → **Muralha Legada SHA-256 (Centro)** → **Escudo Neural IA + Servidor (`HP 100%`) + Cofre de Quarentena (Direita)**.
2. **(36–40 min) Passo a Passo em Câmera Lenta (`[6]` → `0.4x`):**
   - Ative **`[6]` Câmera Lenta (`0.4x`)**.
   - Dispare **`[1]` Pacote Original:** mostre o bloqueio instantâneo com explosão âmbar na Muralha SHA-256 (`AV BLOQUEOU`).
   - Dispare **`[2]` Ataque Polimórfico:** acompanhe em câmera lenta o polígono **mudando de forma (`3→4→5→6→8` lados) e cor** com a etiqueta flutuante `SHA:... | H=...`, atravessando a Muralha SHA-256 (**BYPASS**) e sendo travado pelo feixe elétrico + onda de choque do **Escudo Neural IA** até a **Quarentena** (partículas violetas).
   - **Inspeção de Código Real (`[C]`):** pressione **`[C]`** (ou clique no item no Feed SOC) para abrir o **Modal Diff Lado a Lado** e mostre à turma o código baseline à esquerda vs. o código real mutado em disco à direita, com delta de SHA-256, Entropia e Nós AST! Feche com `ESC`.
3. **(40–44 min) Falsos Positivos & Impacto da Falta de IA (`[3]`, `[4]` e Queda de HP):**
   - Dispare **`[3]` Tráfego Misto (`x4`):** destaque o `instalador_compactado.pkg` (blob `zlib` real com `H ≈ 7.93 bits/B` e **`RF = 0.0%`**) atravessando o radar com selo `ALTA ENTROPIA, 0 FP!` e chegando seguro ao servidor, enquanto os 2 ataques são quarentenados (**HP do Servidor permanece em 100%**).
   - Pressione **`[4]`** para **DESLIGAR o Escudo IA** (o radar fica vermelho/OFFLINE) e dispare **`[2]`** duas ou três vezes: mostre os ataques polimórficos ignorando o AV e atingindo o servidor com tremor de tela, alerta vermelho e **queda real da barra de integridade (`HP 100% → 80% → 60% → 40%`)**!
   - Pressione **`[4]`** para **RELIGAR o Escudo IA** e **`[5]`** para resetar (`HP 100%`).
4. **(44–49 min) Teste de Estresse Contínuo (`[6]` → `1.0x` + `[7]` Onda Massiva `x8`):**
   - Volte à velocidade normal (**`[6]` → `1.0x`**) e pressione **`[7]` Onda x8**.
   - Deixe a rajada real de 8 pacotes rodar enquanto aponta o **gráfico HUD de Histórico de Risco IA (0%–100%)** desenhado em tempo real no rodapé do Canvas, o contador de latência média (`ms`) e o servidor intacto em **`HP 100%`**!
   - Encerre a Arena Web voltando ao terminal com **`Ctrl+C`** (e deixe o menu pronto para o Ato 5).

---

## 💬 Ato 5 (49–59 min) — Debate Técnico, Ética em Sandbox e Encerramento

### Pergunta-Chave da Banca: *"Por que usar sandbox local controlado em vez de testar contra máquinas reais ou malware de verdade?"*
**Resposta técnica completa (para 1–2 minutos):**
1. **Ética, Legislação e Segurança Operacional:** executar malware real ou disparar tráfego ofensivo contra hosts sem autorização viola normas acadêmicas e o **Art. 154-A do Código Penal** (invasão de dispositivo informático), além de oferecer risco real de contaminação na rede do laboratório da universidade.
2. **Validade Científica com Telemetria Real do SO:** usar um **workload benigno controlado** em `./sandbox_env/` com socket exclusivamente em loopback (`127.0.0.1:59999`) permite medir **exatamente os mesmos sinais de sistema operacional** que um EDR/IDS observa no mundo real — eventos reais de disco via `inotify`/`watchdog`, I/O real via `psutil`, conexões TCP reais, Entropia de Shannon real e AST Python real — mantendo **100% de reprodutibilidade e zero risco**.
3. **Alinhamento com Práticas de Indústria:** equipes reais de Red/Purple Team usam *Breach and Attack Simulation (BAS)* e emulação benigna controlada (como Atomic Red Team / Caldera) exatamente por esse motivo: validar a eficácia dos detectores sem colocar ativos reais em perigo.

*(Para mais 5 perguntas difíceis — falsos positivos, latência/custo computacional, ataques adversariais, diferença entre polimorfismo/metamorfismo/LLMs e XAI — consulte [`PERGUNTAS_PROFESSOR.md`](./PERGUNTAS_PROFESSOR.md).)*

### Limpeza Final ao Encerrar a Apresentação
No menu do terminal (`apresentar.py`), pressione **`[0]`** para remover automaticamente todos os artefatos temporários (`generated_variants/`, `sandbox_env/`, `quarantine/`, `telemetry_dataset.csv`, `RELATORIO_INCIDENTE_SOC.md` e `dashboard_soc.png`) e deixar a máquina do laboratório completamente limpa.
