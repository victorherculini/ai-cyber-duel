# 🎤 Roteiro Ao Vivo — Apresentação Universitária de 30 a 45 Minutos (`ai-cyber-duel`)

> **Duração planejada:** 35 a 45 minutos (4 blocos práticos de ~10 min + ~5 min de arguição/Q&A)
> **Formato:** 100% prático, sem slides, alternando entre **GitHub**, **Terminal (Linux Mint sem `sudo`)** e **Arena Tática Web (`http://127.0.0.1:8080`)**.

---

## ✅ Checklist Rápido (3 Minutos Antes — Linux Mint 100% sem `sudo`)

1. **Aba 1 do Navegador:** Abra `https://github.com/victorherculini/ai-cyber-duel` (zoom `Ctrl + +` para 125%–150% no projetor).
2. **Terminal (Linux Mint — espaço de usuário, zero `sudo`):**
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
   - **Se o `pip` não estiver instalado na sala (sem `sudo`):** execute antes de criar o `.venv`:
     ```bash
     curl -sS https://bootstrap.pypa.io/get-pip.py | python3 - --user
     ```
   - **Aumente a fonte do terminal** (`Ctrl + Shift + +`) até ficar legível do fundo da sala. Acima de **96 colunas** a Arena Split-Screen fica lado a lado; abaixo disso empilha automaticamente sem cortes.
   - **Abertura automática no Linux Mint:** `[7]` abre `dashboard_soc.png` e `[8]` abre `http://127.0.0.1:8080` (fallback `8081`) via `xdg-open` sem travar o terminal. Para sair de `[8]`, pressione `Ctrl+C`.
3. **Plano B (Emergência em 1 Clique):** Se a rede do laboratório bloquear `git clone` ou `pip`, clique no botão verde **`Code → Codespaces → Create codespace on main`** no GitHub — o `.devcontainer` configura tudo em ~1 minuto.

### Mapa de Atalhos do Menu (`python3 apresentar.py`)
| Tecla | Módulo / Etapa | Bloco do Seminário |
| :---: | :--- | :---: |
| **`1`** | Gerador Polimórfico Básico (`polymorphic_simulator.py`) | Bloco 2 |
| **`2`** | Teste no Antivírus Tradicional SHA-256 (`static_av_bypass_demo.py`) | Bloco 2 |
| **`3`** | Treinar e Rodar IDS Defensivo com IA (`train_and_detect_ids.py`) | Bloco 2 |
| **`4`** | Motor Avançado de Mutação AST (`ast_transform_engine.py`) | Bloco 3 |
| **`5`** | Arena Ao Vivo Split-Screen (`arena_duel_live.py` — `Watchdog` + `Psutil` + IA) | Bloco 3 |
| **`6`** | Exibir Relatório Técnico Gerado (`RELATORIO_INCIDENTE_SOC.md`) | Bloco 3 |
| **`7`** | Gráficos Visuais SOC (`visual_analytics.py` — Terminal + `dashboard_soc.png`) | Bloco 3 |
| **`8`** | Arena Tática Web no Navegador (`web_arena.py` — `http://127.0.0.1:8080`) | Bloco 4 |
| **`0`** | Limpar artefatos temporários e sair | Encerramento |

---

## 🗺️ Bloco 1 (00–10 min) — Contexto, Teoria e Arquitetura no GitHub
**📺 Tela:** Navegador em `README.md` no GitHub

### Pontos para percorrer na tela
1. **A Corrida Armamentista da IA na Cibersegurança:** explique por que assinaturas estáticas (`MD5`/`SHA-256`) falham com o **efeito avalanche** diante de motores polimórficos e LLMs.
2. **Tabela Comparativa (AV Tradicional vs. IDS/EDR com IA):** destaque a mudança de paradigma (*"como o arquivo se parece"* → *"estrutura estatística + comportamento"*), falsos positivos e explicabilidade (XAI).
3. **Diagrama Mermaid ("Arquitetura do Duelo"):** aponte os 3 blocos (Red Team → Defesa Legada → Blue Team com IA).
4. **Aviso Ético:** reforce que 100% dos payloads são scripts Python benignos rodando localmente em `./sandbox_env/` e loopback `127.0.0.1`.

### 🗣️ Fala-chave de abertura
> *"Hoje vamos apresentar sem slides: vamos alternar entre a documentação no GitHub, o terminal ao vivo no Linux Mint e uma Arena Tática Web rodando localmente com modelos reais de Machine Learning. Vamos provar na prática como a automação polimórfica e metamórfica derrota antivírus por assinatura — e como um Ensemble de IA com telemetria real de sistema operacional vira o jogo."*

---

## 🔴🔵 Bloco 2 (10–20 min) — Duelo Clássico: Polimorfismo vs. AV SHA-256 vs. IDS RandomForest
**📺 Tela:** Terminal em `python3 apresentar.py` → Teclas **`[1]`**, **`[2]`** e **`[3]`**

### 1. Tecla **`[1]`** — Gerador Polimórfico Básico (~3 min)
- **Pausa 1 (`payload_original.py`):** aponte o **SHA-256** fixo e a **Entropia de Shannon** baixa (`~4.73 bits/B`, típica de código humano legível).
- **Pausa 2 (Tabela das 5 variantes):** mostre os **6 hashes 100% distintos** (XOR dinâmico, renomeação, *junk code*, Zlib + Base85) e o **salto de entropia** para `6.0–6.35 bits/B`.
- **Pausa 3 (Equivalência Funcional):** mostre o código ofuscado irreconhecível da Variante 5 gerando exatamente a mesma saída do original no terminal.

### 2. Tecla **`[2]`** — Antivírus Tradicional SHA-256 (~3 min)
- Mostre o `payload_original.py` **100% bloqueado** (hash na blacklist) e as **5 variantes polimórficas com 0/5 detecções (0% — evasão total)**.

### 3. Tecla **`[3]`** — IDS Defensivo com IA (`RandomForestClassifier`) (~4 min)
- **Pausa 1 (Treino ao vivo + Métricas):** destaque a divisão estratificada 80/20, Acurácia/Precisão/Recall/ROC-AUC e o gráfico de **Importância das Features (XAI)**.
- **Fluxo em tempo real:**
  - `backup_diario.py` → liberado (verde).
  - **`instalador_compactado.pkg`** → **teste intencional de falso positivo!** Alta entropia (`6.24 bits/B`), mas comportamento limpo → **liberado sem falso alarme**.
  - 5 variantes polimórficas reais → **5/5 interceptadas (100%)** com explicação XAI por evento.

---

## ⚙️ Bloco 3 (20–30 min) — Mutação AST Real, Telemetria de SO (`Watchdog`/`Psutil`) e Visual Analytics
**📺 Tela:** Terminal em `python3 apresentar.py` → Teclas **`[4]`**, **`[5]`**, **`[6]`** e **`[7]`**

### 1. Tecla **`[4]`** — Motor Avançado de Mutação Estrutural via AST (~2 min)
- Explique a diferença entre **polimorfismo** (criptografia/packer) e **metamorfismo AST** (reescrita real da árvore sintática: `for → while`, renomeação de funções, embaralhamento e predicados opacos).
- Aponte o detalhe crucial na tabela: nas ondas ímpares (`AST Opaque`), a entropia fica **baixa (`~4.93 bits/B`)** — enganando tanto o AV quanto detectores baseados só em entropia!

### 2. Tecla **`[5]`** — Arena Ao Vivo Split-Screen (~4 min)
- Mostre 5 ondas rodando ao vivo no sandbox (`./sandbox_env/`):
  - **`watchdog`** interceptando eventos reais de criação de arquivos no disco;
  - **`psutil`** medindo I/O real + servidor TCP `127.0.0.1:59999` capturando pings loopback reais;
  - **Ensemble `RandomForest + IsolationForest`** isolando **10/10** variantes na pasta `quarantine/` em ~13 ms.

### 3. Teclas **`[6]`** e **`[7]`** — Relatório SOC e Dashboard Dark Mode PNG (~4 min)
- **`[6]`** projeta `RELATORIO_INCIDENTE_SOC.md` formatado em Markdown no terminal.
- **`[7]`** renderiza os 3 gráficos de barras Unicode no terminal (Entropia vs. Limiar `5.50`, AV vs. IA e XAI) e abre automaticamente **`dashboard_soc.png`** (Curva ROC + Matriz de Confusão, Distribuição de Entropia e Latência por Onda AST).

---

## 🎮 Bloco 4 (30–40 min) — Clímax Visual: Arena Tática Web SOC (`localhost:8080`)
**📺 Tela:** Navegador aberto pela tecla **`[8]`** (`python3 web_arena.py`)

> **Destaque técnico para a banca:** tudo que acontece no navegador é **100% real no backend Python** — cada clique dispara mutação real via `ast` / `polymorphic_simulator`, execução real no sandbox, captura real de ping TCP em `127.0.0.1:59999` e inferência real do `RandomForest + IsolationForest`. Zero números mockados no JavaScript!

### Sequência guiada de botões/atalhos no navegador (`1` a `7`)
1. Pressione **`[6]`** para ligar o **Modo Câmera Lenta (`0.4x`)** — ideal para a turma enxergar cada detalhe no projetor.
2. Pressione **`[1]`** (*Original*) → acompanhe o pacote colidir e explodir na **Muralha Legada SHA-256** (`AV BLOQUEOU`).
3. Pressione **`[2]`** (*Polimórfico*) → aponte o polígono **mudando de forma e cor em voo** com a etiqueta flutuante `SHA:... | H=...`, atravessando a muralha SHA-256 (**BYPASS**) e sendo travado pelo feixe neon + onda de choque do **Escudo Neural IA** até o cofre de **Quarentena** (com explosão de partículas violetas). Clique no evento no feed para mostrar o **Painel de Inspeção** (tempo de mutação, I/O real, pings loopback reais, `RF%`, `IsolationForest` e código mutado).
4. Pressione **`[3]`** (*Tráfego Misto x4*) → destaque o `instalador_compactado.pkg` (blob `zlib` real com `H ≈ 7.93`, **0% risco RF**, zero falsos positivos!) chegando limpo ao servidor enquanto os ataques são interceptados.
5. Pressione **`[4]`** para **DESLIGAR o Escudo IA** e depois **`[2]`** → mostre o impacto visual do **BREACH** (tremor de tela + choque vermelho no servidor) provando o que acontece sem defesa de IA. Pressione **`[4]`** para religar o escudo.
6. Volte para velocidade normal (**`[6]` → `1.0x`**) e pressione **`[7]`** (*Onda Massiva de Estresse x8*) → deixe a batalha tática rodar enquanto o **gráfico de histórico de risco IA em tempo real** é desenhado no rodapé do Canvas!
7. Pressione **`[5]`** se quiser resetar para perguntas ao vivo, ou volte ao terminal com **`Ctrl+C`** e pressione **`[0]`** no menu para limpar todos os artefatos temporários.

---

## 🏁 Bloco 5 (40–45 min) — Conclusão e Arguição (Q&A)
**📺 Tela:** Placar / Arena Web ou Diagrama Mermaid no GitHub *(apoio rápido: [`PERGUNTAS_PROFESSOR.md`](./PERGUNTAS_PROFESSOR.md))*

### 🗣️ Encerramento (2 min)
> *"Três conclusões objetivas que comprovamos ao vivo:*
> *1. **Assinaturas estáticas (SHA-256)** continuam úteis como filtro rápido para ameaças conhecidas, mas falham 100% diante de polimorfismo e metamorfismo AST automatizados.*
> *2. **Defesa baseada em IA + telemetria real de SO** (entropia, estrutura AST, disco e rede) generaliza para ameaças inéditas mantendo falsos positivos sob controle — inclusive para arquivos legítimos compactados.*
> *3. **Defesa em profundidade e XAI são essenciais:** modelos defensivos precisam ser auditáveis, rápidos (milissegundos) e resilientes a evasão adversarial.*
>
> *Todo o código é aberto em `github.com/victorherculini/ai-cyber-duel`. Muito obrigado — fico à disposição para as perguntas do professor e da turma!"*
