# 🎤 Roteiro Ao Vivo — Apresentação Prática Sem Slides (`ai-cyber-duel`)

> **Duração sugerida:** 15 a 18 minutos (+ perguntas)
> **Formato:** 100% prático, alternando entre o **Navegador (GitHub)** e o **Terminal (Linux Mint / Codespaces)**.

---

## ✅ Checklist Rápido (2 Minutos Antes de Começar — Linux Mint)

1. **Aba 1 do Navegador:** Abra `https://github.com/victorherculini/ai-cyber-duel` (dê zoom `Ctrl + +` para 125% ou 150% no projetor).
2. **Terminal (Linux Mint):**
   - Entre na pasta, ative o ambiente virtual e valide a instalação:
     ```bash
     cd ai-cyber-duel
     source .venv/bin/activate
     export TERM=xterm-256color
     python3 --version
     clear
     ```
   - Aumente a fonte (`Ctrl + Shift + +`) até ficar legível do fundo da sala.
   - **Abra o menu interativo de 1 tecla:**
     ```bash
     python3 apresentar.py
     ```
   - Confira no topo do menu a resolução detectada do terminal (`Terminal: LxA`): acima de **96 colunas** a Arena Ao Vivo exibe o **Split-Screen lado a lado**; em projetores muito estreitos (`< 96` colunas) ela adapta automaticamente para painéis empilhados sem cortar texto.
   - *(Dica: ao final da apresentação, pressione `[0]` no menu para limpar automaticamente `sandbox_env/`, `quarantine/`, `generated_variants/` e `RELATORIO_INCIDENTE_SOC.md`.)*
3. **Plano B (Emergência):** Se o laboratório bloquear `git clone` ou `apt`/`pip`, clique no botão verde **`Code → Codespaces → Create codespace on main`** no próprio GitHub — o `.devcontainer` instala tudo sozinho em ~1 minuto.

### Atalhos no Menu (`python3 apresentar.py`)
| Tecla | Etapa / Ação | Comando Equivalente |
| :---: | :--- | :--- |
| **`1`** | Gerador Polimórfico Básico | `python3 01-red-team-polymorphic/polymorphic_simulator.py` |
| **`2`** | Teste no Antivírus Tradicional SHA-256 | `python3 01-red-team-polymorphic/static_av_bypass_demo.py` |
| **`3`** | Treinar e Rodar IDS Defensivo com IA | `python3 02-blue-team-realtime-ids/train_and_detect_ids.py` |
| **`4`** | Motor Avançado de Mutação AST | `python3 01-red-team-polymorphic/ast_transform_engine.py` |
| **`5`** | Arena Ao Vivo Split-Screen (`Watchdog` + `Psutil` + IA) | `python3 arena_duel_live.py` |
| **`6`** | Exibir Relatório Técnico (`RELATORIO_INCIDENTE_SOC.md`) | Visualização em Markdown no terminal |
| **`0`** | Limpar artefatos temporários e sair | Remove arquivos temporários da demo |

---

## 🗺️ Etapa 1 — Explicação no GitHub (Arquitetura e Teoria Visual)
**⏱️ Tempo:** ~3 a 4 minutos | **📺 Tela:** Navegador no `README.md` do GitHub

### O que mostrar na tela
1. Role até a tabela **"Comparativo Direto: Defesa Tradicional vs. Defesa com IA"**.
2. Role até o **Diagrama Mermaid ("Arquitetura do Duelo")**.

### 🗣️ O que falar
> *"Boa noite, professor e turma. Hoje não vamos usar slides tradicionais — toda a apresentação vai acontecer direto entre o nosso repositório no GitHub e o terminal ao vivo.*
>
> *O tema é a corrida armamentista da Inteligência Artificial na cibersegurança: como atacantes usam técnicas generativas e polimorfismo para derrotar antivírus tradicionais, e como defensores usam a mesma tecnologia — Machine Learning — para pegar esses ataques em tempo real.*
>
> *Antes de rodar o código, um aviso ético importante: toda a simulação é 100% inofensiva. O nosso 'malware' simulado na verdade é apenas um script Python benigno que imprime uma mensagem no terminal.*
>
> *[Aponte para o diagrama Mermaid na tela]*
> *Olhem o fluxo que vamos provar ao vivo nos próximos 10 minutos: primeiro, o lado vermelho (Red Team) pega um código benigno conhecido e gera 5 variantes polimórficas com hashes SHA-256 totalmente novos. Em seguida, passamos tudo num Antivírus tradicional por assinatura e vamos ver ele falhar miseravelmente. Por fim, treinamos um IDS com Machine Learning ao vivo e colocamos ele para inspecionar os mesmos arquivos reais em tempo real."*

---

## 🔴 Etapa 2 — Rodando o Ataque Polimórfico (Red Team)
**⏱️ Tempo:** ~3 a 4 minutos | **📺 Tela:** Terminal

### Comando para executar
```bash
python3 01-red-team-polymorphic/polymorphic_simulator.py
```

### 🗣️ O que falar em cada pausa do script

- **Na Pausa 1 (Mostrando o `payload_original.py` na tela):**
  > *"Aqui está o nosso ponto de partida: um script legível, simples, que apenas imprime 'Simulacao de Payload Ativo'. Reparem em dois números aqui embaixo: o hash **SHA-256** dele — que é a impressão digital criptográfica do arquivo — e a **Entropia de Shannon**, que está em torno de 4,7 bits por byte, típica de código-fonte humano legível.*
  > *Agora vou pressionar ENTER para ligar o motor polimórfico."*

- **Na Pausa 2 (Após gerar as 5 variantes e exibir a tabela `rich`):**
  > *"Em menos de dois segundos, o motor aplicou renomeação aleatória de variáveis, injeção de junk code (código morto), compressão Zlib e criptografia XOR com chaves dinâmicas e Base85.*
  > *Olhem a coluna de **SHA-256**: 6 arquivos, 6 hashes 100% diferentes! Mesmo mudando poucos elementos, o efeito avalanche do SHA-256 destrói qualquer assinatura anterior.*
  > *Agora reparem na coluna de **Entropia de Shannon** (em vermelho): o código normal tinha ~4,7 bits/byte, e as variantes saltaram para acima de **6,0 a 6,3 bits/byte**. Guardem esse detalhe — essa aleatoriedade extra é a pista estatística que vai trair o atacante depois!"*

- **Após pressionar ENTER (Prova de Equivalência Funcional):**
  > *"Aqui embaixo está o trecho da Variante 5: completamente ilegível para um humano. Mas quando executamos o original e a Variante 5 ao vivo, olhem o quadro verde: **exatamente a mesma saída no terminal**. Código diferente, hash diferente, mesmo comportamento. Hoje, LLMs conseguem automatizar essa reescrita em segundos para cada alvo individual."*

---

## ⚠️ Etapa 3 — Mostrando a Falha do Antivírus Tradicional
**⏱️ Tempo:** ~2 a 3 minutos | **📺 Tela:** Terminal

### Comando para executar
```bash
python3 01-red-team-polymorphic/static_av_bypass_demo.py
```

### 🗣️ O que falar em cada pausa do script

- **Na Pausa 1 (Mostrando o Banco de Assinaturas SHA-256):**
  > *"Agora vamos colocar esses arquivos na frente de um Antivírus tradicional, baseado em banco de assinaturas SHA-256 — como funciona a primeira camada de bloqueio estático.*
  > *Reparem que a assinatura exata do `payload_original.py` JÁ está cadastrada na blacklist do antivírus (destacada em verde). Vamos rodar a varredura na pasta `generated_variants/`."*

- **Após a varredura (Tabela de Resultados + Veredito Vermelho):**
  > *"Resultado na tela: a versão original conhecida foi **100% bloqueada**, exatamente como esperado.*
  > *Mas olhem as 5 variantes polimórficas logo abaixo: **0 de 5 detectadas — 0% de detecção, evasão total!** Todas passaram livres porque seus hashes nunca existiram antes no banco de dados.*
  > *Isso prova na prática por que depender só de assinatura estática contra IA ofensiva é uma batalha perdida."*

---

## 🔵 Etapa 4 — Rodando o IDS com IA e Pegando o Ataque em Tempo Real (Blue Team)
**⏱️ Tempo:** ~4 a 5 minutos | **📺 Tela:** Terminal

*(Opcional: se quiser mostrar a geração do dataset separadamente antes, rode `python3 02-blue-team-realtime-ids/generate_telemetry_data.py`. Caso contrário, o comando abaixo já gera automaticamente se não existir.)*

### Comando para executar
```bash
python3 02-blue-team-realtime-ids/train_and_detect_ids.py
```

### 🗣️ O que falar em cada pausa do script

- **Na Pausa 1 (Após o treinamento do `RandomForestClassifier` e exibição das métricas):**
  > *"Agora vira o jogo: entramos com o Blue Team. Acabamos de treinar um classificador **Random Forest** ao vivo em menos de 1 segundo sobre 2.000 eventos de telemetria de sistema operacional e rede (80% treino, 20% teste inédito).*
  > *Reparem na tabela de métricas: Acurácia, Precisão e Recall altíssimos, com matriz de confusão transparente. E mais importante: olhem o gráfico de **Importância das Features** — a IA não olha para o hash do arquivo! Ela aprende a cruzar entropia, sinais de ofuscação, criação anômala de processos, chamadas de API suspeitas e conexões de rede.*
  > *Vou pressionar ENTER para ligar o sensor em tempo real sobre os **mesmos arquivos reais** que enganaram o antivírus."*

- **Durante o fluxo de monitoramento em tempo real (aponte conforme os painéis aparecem):**
  > *"Primeiro passam dois eventos legítimos de controle em **VERDE**:*
  > *1) `backup_diario.py` — código normal, baixa entropia, liberado.*
  > *2) Olhem o segundo evento (`instalador_compactado.pkg`) — esse é um teste proposital de **Falso Positivo**! Ele tem entropia **alta (6,24 bits/byte)** por ser um pacote compactado legítimo, mas como o comportamento de processos e rede está limpo, a IA **NÃO** disparou alarme falso!*
  >
  > *Agora chegam as 5 variantes polimórficas REAIS da pasta do Red Team... e os **painéis vermelhos de ALERTA CRÍTICO** disparam em tempo real!*
  > *Mesmo com hashes SHA-256 inéditos, a IA pega uma por uma e ainda entrega **Explicabilidade (XAI)**: ela mostra exatamente quais features fugiram da média normal — a entropia real que calculamos do disco, o score de ofuscação e a telemetria anômala de execução."*

- **Na Pausa Final (Placar Comparativo):**
  > *"Pressiono ENTER para o placar final do duelo:*
  > *- **Antivírus Tradicional (SHA-256):** 0/5 variantes polimórficas (0%) — evadido.*
  > *- **IDS com IA (RandomForest):** 5/5 variantes polimórficas (100%), com 0 falsos positivos nos controles legítimos."*

---

## ⚡ Etapa Extra (Opcional / Diferencial) — Mutação AST e Arena Ao Vivo com Telemetria Real
**⏱️ Tempo:** ~3 minutos | **📺 Tela:** Menu `python3 apresentar.py` → Teclas **`[4]`**, **`[5]`** e **`[6]`**

1. Pressione **`[4]`** (`python3 01-red-team-polymorphic/ast_transform_engine.py`) para mostrar reescrita estrutural real via árvore sintática (`ast`): renomeação de funções, embaralhamento de definições, conversão `for → while` e predicados opacos.
2. Pressione **`[5]`** (`python3 arena_duel_live.py`) para abrir a **Arena Ao Vivo Split-Screen**, executando 5 ondas em `sandbox_env/` com captura real de disco (`watchdog`), I/O (`psutil`), pings TCP loopback (`127.0.0.1:59999`), detecção via Ensemble (`RandomForest + IsolationForest`) e isolamento automático em `quarantine/`.
3. Pressione **`[6]`** para exibir o relatório técnico **`RELATORIO_INCIDENTE_SOC.md`** renderizado direto no terminal.
4. Ao encerrar, pressione **`[0]`** para limpar todos os artefatos temporários.

---

## 🏁 Etapa 5 — Conclusão e Abertura para Perguntas
**⏱️ Tempo:** ~2 minutos | **📺 Tela:** Placar Final no Terminal (ou Diagrama no GitHub)

### 🗣️ O que falar
> *"Para fechar com três aprendizados práticos:*
> *1. **Assinaturas estáticas não morreram**, mas hoje servem apenas como filtro barato e rápido para ameaças já conhecidas — nunca como única defesa.*
> *2. **Polimorfismo esconde o hash, mas deixa rastros estatísticos e comportamentais.** Ao combinar análise estática heurística (entropia) com comportamento em tempo real (EDR/NDR), o custo para o atacante aumenta drasticamente.*
> *3. **A IA não é uma bala de prata:** assim como atacantes usam IA para mutar código, eles também tentam ataques adversariais contra modelos defensivos (como camuflar entropia). Por isso, cibersegurança moderna é defesa em profundidade contínua.*
>
> *Todo o código está aberto em `github.com/victorherculini/ai-cyber-duel` para quem quiser testar. Muito obrigado — fico aberto às perguntas do professor e da turma!"*
