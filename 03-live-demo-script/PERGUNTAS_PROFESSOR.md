# 🎓 Banco de Perguntas Difíceis — Defesa da Apresentação (Q&A)

Cinco perguntas técnicas avançadas que o professor ou a turma costumam fazer durante uma demonstração ao vivo de IA em Cibersegurança, com **respostas curtas e diretas** para responder com segurança na hora.

---

### 1. "Se arquivos legítimos compactados (ZIP, instaladores, binários com UPX) também têm alta entropia, esse IDS de IA não vai gerar muitos falsos positivos e travar a empresa?"

**Resposta direta (30s):**
> *"Excelente ponto — se o modelo olhasse **apenas** para a entropia, geraria muitos falsos positivos mesmo (a chamada alert fatigue no SOC). É exatamente por isso que incluímos dois cuidados no nosso experimento: primeiro, no dataset de treino inserimos 'negativos difíceis' — softwares legítimos compactados com alta entropia (acima de 6 bits/byte), mas sem comportamento malicioso. Segundo, o Random Forest cruza a entropia com 5 outras features comportamentais (processos, APIs e rede). Por isso, na demo, o `instalador_compactado.pkg` com entropia 6,24 foi corretamente liberado como Normal."*

**Nota técnica extra (se o professor aprofundar):**
Em produção, EDRs reais ainda combinam o score de ML com **assinatura digital válida (code signing / certificados confiáveis)**, *allowlists* organizacionais e **limiares de decisão calibrados** (ex.: só isolar automaticamente acima de 95% de confiança; entre 70% e 95%, abrir ticket para o analista).

---

### 2. "Qual é o custo computacional de rodar Inteligência Artificial em tempo real? Isso não deixa o servidor ou a rede lentos demais?"

**Resposta direta (30s):**
> *"Depende totalmente da arquitetura escolhida. Treinar modelos pesados é caro, mas a **inferência** em produção de modelos baseados em árvores — como o Random Forest que usamos aqui ou LightGBM — leva frações de milissegundo na CPU e consome pouquíssima memória. Em ambientes reais de alta vazão, usa-se uma arquitetura em camadas: filtros baratos primeiro (hash/assinatura + regras determinísticas), depois modelos leves no endpoint (edge), e só os eventos suspeitos sobem para modelos profundos (Deep Learning) na nuvem ou no SIEM."*

**Nota técnica extra:**
Na nossa própria demo, o treinamento de 120 árvores levou menos de 1 segundo e cada inferência em tempo real ocorre na casa de poucos milissegundos. O gargalo em redes de dezenas de Gbps normalmente é a **extração de features**, não a árvore de decisão em si.

---

### 3. "E se o atacante souber que há uma IA defendendo e atacar o próprio modelo de Machine Learning (Adversarial Attacks)?"

**Resposta direta (30s):**
> *"Esse é justamente o campo de **Adversarial Machine Learning**, o próximo nível dessa corrida armamentista. Existem dois grandes vetores: **Evasion Attacks** — por exemplo, o atacante faz *entropy padding*, inserindo megabytes de texto comum em inglês dentro do malware só para derrubar a Entropia de Shannon artificialmente, ou executa ações maliciosas muito devagar (*low-and-slow*) para fugir da taxa de processos/minuto — e **Data Poisoning**, tentando contaminar os dados usados no retreinamento do IDS."*

**Como o Blue Team mitiga isso:**
- **Adversarial Training:** treinar o IDS também com amostras evadidas (ex.: entropia camuflada + *entropy windowing* por seção do arquivo, não só entropia global).
- **Defesa em Profundidade:** nunca depender de um único modelo nem de uma única feature — correlacionar telemetria de host, rede e identidade ao longo de janelas maiores de tempo.

---

### 4. "Qual é a diferença técnica entre malware polimórfico, metamórfico e código ofuscado por LLMs? O que vocês simularam aqui é polimorfismo mesmo?"

**Resposta direta (30s):**
> *"Sim! No **polimorfismo clássico**, o payload original permanece cifrado ou codificado e muda de chave/stub de decodificação a cada geração — foi exatamente o que fizemos com XOR dinâmico, Base85 e Zlib. Já no **metamorfismo**, não existe criptografia nem stub fixo: o próprio código executável é reescrito estruturalmente (trocando instruções equivalentes, reordenando blocos e inserindo código morto). O que torna os **LLMs** tão disruptivos hoje é que eles facilitam combinar os dois mundos: reescrevem a sintaxe (metamorfismo) e ainda geram rotinas de ofuscação variáveis (polimorfismo) a partir de um simples prompt."*

---

### 5. "Se a IA disparar um alerta crítico às 3 da manhã num servidor de produção, como o analista sabe que pode confiar na decisão e não está diante de uma 'caixa-preta'?"

**Resposta direta (30s):**
> *"Essa é a importância da **IA Explicável (XAI — Explainable AI)** em segurança. Um alerta que só diz '98% de chance de ataque' é quase inútil para resposta a incidentes. Por isso, escolhemos Random Forest e implementamos na demo um módulo de explicação por evento: em cada painel vermelho, o IDS compara cada feature observada com a média normal aprendida e mostra exatamente o que denunciou o arquivo (entropia real, score de ofuscação, chamadas de API e rede). Em produção, técnicas como **SHAP** ou **LIME** fazem isso em escala para dar auditoria, rastreabilidade e velocidade ao analista do SOC."*
