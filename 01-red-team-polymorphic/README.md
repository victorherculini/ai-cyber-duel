# 🔴 Módulo 01 — Red Team: Motor Polimórfico e Evasão de Análise Estática

> **Aviso Educacional:** Todos os scripts desta pasta são **100% inofensivos**. O payload base apenas imprime a frase `"Simulacao de Payload Ativo - [DEMO EDUCACIONAL INOFENSIVA]"` no terminal. O objetivo é provar matematicamente por que defesas baseadas apenas em hash (`SHA-256`) falham diante de código polimórfico.

---

## 🧬 O que é Malware Polimórfico?

Um artefato **polimórfico** altera sua própria aparência em disco a cada nova geração ou infecção, mantendo exatamente a mesma funcionalidade final. Enquanto uma assinatura estática (`MD5`, `SHA-1`, `SHA-256` ou regra YARA rígida) procura um padrão fixo de bytes, o motor polimórfico transforma os bytes a cada execução.

### Técnicas demonstradas neste laboratório:

| Técnica | Como funciona na prática | Efeito sobre a Análise Estática |
| :--- | :--- | :--- |
| **Renomeação Dinâmica** | Substitui nomes de variáveis e funções por identificadores aleatórios | Quebra assinaturas baseadas em strings/símbolos |
| **Injeção de *Junk Code*** | Insere cálculos inúteis, funções auxiliares falsas e predicados opacos | Altera tamanho, estrutura da AST e o hash do arquivo |
| **Criptografia XOR Dinâmica** | Cifra o conteúdo com chaves aleatórias novas a cada variante (simples, dupla camada e rotativa) | Oculta literais de texto e muda completamente os bytes |
| **Compressão + Codificação (`Zlib` + `Base64/Base85`)** | Compacta e empacota o bloco cifrado | Eleva drasticamente a **Entropia de Shannon** (pista que o Blue Team vai explorar!) |

---

## 🤖 Como LLMs e IA Generativa Automatizam Isso Hoje

Historicamente, criar um motor polimórfico ou metamórfico robusto exigia conhecimento avançado de compiladores e engenharia reversa (reescrita de *Abstract Syntax Trees* ou *Assembly*).

Com a chegada de **LLMs (Large Language Models)** e algoritmos generativos, atacantes passaram a automatizar a mutação em escala:

1. **Reescrita Semântica Sob Demanda:** Um modelo pode reescrever o mesmo fluxo lógico em múltiplas estruturas sintáticas (trocando `for` por `while`, recursão por iteração, dicionários por classes) mantendo a semântica intacta.
2. **Ofuscação Contextual:** Em vez de inserir lixo óbvio, modelos generativos conseguem gerar *junk code* que imita bibliotecas legítimas de negócios ou telemetria comum.
3. **Polimorfismo em Tempo Real (*Just-in-Time*):** Cada vítima ou requisição pode receber um artefato exclusivo, garantindo que o hash gerado nunca tenha aparecido antes em repositórios globais como o VirusTotal.

---

## ▶️ Como Executar Este Módulo

A partir da **raiz do repositório** (com o ambiente virtual ativado):

```bash
# 1. Gera o payload original + 5 variantes polimórficas em generated_variants/
python3 01-red-team-polymorphic/polymorphic_simulator.py

# 2. Executa o Antivírus tradicional (SHA-256) e comprova 0% de detecção nas variantes
python3 01-red-team-polymorphic/static_av_bypass_demo.py
```

*(Adicione `--auto` ao final do comando para executar sem pausas interativas.)*

---

## 🔍 A Fraqueza Oculta do Polimorfismo

Apesar de enganar 100% o antivírus baseado em hash, **a própria mutação deixa rastros matemáticos inevitáveis**:
- Criptografar e empacotar o código eleva a **Entropia de Shannon** (aleatoriedade dos bytes);
- Decodificar e executar o payload em tempo de execução gera **anomalias comportamentais** (picos de CPU, chamadas sensíveis e comunicação de rede atípica).

É exatamente isso que vamos explorar no [**Módulo 02 — Blue Team (IDS com IA em Tempo Real)**](../02-blue-team-realtime-ids/README.md).
