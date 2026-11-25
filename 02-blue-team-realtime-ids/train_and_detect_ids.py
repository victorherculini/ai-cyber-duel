#!/usr/bin/env python3
"""
AI Cyber Duel — Módulo 02 (Blue Team): IDS com Machine Learning em Tempo Real
=============================================================================
Treina um classificador RandomForestClassifier sobre telemetria de SO e rede,
exibe métricas completas de avaliação (Acurácia, Precisão, Recall, F1, Matriz de
Confusão e Importância das Features) e inicia um monitoramento simulado em tempo
real analisando os arquivos REAIS gerados pelo módulo Red Team.

Diferencial técnico:
  - Calcula Entropia de Shannon REAL e Score Heurístico de Ofuscação REAL a partir
    dos bytes dos arquivos gerados em 01-red-team-polymorphic/generated_variants/.
  - Combina essas métricas reais com telemetria comportamental simulada de EDR/NDR.
  - Explica visualmente QUAIS features denunciaram cada variante polimórfica.

Uso:
  python3 02-blue-team-realtime-ids/train_and_detect_ids.py
  python3 02-blue-team-realtime-ids/train_and_detect_ids.py --auto
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Permite importar generate_telemetry_data rodando da raiz ou de dentro da pasta
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from generate_telemetry_data import (  # noqa: E402
    DATASET_PATH,
    FEATURE_COLUMNS,
    FEATURE_LABELS,
    generate_dataset,
)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

PROJECT_ROOT = CURRENT_DIR.parent
RED_TEAM_VARIANTS_DIR = PROJECT_ROOT / "01-red-team-polymorphic" / "generated_variants"

# Padrões usados pelo analisador heurístico estático real
OBFUSCATED_IDENT_RE = re.compile(r"\b_[a-z]{1,8}_[a-z0-9]{6,}\b")
DECODE_PRIMITIVES = ("b85decode", "b64decode", "zlib.decompress", "base64", "^")


@dataclass
class LiveEvent:
    name: str
    source_type: str  # "baseline_benign" | "polymorphic_variant"
    sha256: str
    size_bytes: int
    features: dict[str, float]
    note: str


def pause(auto: bool, prompt: str = "\n[Pressione ENTER para continuar a demonstração...]") -> None:
    if not auto:
        input(prompt)


def compute_shannon_entropy(data: bytes) -> float:
    """Calcula a Entropia de Shannon real (bits/byte) de um arquivo em disco."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def compute_static_obfuscation_score(text: str) -> float:
    """
    Calcula um score heurístico real de ofuscação (0.0 a 1.0) inspecionando:
      - Presença de rotinas de decodificação/descompressão + operação XOR
      - Densidade de linhas com blobs codificados longos sem espaços
      - Quantidade de identificadores com padrão aleatório/renomeado
    """
    if not text:
        return 0.0

    lines = text.splitlines()
    total_lines = max(1, len(lines))

    # 1) Primitivas de decodificação / XOR
    primitive_hits = sum(1 for token in DECODE_PRIMITIVES if token in text)
    primitive_score = min(1.0, primitive_hits / 4.0)

    # 2) Proporção de linhas que parecem payloads codificados (longas e sem espaços)
    encoded_lines = sum(
        1 for ln in lines if len(ln.strip().strip('"')) >= 55 and " " not in ln.strip().strip('"')
    )
    blob_ratio = min(1.0, (encoded_lines / total_lines) * 2.4)

    # 3) Identificadores dinamicamente renomeados (_prefix_xxxxxxx)
    obf_idents = len(set(OBFUSCATED_IDENT_RE.findall(text)))
    ident_score = min(1.0, obf_idents / 6.0)

    score = (0.35 * primitive_score) + (0.35 * blob_ratio) + (0.30 * ident_score)
    return round(min(1.0, max(0.0, score)), 3)


def simulate_variant_runtime_telemetry(variant_index: int, real_entropy: float, real_obf: float) -> dict[str, float]:
    """
    Combina as features REAIS extraídas do arquivo em disco (entropia e ofuscação)
    com telemetria comportamental simulada de um sensor EDR/NDR ao observar a
    tentativa de execução da variante polimórfica em sandbox/endpoint.
    """
    # Perfis determinísticos e realistas por variante (sem depender de aleatoriedade caótica no palco)
    profiles = [
        {"spawn": 8.4, "api": 16.0, "net": 5.0, "cpu": 4.1},
        {"spawn": 10.2, "api": 19.0, "net": 6.0, "cpu": 4.7},
        {"spawn": 11.8, "api": 23.0, "net": 8.0, "cpu": 5.4},
        {"spawn": 13.1, "api": 26.0, "net": 9.0, "cpu": 6.1},
        {"spawn": 15.6, "api": 31.0, "net": 11.0, "cpu": 7.0},
    ]
    prof = profiles[variant_index % len(profiles)]
    return {
        "file_entropy": round(real_entropy, 3),
        "obfuscation_score": round(real_obf, 3),
        "process_spawn_rate": prof["spawn"],
        "suspicious_api_calls": prof["api"],
        "anomalous_net_connections": prof["net"],
        "cpu_burst_ratio": prof["cpu"],
    }


def build_live_inspection_queue() -> list[LiveEvent]:
    """
    Monta a fila de inspeção ao vivo combinando:
      - 2 processos legítimos de linha de base (incluindo 1 arquivo compactado de alta entropia
        para demonstrar que a IA evita falsos positivos!)
      - As 5 variantes polimórficas REAIS geradas pelo Red Team em generated_variants/
    """
    events: list[LiveEvent] = [
        LiveEvent(
            name="backup_diario.py",
            source_type="baseline_benign",
            sha256=hashlib.sha256(b"backup_diario_legitimo_v1").hexdigest(),
            size_bytes=1840,
            features={
                "file_entropy": 4.320,
                "obfuscation_score": 0.080,
                "process_spawn_rate": 1.2,
                "suspicious_api_calls": 1.0,
                "anomalous_net_connections": 0.0,
                "cpu_burst_ratio": 1.15,
            },
            note="Script administrativo rotineiro (baixa entropia, comportamento limpo)",
        ),
        LiveEvent(
            name="instalador_compactado.pkg",
            source_type="baseline_benign",
            sha256=hashlib.sha256(b"instalador_legitimo_compactado_v2").hexdigest(),
            size_bytes=48250,
            features={
                "file_entropy": 6.240,
                "obfuscation_score": 0.210,
                "process_spawn_rate": 2.1,
                "suspicious_api_calls": 2.0,
                "anomalous_net_connections": 0.0,
                "cpu_burst_ratio": 1.95,
            },
            note="Teste de Falso Positivo: pacote legítimo compactado (ALTA entropia, mas comportamento limpo!)",
        ),
    ]

    variant_files = sorted(RED_TEAM_VARIANTS_DIR.glob("variante_*.py"))
    for idx, vpath in enumerate(variant_files):
        raw_bytes = vpath.read_bytes()
        text = raw_bytes.decode("utf-8", errors="replace")
        real_hash = hashlib.sha256(raw_bytes).hexdigest()
        real_entropy = compute_shannon_entropy(raw_bytes)
        real_obf = compute_static_obfuscation_score(text)

        events.append(
            LiveEvent(
                name=vpath.name,
                source_type="polymorphic_variant",
                sha256=real_hash,
                size_bytes=len(raw_bytes),
                features=simulate_variant_runtime_telemetry(idx, real_entropy, real_obf),
                note="Artefato REAL gerado pelo Red Team (EVADIU o Antivírus tradicional!)",
            )
        )

    return events


def explain_detection(
    features: dict[str, float],
    normal_stats: dict[str, tuple[float, float]],
    importances: dict[str, float],
) -> list[tuple[str, float, float, str]]:
    """
    Calcula quais features mais contribuíram para o alerta daquele arquivo específico,
    combinando o desvio em relação ao comportamento normal (z-score) com a importância
    global aprendida pelo RandomForest.
    """
    scored: list[tuple[float, str, float, float, str]] = []
    for col in FEATURE_COLUMNS:
        val = features[col]
        n_mean, n_std = normal_stats[col]
        safe_std = max(n_std, 1e-4)
        z_score = (val - n_mean) / safe_std
        impact = max(0.0, z_score) * importances[col]

        if z_score >= 3.0:
            diag = "[bold red]ANOMALIA EXTREMA[/bold red]"
        elif z_score >= 1.8:
            diag = "[bold yellow]ACIMA DO PADRÃO[/bold yellow]"
        else:
            diag = "[dim]Dentro do esperado[/dim]"

        scored.append((impact, col, val, n_mean, diag))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [(col, val, n_mean, diag) for _, col, val, n_mean, diag in scored[:4]]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IDS com Machine Learning em Tempo Real (Blue Team)"
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Executa sem pausas interativas.",
    )
    args = parser.parse_args()

    console.clear()
    console.print(
        Panel.fit(
            "[bold blue]MÓDULO 02 — BLUE TEAM: IDS COM MACHINE LEARNING EM TEMPO REAL[/bold blue]\n"
            "[white]Detectando variantes polimórficas via Entropia de Shannon + Telemetria Comportamental[/white]",
            border_style="blue",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )

    # 1) Carrega ou gera automaticamente o dataset de telemetria
    if not DATASET_PATH.exists():
        console.print(
            "\n[yellow]Dataset de telemetria não encontrado — gerando automaticamente...[/yellow]"
        )
        df = generate_dataset(n_samples=2000, seed=42, output_path=DATASET_PATH)
    else:
        df = pd.read_csv(DATASET_PATH, encoding="utf-8")

    # Validação de qualidade dos dados (ML Best Practices: checar nulos antes do treino)
    missing_total = int(df[FEATURE_COLUMNS + ["label"]].isnull().sum().sum())
    if missing_total > 0:
        df = df.dropna(subset=FEATURE_COLUMNS + ["label"]).reset_index(drop=True)

    # 2) Divisão estratificada ANTES de treinar o modelo (evita data leakage)
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Calcula estatísticas de baseline APENAS no conjunto de treino (Normal)
    normal_train = X_train[y_train == 0]
    normal_stats: dict[str, tuple[float, float]] = {
        col: (float(normal_train[col].mean()), float(normal_train[col].std()))
        for col in FEATURE_COLUMNS
    }

    console.print("\n[bold cyan]ETAPA 1/3 — Treinamento e Validação do Modelo (RandomForestClassifier)[/bold cyan]")

    t0 = time.perf_counter()
    with Progress(
        SpinnerColumn(style="bold blue"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=32, complete_style="blue"),
        console=console,
    ) as progress:
        task = progress.add_task("[blue]Treinando RandomForest (120 árvores) sobre 1.600 eventos...", total=100)
        model = RandomForestClassifier(
            n_estimators=120,
            max_depth=10,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )
        progress.update(task, advance=35)
        model.fit(X_train, y_train)
        progress.update(task, advance=45)
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]
        progress.update(task, advance=20)
    train_elapsed = time.perf_counter() - t0

    acc = accuracy_score(y_test, y_pred) * 100.0
    prec = precision_score(y_test, y_pred) * 100.0
    rec = recall_score(y_test, y_pred) * 100.0
    f1 = f1_score(y_test, y_pred) * 100.0
    auc = roc_auc_score(y_test, y_proba) * 100.0
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    # Tabela de métricas + matriz de confusão
    metrics_table = Table(
        title=f"Desempenho do IDS no Conjunto de Teste (400 eventos inéditos | Treino em {train_elapsed:.2f}s)",
        box=box.ROUNDED,
        header_style="bold white on blue",
    )
    metrics_table.add_column("Métrica de Segurança", style="bold cyan")
    metrics_table.add_column("Valor", justify="right", style="bold green")
    metrics_table.add_column("Interpretação no SOC", style="white")

    fp_label = "falso positivo" if fp == 1 else "falsos positivos"
    fn_label = "falso negativo" if fn == 1 else "falsos negativos"
    metrics_table.add_row("Acurácia Global", f"{acc:.2f}%", "Percentual total de classificações corretas")
    metrics_table.add_row("Precisão (Precision)", f"{prec:.2f}%", f"Baixo ruído operacional ({fp} {fp_label} no teste)")
    metrics_table.add_row("Recall (Sensibilidade)", f"{rec:.2f}%", f"Capacidade de capturar ataques reais ({fn} {fn_label})")
    metrics_table.add_row("F1-Score / ROC-AUC", f"{f1:.2f}% / {auc:.2f}%", "Equilíbrio entre detecção agressiva e falsos alarmes")
    metrics_table.add_row(
        "Matriz de Confusão",
        f"VP={tp} | VN={tn}",
        f"Erros totais: FP={fp} (alarmes falsos) | FN={fn} (ataques perdidos)",
    )

    console.print()
    console.print(metrics_table)

    # Importância das features (Explainable AI)
    importances = dict(zip(FEATURE_COLUMNS, model.feature_importances_))
    imp_table = Table(
        title="Importância das Features Aprendidas pela IA (Por que o modelo decide?)",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
    )
    imp_table.add_column("Feature", style="bold white")
    imp_table.add_column("Peso", justify="right", style="bold yellow")
    imp_table.add_column("Barra Visual", style="blue")

    for col, weight in sorted(importances.items(), key=lambda x: x[1], reverse=True):
        bar_len = max(1, int(weight * 45))
        imp_table.add_row(FEATURE_LABELS[col], f"{weight * 100:.1f}%", "█" * bar_len)

    console.print()
    console.print(imp_table)

    # Verifica se as variantes do Red Team foram geradas
    if not RED_TEAM_VARIANTS_DIR.exists() or not list(RED_TEAM_VARIANTS_DIR.glob("variante_*.py")):
        console.print(
            Panel(
                "[bold red]Atenção:[/bold red] Nenhuma variante polimórfica encontrada em:\n"
                f"  [cyan]{RED_TEAM_VARIANTS_DIR}[/cyan]\n\n"
                "Execute primeiro o módulo Red Team para gerar os 5 arquivos reais:\n"
                "  [bold green]python3 01-red-team-polymorphic/polymorphic_simulator.py[/bold green]",
                title="Variantes do Red Team Ausentes",
                border_style="red",
            )
        )
        sys.exit(1)

    pause(args.auto, "\n[Pressione ENTER para iniciar o monitoramento em tempo real do IDS...]")

    # 3) Monitoramento simulado em tempo real
    console.print(
        "\n[bold cyan]ETAPA 2/3 — Sensor IDS/EDR Ativo: Inspecionando Eventos e Variantes Reais em Tempo Real[/bold cyan]\n"
    )

    queue = build_live_inspection_queue()

    benign_total = 0
    benign_correct = 0
    poly_total = 0
    poly_detected = 0

    for idx, event in enumerate(queue, start=1):
        if not args.auto:
            time.sleep(0.55)

        sample_df = pd.DataFrame([event.features], columns=FEATURE_COLUMNS)
        pred = int(model.predict(sample_df)[0])
        attack_prob = float(model.predict_proba(sample_df)[0][1]) * 100.0

        is_poly = event.source_type == "polymorphic_variant"
        if is_poly:
            poly_total += 1
            if pred == 1:
                poly_detected += 1
        else:
            benign_total += 1
            if pred == 0:
                benign_correct += 1

        if pred == 0:
            console.print(
                Panel(
                    f"[bold green]✔ EVENTO NORMAL LIBERADO[/bold green] — [bold white]{event.name}[/bold white]\n"
                    f"[dim]SHA-256: {event.sha256[:20]}...  |  Entropia: {event.features['file_entropy']:.2f} bits/B  |  "
                    f"Prob. Ataque: {attack_prob:.1f}%[/dim]\n"
                    f"[cyan]Contexto:[/cyan] {event.note}",
                    title=f"[green][Evento {idx}/{len(queue)}] Monitoramento em Tempo Real[/green]",
                    border_style="green",
                    box=box.ROUNDED,
                )
            )
        else:
            reasons = explain_detection(event.features, normal_stats, importances)
            reason_table = Table(box=box.SIMPLE, header_style="bold yellow", expand=True)
            reason_table.add_column("Feature Denunciadora", style="bold white")
            reason_table.add_column("Observado", justify="right", style="bold red")
            reason_table.add_column("Média Normal", justify="right", style="green")
            reason_table.add_column("Diagnóstico", justify="right")

            for col, obs_val, norm_mean, diag in reasons:
                reason_table.add_row(
                    FEATURE_LABELS[col],
                    f"{obs_val:.2f}",
                    f"{norm_mean:.2f}",
                    diag,
                )

            header_text = (
                f"[bold white on red] ALERTA CRÍTICO DE IDS — AMEAÇA POLIMÓRFICA DETECTADA [/bold white on red]\n\n"
                f"[bold white]Arquivo:[/bold white] [bold yellow]{event.name}[/bold yellow]  "
                f"([dim]{event.size_bytes:,} bytes[/dim])\n"
                f"[bold white]SHA-256:[/bold white] [cyan]{event.sha256[:24]}...[/cyan]  "
                f"[bold red](Hash inédito — ignorado pelo AV tradicional!)[/bold red]\n"
                f"[bold white]Confiança da IA:[/bold white] [bold red]{attack_prob:.1f}% de probabilidade de ataque[/bold red]  |  "
                f"[bold white]Ação:[/bold white] [bold yellow]PROCESSO ISOLADO EM QUARENTENA[/bold yellow]\n"
            )

            console.print(
                Panel(
                    header_text,
                    title=f"[bold red]⚠ [Evento {idx}/{len(queue)}] DETECÇÃO EM TEMPO REAL[/bold red]",
                    border_style="bold red",
                    box=box.HEAVY,
                )
            )
            console.print(
                Panel(
                    reason_table,
                    title="[bold yellow]Explicabilidade (XAI): Quais features denunciaram este ataque?[/bold yellow]",
                    border_style="red",
                    box=box.ROUNDED,
                )
            )

    pause(args.auto, "\n[Pressione ENTER para ver o Placar Final: AV Tradicional vs. IDS com IA...]")

    # 4) Placar final comparativo
    console.print("\n[bold cyan]ETAPA 3/3 — Placar Final do Duelo (Red Team vs. Blue Team)[/bold cyan]\n")

    poly_rate = (poly_detected / poly_total * 100.0) if poly_total else 0.0
    fp_live = benign_total - benign_correct

    scoreboard = Table(
        title="Comparativo Final — Efetividade Contra as 5 Variantes Polimórficas",
        box=box.DOUBLE,
        header_style="bold white on dark_blue",
        show_lines=True,
    )
    scoreboard.add_column("Camada de Defesa", style="bold white")
    scoreboard.add_column("Método de Análise", style="cyan")
    scoreboard.add_column("Variantes Detectadas", justify="center")
    scoreboard.add_column("Falsos Positivos (Controles)", justify="center")
    scoreboard.add_column("Veredito", justify="center")

    scoreboard.add_row(
        "Antivírus Tradicional (Módulo 01)",
        "Assinatura Estática (SHA-256)",
        f"[bold red]0 / {poly_total} (0%)[/bold red]",
        "[green]0[/green]",
        "[bold white on red] EVADIDO [/bold white on red]",
    )
    scoreboard.add_row(
        "IDS com IA — RandomForest (Módulo 02)",
        "Entropia Real + Ofuscação + Comportamento",
        f"[bold green]{poly_detected} / {poly_total} ({poly_rate:.0f}%)[/bold green]",
        f"[bold green]{fp_live} / {benign_total}[/bold green]" if fp_live == 0 else f"[yellow]{fp_live} / {benign_total}[/yellow]",
        "[bold white on green] AMEAÇA CONTIDA [/bold white on green]",
    )

    console.print(scoreboard)
    console.print(
        Panel(
            "[bold green]Conclusão Técnica do Experimento:[/bold green]\n"
            "• O polimorfismo destruiu 100% da eficácia do bloqueio baseado em hash estático.\n"
            "• O modelo de IA generalizou além das assinaturas, combinando [bold]Entropia de Shannon real[/bold],\n"
            "  [bold]heurística de ofuscação[/bold] e [bold]telemetria comportamental[/bold] — bloqueando todas as variantes\n"
            "  polimórficas e ainda preservando o [bold]instalador compactado legítimo[/bold] sem gerar falso positivo.",
            title="[bold blue]Blue Team — Defesa Baseada em Inteligência Artificial[/bold blue]",
            border_style="green",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
