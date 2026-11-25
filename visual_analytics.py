#!/usr/bin/env python3
"""
AI Cyber Duel — Módulo de Visual Analytics (Terminal Rich + Dashboard PNG)
==========================================================================
Gera elementos gráficos de alto impacto para apresentação em sala de aula:
  1. Gráficos de barras visuais em Unicode/ASCII diretamente no terminal (Rich):
     - Entropia de Shannon (Código Original vs. Variantes Polimórficas/AST vs. Limiar)
     - Taxa de Detecção (AV Tradicional SHA-256 vs. Ensemble IA)
     - Importância das Features (XAI) do RandomForest
  2. Dashboard gráfico em alta resolução (dashboard_soc.png, tema dark mode SOC)
     com 3 subplots:
     - Curva ROC + Matriz de Confusão do IDS RandomForest
     - Distribuição de Entropia (Normal vs. Ataque + Amostras Reais + Limiar)
     - Latência de Inferência por Onda AST (ms) + Taxa de Detecção

Compatível com Linux Mint, Windows e GitHub Codespaces (Python 3.10+, backend Agg).

Uso:
  python3 visual_analytics.py
  python3 visual_analytics.py --auto
  python3 visual_analytics.py --no-open
"""

from __future__ import annotations

import argparse
import ast
import base64
import importlib.util
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# Garante diretório gravável de cache do Matplotlib em laboratórios restritos
if not os.environ.get("MPLCONFIGDIR"):
    _mpl_cache = Path(tempfile.gettempdir()) / "ai_cyber_duel_mpl"
    try:
        _mpl_cache.mkdir(parents=True, exist_ok=True)
        os.environ["MPLCONFIGDIR"] = str(_mpl_cache)
    except OSError:
        pass

import matplotlib

# Backend headless seguro (evita erro de Tkinter ausente no Linux Mint / Codespaces)
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

ROOT_DIR = Path(__file__).resolve().parent
RED_DIR = ROOT_DIR / "01-red-team-polymorphic"
BLUE_DIR = ROOT_DIR / "02-blue-team-realtime-ids"
VARIANTS_DIR = RED_DIR / "generated_variants"
REPORT_PATH = ROOT_DIR / "RELATORIO_INCIDENTE_SOC.md"
DASHBOARD_PATH = ROOT_DIR / "dashboard_soc.png"

ENTROPY_ALERT_THRESHOLD = 5.50

# Paleta Dark Mode SOC de alto contraste para projetor
SOC_BG = "#0d1117"
SOC_CARD = "#161b22"
SOC_GRID = "#30363d"
SOC_TEXT = "#f0f6fc"
SOC_MUTED = "#8b949e"
SOC_CYAN = "#38bdf8"
SOC_GREEN = "#22c55e"
SOC_AMBER = "#f59e0b"
SOC_RED = "#ef4444"
SOC_PURPLE = "#a855f7"


@dataclass
class WaveMetric:
    label: str
    filename: str
    technique: str
    entropy: float
    ast_nodes: int
    ai_score_pct: float
    latency_ms: float
    detected: bool


@dataclass
class AnalyticsBundle:
    # Modelo IDS (RandomForest)
    fpr: np.ndarray
    tpr: np.ndarray
    roc_auc: float
    accuracy_pct: float
    f1_pct: float
    tn: int
    fp: int
    fn: int
    tp: int
    feature_importances: list[tuple[str, float]]
    normal_entropies: np.ndarray
    attack_entropies: np.ndarray
    # Amostras reais (polimórfico + AST)
    original_entropy: float
    poly_samples: list[tuple[str, float, str]]
    wave_metrics: list[WaveMetric]
    wave_source: str
    av_detection_pct: float
    ai_detection_pct: float


def compute_shannon_entropy(data: bytes) -> float:
    """Calcula a Entropia de Shannon em bits/byte (0.0 a 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Não foi possível carregar o módulo {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _compact_wave_label(filename: str) -> str:
    stem = Path(filename).stem
    parts = stem.split("_")
    if len(parts) == 4 and parts[0] == "wave" and parts[2] == "variant":
        return f"W{parts[1]}-V{parts[3]}"
    return stem[:10]


def _parse_soc_report(report_path: Path) -> list[WaveMetric]:
    """Extrai métricas reais de ondas AST a partir do RELATORIO_INCIDENTE_SOC.md."""
    if not report_path.exists():
        return []

    rows: list[WaveMetric] = []
    pattern = re.compile(
        r"^\|\s*(wave_[^|\s]+)\s*\|\s*([^|]+?)\s*\|\s*([0-9.]+)\s*\|\s*(\d+)\s*\|\s*([0-9.]+)%\s*\|\s*([0-9.]+)\s*ms\s*\|\s*([^|]+?)\s*\|$"
    )
    for line in report_path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        fname, tech, ent, nodes, score, lat, action = match.groups()
        rows.append(
            WaveMetric(
                label=_compact_wave_label(fname),
                filename=fname,
                technique=tech.strip(),
                entropy=float(ent),
                ast_nodes=int(nodes),
                ai_score_pct=float(score),
                latency_ms=float(lat),
                detected="QUARENTENA" in action.upper(),
            )
        )
    return rows


def _benchmark_ast_waves_in_memory() -> list[WaveMetric]:
    """
    Caso a Arena Ao Vivo ainda não tenha sido executada, gera 10 ondas AST reais
    em memória (sem sobrescrever generated_variants/) e mede latência real de
    inferência com o Ensemble defensivo (RandomForest + IsolationForest).
    """
    ast_mod = _load_module("ast_transform_engine_va", RED_DIR / "ast_transform_engine.py")
    arena_mod = _load_module("arena_duel_live_va", ROOT_DIR / "arena_duel_live.py")
    rf_model, iso_model = arena_mod.train_hybrid_defense()

    results: list[WaveMetric] = []
    for wave_id in range(1, 6):
        for variant_idx in range(1, 3):
            seed = wave_id * 100 + variant_idx
            tree = ast.parse(ast_mod.WORKLOAD_TEMPLATE)
            mutator = ast_mod.StructuralMutator(seed=seed)
            mutated_tree = mutator.visit(tree)

            imports = [n for n in mutated_tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
            funcs = [n for n in mutated_tree.body if isinstance(n, ast.FunctionDef)]
            others = [
                n for n in mutated_tree.body
                if not isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))
            ]
            mutator.rng.shuffle(funcs)
            mutated_tree.body = imports + funcs + others
            ast.fix_missing_locations(mutated_tree)
            mutated_source = ast.unparse(mutated_tree)

            if wave_id % 2 == 0:
                compressed = zlib.compress(mutated_source.encode("utf-8"), level=9)
                encoded = base64.b85encode(compressed).decode("ascii")
                final_code = (
                    "import base64, zlib\n"
                    f"_b = {encoded!r}\n"
                    "exec(compile(zlib.decompress(base64.b85decode(_b)), '<ast_wave>', 'exec'))\n"
                )
                technique = "AST Shuffle + For->While + Zlib/Base85"
            else:
                final_code = mutated_source
                technique = "AST Shuffle + For->While + Opaque Predicates"

            raw_bytes = final_code.encode("utf-8")
            t0 = time.perf_counter()
            entropy = compute_shannon_entropy(raw_bytes)
            parsed = ast.parse(final_code)
            ast_nodes = sum(1 for _ in ast.walk(parsed))
            has_exec = int(any(isinstance(n, ast.Name) and n.id == "exec" for n in ast.walk(parsed)))
            vec = np.array([[entropy, ast_nodes, has_exec, 16.0, 1]])
            prob_attack = float(rf_model.predict_proba(vec)[0][1])
            iso_flag = int(iso_model.predict(vec)[0]) == -1
            latency_ms = (time.perf_counter() - t0) * 1000.0

            fname = f"wave_{wave_id:02d}_variant_{variant_idx:02d}.py"
            results.append(
                WaveMetric(
                    label=f"W{wave_id:02d}-V{variant_idx:02d}",
                    filename=fname,
                    technique=technique,
                    entropy=round(entropy, 4),
                    ast_nodes=ast_nodes,
                    ai_score_pct=round(prob_attack * 100.0, 1),
                    latency_ms=round(latency_ms, 2),
                    detected=(prob_attack >= 0.5 or iso_flag),
                )
            )
    return results


def collect_analytics() -> AnalyticsBundle:
    """Coleta métricas reais do IDS RandomForest, das variantes polimórficas e das ondas AST."""
    tel_mod = _load_module("generate_telemetry_data_va", BLUE_DIR / "generate_telemetry_data.py")
    poly_mod = _load_module("polymorphic_simulator_va", RED_DIR / "polymorphic_simulator.py")

    if tel_mod.DATASET_PATH.exists():
        df = pd.read_csv(tel_mod.DATASET_PATH, encoding="utf-8")
    else:
        df = tel_mod.generate_dataset(n_samples=2000, seed=42, output_path=tel_mod.DATASET_PATH)

    feature_cols: list[str] = list(tel_mod.FEATURE_COLUMNS)
    feature_labels: dict[str, str] = dict(tel_mod.FEATURE_LABELS)
    df = df.dropna(subset=feature_cols + ["label"]).reset_index(drop=True)

    X = df[feature_cols]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=10,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc_val = float(roc_auc_score(y_test, y_proba))
    acc_pct = float(accuracy_score(y_test, y_pred) * 100.0)
    f1_pct = float(f1_score(y_test, y_pred) * 100.0)
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y_test, y_pred).ravel())

    importances = sorted(
        [(feature_labels[col], float(w)) for col, w in zip(feature_cols, model.feature_importances_)],
        key=lambda item: item[1],
        reverse=True,
    )

    # Entropia do payload original e das variantes polimórficas reais (em disco ou em memória)
    original_entropy = compute_shannon_entropy(poly_mod.ORIGINAL_PAYLOAD_SOURCE.encode("utf-8"))
    poly_samples: list[tuple[str, float, str]] = [
        ("payload_original.py", original_entropy, "original"),
    ]

    disk_variants = sorted(VARIANTS_DIR.glob("variante_*.py")) if VARIANTS_DIR.exists() else []
    if disk_variants:
        for vpath in disk_variants:
            ent = compute_shannon_entropy(vpath.read_bytes())
            short = vpath.stem.replace("variante_", "Var ")
            poly_samples.append((short, ent, "poly"))
    else:
        builders = [
            poly_mod.build_variant_01_xor_basico,
            poly_mod.build_variant_02_junk_renomeacao,
            poly_mod.build_variant_03_xor_multichave,
            poly_mod.build_variant_04_zlib_xor_camadas,
            poly_mod.build_variant_05_polimorfismo_total,
        ]
        for builder in builders:
            fname, _, src = builder()
            ent = compute_shannon_entropy(src.encode("utf-8"))
            short = Path(fname).stem.replace("variante_", "Var ")
            poly_samples.append((short, ent, "poly"))

    # Ondas AST reais do RELATORIO_INCIDENTE_SOC.md ou benchmark instantâneo
    wave_metrics = _parse_soc_report(REPORT_PATH)
    if wave_metrics:
        wave_source = f"Dados reais de {REPORT_PATH.name}"
    else:
        wave_metrics = _benchmark_ast_waves_in_memory()
        wave_source = "Benchmark real em memória (5 ondas AST x 2 variantes)"

    # Inclui representantes AST (Opaque e Zlib/Base85) no comparativo de entropia
    ast_opaque = [w.entropy for w in wave_metrics if "Opaque" in w.technique]
    ast_zlib = [w.entropy for w in wave_metrics if "Zlib" in w.technique]
    if ast_opaque:
        poly_samples.append(("AST Opaque (média)", float(np.mean(ast_opaque)), "ast_low"))
    if ast_zlib:
        poly_samples.append(("AST Zlib+B85 (média)", float(np.mean(ast_zlib)), "ast_high"))

    ai_det_pct = (
        (sum(1 for w in wave_metrics if w.detected) / len(wave_metrics)) * 100.0
        if wave_metrics
        else 100.0
    )

    return AnalyticsBundle(
        fpr=fpr,
        tpr=tpr,
        roc_auc=auc_val,
        accuracy_pct=acc_pct,
        f1_pct=f1_pct,
        tn=tn,
        fp=fp,
        fn=fn,
        tp=tp,
        feature_importances=importances,
        normal_entropies=df.loc[df["label"] == 0, "file_entropy"].to_numpy(dtype=float),
        attack_entropies=df.loc[df["label"] == 1, "file_entropy"].to_numpy(dtype=float),
        original_entropy=original_entropy,
        poly_samples=poly_samples,
        wave_metrics=wave_metrics,
        wave_source=wave_source,
        av_detection_pct=0.0,
        ai_detection_pct=ai_det_pct,
    )


def _ascii_bar(value: float, max_value: float, width: int, color: str, marker_at: float | None = None) -> str:
    """Constroi barra horizontal em blocos Unicode com suporte a marcador de limiar."""
    safe_max = max(max_value, 1e-6)
    ratio = min(1.0, max(0.0, value / safe_max))
    filled = int(round(ratio * width))
    marker_pos = None
    if marker_at is not None:
        marker_pos = min(width - 1, max(0, int(round((marker_at / safe_max) * width))))

    chars: list[str] = []
    for idx in range(width):
        if marker_pos is not None and idx == marker_pos:
            chars.append("[bold yellow]│[/bold yellow]")
        elif idx < filled:
            chars.append(f"[{color}]█[/{color}]")
        else:
            chars.append("[dim]░[/dim]")
    return "".join(chars)


def render_terminal_charts(bundle: AnalyticsBundle, target_console: Console | None = None) -> None:
    """Renderiza os 3 gráficos comparativos em ASCII/Unicode no terminal usando Rich."""
    out = target_console if target_console is not None else console
    term_w = out.size.width
    wide = term_w >= 136
    bar_w = 22 if wide else max(14, min(30, term_w - 46))

    out.print(
        Panel.fit(
            "[bold cyan]📊 VISUAL ANALYTICS — PAINEL GRÁFICO SOC (TERMINAL + PNG)[/bold cyan]\n"
            f"[white]Origem das Ondas AST:[/white] [yellow]{bundle.wave_source}[/yellow]  |  "
            f"[white]ROC-AUC IDS:[/white] [bold green]{bundle.roc_auc * 100:.2f}%[/bold green]  |  "
            f"[white]Acurácia:[/white] [bold green]{bundle.accuracy_pct:.2f}%[/bold green]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    # 1) Gráfico de Entropia de Shannon (Original vs. Variantes vs. Limiar)
    ent_table = Table(
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
        expand=True,
    )
    ent_table.add_column("Amostra", style="bold white", no_wrap=True, overflow="ellipsis")
    ent_table.add_column("Entropia (0–8 bits/B | │ = 5.50)", no_wrap=True)
    ent_table.add_column("Valor", justify="right", no_wrap=True)

    for label, ent_val, kind in bundle.poly_samples:
        if kind == "original":
            color = "bold green"
        elif kind == "ast_low":
            color = "bold yellow"
        elif ent_val >= ENTROPY_ALERT_THRESHOLD:
            color = "bold red"
        else:
            color = "bold cyan"
        bar = _ascii_bar(ent_val, 8.0, bar_w, color, marker_at=ENTROPY_ALERT_THRESHOLD)
        ent_table.add_row(label[:20], bar, f"[{color}]{ent_val:.2f}[/{color}]")

    ent_panel = Panel(
        ent_table,
        title="[bold cyan]1. Entropia de Shannon vs. Limiar de Alerta (│ 5.50)[/bold cyan]",
        subtitle="[dim]Verde: normal | Amarelo: AST furtivo (exige telemetria SO) | Vermelho: ofuscado[/dim]",
        border_style="cyan",
    )

    # 2) Gráfico de Taxa de Detecção (AV Tradicional vs. Ensemble IA)
    det_table = Table(box=box.SIMPLE_HEAD, padding=(0, 1), expand=True)
    det_table.add_column("Defesa", style="bold white", no_wrap=True)
    det_table.add_column("Taxa de Detecção (0–100%)", no_wrap=True)
    det_table.add_column("Score", justify="right", no_wrap=True)

    det_bar_w = bar_w if not wide else 20
    det_table.add_row(
        "AV Estático (SHA-256)",
        _ascii_bar(bundle.av_detection_pct, 100.0, det_bar_w, "bold red"),
        f"[bold red]{bundle.av_detection_pct:.1f}%[/bold red]",
    )
    det_table.add_row(
        "IDS RandomForest",
        _ascii_bar(bundle.accuracy_pct, 100.0, det_bar_w, "bold blue"),
        f"[bold blue]{bundle.accuracy_pct:.1f}%[/bold blue]",
    )
    det_table.add_row(
        "Ensemble IA + SOAR",
        _ascii_bar(bundle.ai_detection_pct, 100.0, det_bar_w, "bold green"),
        f"[bold green]{bundle.ai_detection_pct:.1f}%[/bold green]",
    )

    det_panel = Panel(
        det_table,
        title="[bold green]2. Taxa de Detecção: AV SHA-256 vs. Ensemble IA[/bold green]",
        subtitle=f"[dim]Matriz Teste IDS: VP={bundle.tp} | VN={bundle.tn} | FP={bundle.fp} | FN={bundle.fn}[/dim]",
        border_style="green",
    )

    # 3) Gráfico de Importância das Features (XAI — RandomForest)
    xai_table = Table(box=box.SIMPLE_HEAD, padding=(0, 1), expand=True)
    xai_table.add_column("Feature Comportamental / Estática", style="bold white", overflow="ellipsis")
    xai_table.add_column("Peso Relativo (XAI)", no_wrap=True)
    xai_table.add_column("%", justify="right", style="bold yellow", no_wrap=True)

    max_imp = max((w for _, w in bundle.feature_importances), default=1.0)
    xai_bar_w = max(16, min(32, term_w - 50))
    for feat_label, weight in bundle.feature_importances:
        color = "bold magenta" if weight >= max_imp * 0.7 else "bold cyan"
        xai_table.add_row(
            feat_label,
            _ascii_bar(weight, max_imp, xai_bar_w, color),
            f"{weight * 100:.1f}%",
        )

    xai_panel = Panel(
        xai_table,
        title="[bold magenta]3. Importância das Features (XAI — RandomForest)[/bold magenta]",
        subtitle="[dim]Quais sinais estatísticos e de SO mais pesaram na decisão da IA[/dim]",
        border_style="magenta",
    )

    out.print()
    if wide:
        out.print(Columns([ent_panel, det_panel], equal=True, expand=True))
    else:
        out.print(ent_panel)
        out.print(det_panel)
    out.print(xai_panel)


def export_soc_dashboard_png(bundle: AnalyticsBundle, output_path: Path = DASHBOARD_PATH) -> Path:
    """Exporta dashboard_soc.png em alta resolução com tema Dark Mode estilo SOC (3 subplots)."""
    plt.rcParams.update(
        {
            "figure.facecolor": SOC_BG,
            "axes.facecolor": SOC_CARD,
            "axes.edgecolor": SOC_GRID,
            "axes.labelcolor": SOC_TEXT,
            "xtick.color": SOC_MUTED,
            "ytick.color": SOC_MUTED,
            "text.color": SOC_TEXT,
            "grid.color": SOC_GRID,
            "grid.alpha": 0.45,
            "font.family": "DejaVu Sans",
        }
    )

    fig, axes = plt.subplots(1, 3, figsize=(18.5, 6.4), dpi=180)
    fig.patch.set_facecolor(SOC_BG)

    # Banner superior
    fig.suptitle(
        "AI CYBER DUEL — SOC VISUAL ANALYTICS DASHBOARD (RED TEAM AST vs. BLUE TEAM IA)",
        fontsize=15,
        fontweight="bold",
        color=SOC_TEXT,
        y=0.97,
    )
    fig.text(
        0.5,
        0.915,
        f"RandomForest ROC-AUC: {bundle.roc_auc * 100:.2f}%  |  Acurácia: {bundle.accuracy_pct:.2f}%  |  "
        f"AV Estático (SHA-256): {bundle.av_detection_pct:.0f}%  vs.  Ensemble IA: {bundle.ai_detection_pct:.0f}%",
        ha="center",
        fontsize=10.5,
        color=SOC_CYAN,
        fontweight="bold",
    )

    # ------------------------------------------------------------------
    # SUBPLOT 1: Curva ROC + Inset da Matriz de Confusão
    # ------------------------------------------------------------------
    ax1 = axes[0]
    ax1.plot(
        bundle.fpr,
        bundle.tpr,
        color=SOC_CYAN,
        linewidth=2.6,
        label=f"RandomForest IDS (AUC = {bundle.roc_auc:.4f})",
    )
    ax1.fill_between(bundle.fpr, bundle.tpr, alpha=0.18, color=SOC_CYAN)
    ax1.plot([0, 1], [0, 1], linestyle="--", color=SOC_MUTED, linewidth=1.2, label="Classificador Aleatório")
    ax1.set_title("1. Curva ROC & Matriz de Confusão", fontsize=12, fontweight="bold", pad=10, color=SOC_TEXT)
    ax1.set_xlabel("Taxa de Falsos Positivos (FPR)", fontsize=10)
    ax1.set_ylabel("Taxa de Verdadeiros Positivos (TPR)", fontsize=10)
    ax1.set_xlim(-0.02, 1.02)
    ax1.set_ylim(-0.02, 1.05)
    ax1.grid(True, linestyle=":")
    ax1.legend(loc="lower right", bbox_to_anchor=(0.99, 0.49), facecolor=SOC_BG, edgecolor=SOC_GRID, fontsize=8.5)

    # Inset com Matriz de Confusão real (2x2)
    inset = ax1.inset_axes([0.52, 0.06, 0.44, 0.34])
    cm_mat = np.array([[bundle.tn, bundle.fp], [bundle.fn, bundle.tp]])
    inset.imshow(cm_mat, cmap="Blues", aspect="auto", alpha=0.92)
    inset.set_xticks([0, 1])
    inset.set_yticks([0, 1])
    inset.set_xticklabels(["Pred: 0", "Pred: 1"], fontsize=7.5, color=SOC_TEXT)
    inset.set_yticklabels(["Real: 0", "Real: 1"], fontsize=7.5, color=SOC_TEXT)
    inset.set_title("Matriz de Confusão", fontsize=8.5, color=SOC_AMBER, pad=4, fontweight="bold")
    cm_labels = [[f"VN\n{bundle.tn}", f"FP\n{bundle.fp}"], [f"FN\n{bundle.fn}", f"VP\n{bundle.tp}"]]
    for r in range(2):
        for c in range(2):
            val = cm_mat[r, c]
            txt_color = SOC_TEXT if val > cm_mat.max() * 0.45 else "#0d1117"
            inset.text(c, r, cm_labels[r][c], ha="center", va="center", fontsize=8.5, fontweight="bold", color=txt_color)

    # ------------------------------------------------------------------
    # SUBPLOT 2: Distribuição de Entropia (Normal vs. Ataque + Amostras)
    # ------------------------------------------------------------------
    ax2 = axes[1]
    bins = np.linspace(2.2, 8.0, 28)
    ax2.hist(
        bundle.normal_entropies,
        bins=bins,
        alpha=0.58,
        color=SOC_GREEN,
        edgecolor=SOC_BG,
        label="Normal / Legítimo",
        density=True,
    )
    ax2.hist(
        bundle.attack_entropies,
        bins=bins,
        alpha=0.58,
        color=SOC_RED,
        edgecolor=SOC_BG,
        label="Ataque Polimórfico",
        density=True,
    )
    ax2.axvline(
        ENTROPY_ALERT_THRESHOLD,
        color=SOC_AMBER,
        linestyle="--",
        linewidth=2.0,
        label=f"Limiar Alerta ({ENTROPY_ALERT_THRESHOLD:.2f})",
    )
    ax2.axvline(
        bundle.original_entropy,
        color=SOC_CYAN,
        linestyle="-.",
        linewidth=1.6,
        label=f"Original ({bundle.original_entropy:.2f})",
    )

    ast_opaque_vals = [w.entropy for w in bundle.wave_metrics if "Opaque" in w.technique]
    ast_zlib_vals = [w.entropy for w in bundle.wave_metrics if "Zlib" in w.technique]
    y_top = ax2.get_ylim()[1]
    if ast_opaque_vals:
        ax2.scatter(
            ast_opaque_vals,
            [y_top * 0.86] * len(ast_opaque_vals),
            color=SOC_AMBER,
            edgecolors=SOC_BG,
            s=58,
            zorder=5,
            label="Ondas AST Opaque",
        )
    if ast_zlib_vals:
        ax2.scatter(
            ast_zlib_vals,
            [y_top * 0.76] * len(ast_zlib_vals),
            color=SOC_PURPLE,
            edgecolors=SOC_BG,
            s=58,
            marker="D",
            zorder=5,
            label="Ondas AST Zlib/B85",
        )

    ax2.set_title("2. Distribuição de Entropia de Shannon", fontsize=12, fontweight="bold", pad=10, color=SOC_TEXT)
    ax2.set_xlabel("Entropia de Shannon (bits / byte)", fontsize=10)
    ax2.set_ylabel("Densidade Probabilística", fontsize=10)
    ax2.grid(True, linestyle=":")
    ax2.legend(loc="upper left", facecolor=SOC_BG, edgecolor=SOC_GRID, fontsize=8.0)

    # ------------------------------------------------------------------
    # SUBPLOT 3: Latência de Inferência por Onda AST (ms)
    # ------------------------------------------------------------------
    ax3 = axes[2]
    labels = [w.label for w in bundle.wave_metrics]
    latencies = [w.latency_ms for w in bundle.wave_metrics]
    bar_colors = [SOC_PURPLE if "Zlib" in w.technique else SOC_CYAN for w in bundle.wave_metrics]
    x_pos = np.arange(len(labels))

    bars = ax3.bar(x_pos, latencies, color=bar_colors, edgecolor=SOC_BG, width=0.66, alpha=0.90)
    avg_lat = float(np.mean(latencies)) if latencies else 0.0
    ax3.axhline(avg_lat, color=SOC_AMBER, linestyle="--", linewidth=1.8, label=f"Latência Média: {avg_lat:.2f} ms")

    for bar, lat_val in zip(bars, latencies):
        ax3.text(
            bar.get_x() + bar.get_width() / 2.0,
            bar.get_height() + max(0.3, max(latencies) * 0.02),
            f"{lat_val:.1f}",
            ha="center",
            va="bottom",
            fontsize=8.0,
            color=SOC_TEXT,
            fontweight="bold",
        )

    ax3.set_title("3. Latência de Inferência IA por Onda AST", fontsize=12, fontweight="bold", pad=10, color=SOC_TEXT)
    ax3.set_xlabel("Onda / Variante AST", fontsize=10)
    ax3.set_ylabel("Latência de Inferência (ms)", fontsize=10)
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(labels, rotation=32, ha="right", fontsize=8.5)
    ax3.set_ylim(0, max(latencies, default=10.0) * 1.24)
    ax3.grid(True, axis="y", linestyle=":")

    # Legenda clara das técnicas + média
    from matplotlib.patches import Patch

    legend_handles = [
        Patch(facecolor=SOC_CYAN, label="AST Opaque Predicates"),
        Patch(facecolor=SOC_PURPLE, label="AST + Zlib/Base85"),
        plt.Line2D([0], [0], color=SOC_AMBER, linestyle="--", linewidth=1.8, label=f"Média: {avg_lat:.2f} ms"),
    ]
    ax3.legend(handles=legend_handles, loc="upper right", facecolor=SOC_BG, edgecolor=SOC_GRID, fontsize=8.0)

    fig.tight_layout(rect=[0.01, 0.02, 0.99, 0.89])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=180, facecolor=SOC_BG)
    plt.close(fig)
    return output_path


def try_open_image(image_path: Path) -> tuple[bool, str]:
    """
    Tenta abrir dashboard_soc.png no visualizador nativo do SO sem travar o terminal.
    Retorna (abriu, comando_manual_sugerido).
    """
    if sys.platform == "win32":
        manual_cmd = f"start {image_path.name}"
        try:
            os.startfile(str(image_path))  # type: ignore[attr-defined]
            return True, manual_cmd
        except OSError:
            return False, manual_cmd

    if sys.platform == "darwin":
        manual_cmd = f"open {image_path.name}"
        if shutil.which("open"):
            try:
                subprocess.Popen(
                    ["open", str(image_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return True, manual_cmd
            except OSError:
                return False, manual_cmd
        return False, manual_cmd

    # Linux Mint / Desktop Linux
    manual_cmd = f"xdg-open {image_path.name}"
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if has_display and shutil.which("xdg-open"):
        try:
            subprocess.Popen(
                ["xdg-open", str(image_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True, manual_cmd
        except OSError:
            return False, manual_cmd
    return False, manual_cmd


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gera gráficos comparativos no terminal (Rich) e dashboard_soc.png (Dark Mode SOC)."
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Executa sem pausas e sem abrir janelas externas (ideal para testes e CI).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Salva dashboard_soc.png sem abrir automaticamente no visualizador de imagens.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DASHBOARD_PATH,
        help="Caminho de saída do PNG (padrão: dashboard_soc.png na raiz).",
    )
    args = parser.parse_args()

    console.clear()
    bundle = collect_analytics()
    render_terminal_charts(bundle)
    saved_path = export_soc_dashboard_png(bundle, output_path=args.output)
    size_kb = saved_path.stat().st_size / 1024.0

    opened = False
    manual_cmd = f"xdg-open {saved_path.name}" if sys.platform != "win32" else f"start {saved_path.name}"
    if not args.auto and not args.no_open:
        opened, manual_cmd = try_open_image(saved_path)

    status_line = (
        "[bold green]✔ Imagem aberta automaticamente no visualizador do sistema.[/bold green]"
        if opened
        else f"[yellow]Para projetar a imagem manualmente, execute:[/yellow] [bold white]{manual_cmd}[/bold white]"
    )

    console.print()
    console.print(
        Panel(
            f"[bold green]✔ Dashboard Dark Mode SOC exportado com sucesso![/bold green]\n"
            f"[white]Arquivo:[/white] [cyan]{saved_path}[/cyan]  ([dim]{size_kb:.1f} KB | 180 DPI[/dim])\n"
            f"[white]Subplots:[/white] Curva ROC + Matriz de Confusão  •  Distribuição de Entropia  •  Latência IA por Onda AST\n"
            f"{status_line}",
            title="[bold cyan]Exportação Gráfica em Alta Resolução[/bold cyan]",
            border_style="green",
            box=box.ROUNDED,
        )
    )


if __name__ == "__main__":
    main()
