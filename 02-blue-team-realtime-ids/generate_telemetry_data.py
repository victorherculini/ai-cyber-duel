#!/usr/bin/env python3
"""
AI Cyber Duel — Módulo 02 (Blue Team): Gerador de Telemetria Sintética
======================================================================
Gera um dataset rotulado simulando telemetria real de Sistema Operacional (EDR)
e Rede (NDR) para treinar o modelo de detecção de intrusões (IDS).

Inclui casos normais comuns, "negativos difíceis" (arquivos legítimos compactados
com alta entropia, porém comportamento limpo) e ataques polimórficos.

Uso:
  python3 02-blue-team-realtime-ids/generate_telemetry_data.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "telemetry_dataset.csv"

FEATURE_COLUMNS: list[str] = [
    "file_entropy",
    "obfuscation_score",
    "process_spawn_rate",
    "suspicious_api_calls",
    "anomalous_net_connections",
    "cpu_burst_ratio",
]

FEATURE_LABELS: dict[str, str] = {
    "file_entropy": "Entropia de Shannon (bits/B)",
    "obfuscation_score": "Score Heurístico de Ofuscação",
    "process_spawn_rate": "Taxa de Criação de Processos (/min)",
    "suspicious_api_calls": "Chamadas de API Suspeitas (/min)",
    "anomalous_net_connections": "Conexões de Rede Anômalas",
    "cpu_burst_ratio": "Pico de CPU no Desempacotamento (x)",
}


def generate_dataset(
    n_samples: int = 2000,
    seed: int = 42,
    output_path: Path = DATASET_PATH,
) -> pd.DataFrame:
    """
    Cria e salva o dataset sintético de telemetria SO/Rede balanceado e realista.
    Classes:
      0 -> Normal (inclui tráfego comum + instaladores compactados legítimos)
      1 -> Ataque Polimórfico (alta entropia/ofuscação + comportamento anômalo)
    """
    rng = np.random.default_rng(seed)

    n_attack = int(n_samples * 0.40)
    n_normal_total = n_samples - n_attack
    # ~10% dos casos normais simulam softwares legítimos compactados/minificados
    # (entropia mais alta, mas comportamento limpo — reduz falsos positivos!)
    n_normal_packed = int(n_normal_total * 0.10)
    n_normal_std = n_normal_total - n_normal_packed

    # 1) Tráfego e processos normais comuns (com variabilidade realista de ambiente corporativo)
    normal_std = pd.DataFrame(
        {
            "file_entropy": np.clip(rng.normal(4.35, 0.50, n_normal_std), 2.20, 5.45),
            "obfuscation_score": np.clip(rng.normal(0.22, 0.16, n_normal_std), 0.00, 0.72),
            "process_spawn_rate": np.clip(rng.normal(2.80, 2.10, n_normal_std), 0.00, 12.00),
            "suspicious_api_calls": np.clip(rng.normal(4.20, 3.60, n_normal_std), 0.00, 18.00),
            "anomalous_net_connections": np.clip(rng.normal(1.20, 1.40, n_normal_std), 0.00, 7.00),
            "cpu_burst_ratio": np.clip(rng.normal(1.85, 0.95, n_normal_std), 0.50, 5.20),
            "label": 0,
            "label_name": "Normal",
        }
    )

    # 2) Negativos difíceis: softwares legítimos compactados/criptografados (instaladores, ZIP)
    normal_packed = pd.DataFrame(
        {
            "file_entropy": np.clip(rng.normal(6.15, 0.45, n_normal_packed), 5.40, 7.40),
            "obfuscation_score": np.clip(rng.normal(0.25, 0.12, n_normal_packed), 0.05, 0.52),
            "process_spawn_rate": np.clip(rng.normal(2.60, 1.25, n_normal_packed), 0.20, 6.50),
            "suspicious_api_calls": np.clip(rng.normal(3.10, 1.80, n_normal_packed), 0.00, 9.00),
            "anomalous_net_connections": np.clip(rng.normal(0.65, 0.75, n_normal_packed), 0.00, 3.50),
            "cpu_burst_ratio": np.clip(rng.normal(2.15, 0.70, n_normal_packed), 0.80, 4.20),
            "label": 0,
            "label_name": "Normal",
        }
    )

    # 3) Ataques polimórficos (entropia elevada + ofuscação + telemetria comportamental anômala)
    attack = pd.DataFrame(
        {
            "file_entropy": np.clip(rng.normal(6.30, 0.45, n_attack), 5.55, 7.95),
            "obfuscation_score": np.clip(rng.normal(0.76, 0.16, n_attack), 0.30, 1.00),
            "process_spawn_rate": np.clip(rng.normal(10.50, 4.20, n_attack), 2.00, 26.00),
            "suspicious_api_calls": np.clip(rng.normal(19.50, 7.50, n_attack), 4.00, 48.00),
            "anomalous_net_connections": np.clip(rng.normal(6.80, 3.20, n_attack), 0.50, 19.00),
            "cpu_burst_ratio": np.clip(rng.normal(4.80, 1.65, n_attack), 1.60, 9.80),
            "label": 1,
            "label_name": "Ataque Polimórfico",
        }
    )

    df = pd.concat([normal_std, normal_packed, attack], ignore_index=True)

    # Injeta ~1.8% de casos limítrofes realistas (zonas cinzentas reais de SOC)
    n_noisy = max(1, int(len(df) * 0.018))
    noisy_idx = rng.choice(df.index.to_numpy(), size=n_noisy, replace=False)
    for idx in noisy_idx:
        if df.at[idx, "label"] == 0:
            df.at[idx, "file_entropy"] = float(rng.uniform(5.7, 6.6))
            df.at[idx, "obfuscation_score"] = float(rng.uniform(0.60, 0.85))
            df.at[idx, "process_spawn_rate"] = float(rng.uniform(8.0, 14.0))
            df.at[idx, "suspicious_api_calls"] = float(rng.uniform(14.0, 24.0))
            df.at[idx, "anomalous_net_connections"] = float(rng.uniform(4.5, 9.0))
            df.at[idx, "cpu_burst_ratio"] = float(rng.uniform(3.5, 6.2))
        else:
            df.at[idx, "file_entropy"] = float(rng.uniform(4.2, 5.2))
            df.at[idx, "obfuscation_score"] = float(rng.uniform(0.12, 0.35))
            df.at[idx, "process_spawn_rate"] = float(rng.uniform(1.0, 3.8))
            df.at[idx, "suspicious_api_calls"] = float(rng.uniform(1.5, 6.0))
            df.at[idx, "anomalous_net_connections"] = float(rng.uniform(0.0, 2.0))
            df.at[idx, "cpu_burst_ratio"] = float(rng.uniform(1.0, 2.5))

    # Arredonda colunas numéricas para legibilidade no CSV
    for col in ["file_entropy", "obfuscation_score", "process_spawn_rate", "cpu_burst_ratio"]:
        df[col] = df[col].round(3)
    for col in ["suspicious_api_calls", "anomalous_net_connections"]:
        df[col] = df[col].round(1)

    # Embaralha todas as linhas com semente fixa para reprodutibilidade
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False, encoding="utf-8")
    return df


def display_dataset_summary(df: pd.DataFrame, output_path: Path) -> None:
    """Exibe resumo estatístico do dataset no terminal usando Rich."""
    normal_df = df[df["label"] == 0]
    attack_df = df[df["label"] == 1]
    null_count = int(df.isnull().sum().sum())

    console.print(
        Panel.fit(
            "[bold blue]MÓDULO 02 — BLUE TEAM: GERADOR DE TELEMETRIA DE SEGURANÇA[/bold blue]\n"
            f"[white]Dataset gerado em:[/white] [cyan]{output_path}[/cyan]\n"
            f"[green]• Total de eventos:[/green] [bold white]{len(df):,}[/bold white]  |  "
            f"[green]Normal:[/green] [bold]{len(normal_df):,}[/bold]  |  "
            f"[red]Ataque Polimórfico:[/red] [bold]{len(attack_df):,}[/bold]  |  "
            f"[yellow]Valores Nulos:[/yellow] [bold]{null_count}[/bold]",
            border_style="blue",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )

    stats_table = Table(
        title="Perfil Estatístico das Features (Média ± Desvio Padrão)",
        box=box.ROUNDED,
        header_style="bold white on blue",
        show_lines=True,
    )
    stats_table.add_column("Feature de Telemetria", style="bold cyan")
    stats_table.add_column("Comportamento Normal", justify="right", style="green")
    stats_table.add_column("Ataque Polimórfico", justify="right", style="bold red")

    for col in FEATURE_COLUMNS:
        n_mean, n_std = normal_df[col].mean(), normal_df[col].std()
        a_mean, a_std = attack_df[col].mean(), attack_df[col].std()
        stats_table.add_row(
            FEATURE_LABELS[col],
            f"{n_mean:.2f} ± {n_std:.2f}",
            f"{a_mean:.2f} ± {a_std:.2f}",
        )

    console.print()
    console.print(stats_table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gera dataset sintético de telemetria SO/Rede para o IDS com IA."
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=2000,
        help="Número total de registros sintéticos (padrão: 2000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Semente aleatória para reprodutibilidade (padrão: 42).",
    )
    args = parser.parse_args()

    console.clear()
    df = generate_dataset(n_samples=args.samples, seed=args.seed, output_path=DATASET_PATH)
    display_dataset_summary(df, DATASET_PATH)
    console.print(
        "\n[bold green]✔ Dataset pronto![/bold green] Próximo comando:\n"
        "  [bold white]python3 02-blue-team-realtime-ids/train_and_detect_ids.py[/bold white]\n"
    )


if __name__ == "__main__":
    main()
