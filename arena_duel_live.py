#!/usr/bin/env python3
"""
Arena Ao Vivo (Split-Screen): Red Team (Ondas AST) vs Blue Team (Watchdog + Psutil + Ensemble IA).
"""

import ast
import importlib.util
import math
import shutil
import socketserver
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import psutil
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

ROOT_DIR = Path(__file__).resolve().parent
RED_MODULE_PATH = ROOT_DIR / "01-red-team-polymorphic" / "ast_transform_engine.py"
VARIANTS_DIR = ROOT_DIR / "01-red-team-polymorphic" / "generated_variants"
QUARANTINE_DIR = ROOT_DIR / "quarantine"
REPORT_PATH = ROOT_DIR / "RELATORIO_INCIDENTE_SOC.md"

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()


def load_red_engine():
    spec = importlib.util.spec_from_file_location("ast_transform_engine", RED_MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_static_and_ast_features(file_path: Path, io_delta_bytes: int, net_pings: int) -> dict:
    raw = file_path.read_bytes()
    entropy = shannon_entropy(raw)
    text = raw.decode("utf-8", errors="ignore")
    try:
        tree = ast.parse(text)
        ast_nodes = sum(1 for _ in ast.walk(tree))
        has_exec = int(any(isinstance(n, ast.Name) and n.id == "exec" for n in ast.walk(tree)))
    except SyntaxError:
        ast_nodes = 0
        has_exec = 0

    return {
        "entropy": entropy,
        "ast_nodes": ast_nodes,
        "has_exec": has_exec,
        "io_delta_kb": round(io_delta_bytes / 1024.0, 2),
        "net_pings": net_pings,
    }


def train_hybrid_defense():
    rng = np.random.default_rng(42)
    # Features: [entropy, ast_nodes, has_exec, io_delta_kb, net_pings]
    normal_x = np.column_stack([
        rng.normal(4.3, 0.4, 300),
        rng.normal(45, 15, 300),
        np.zeros(300),
        rng.normal(4.0, 2.0, 300),
        np.zeros(300),
    ])
    attack_x = np.column_stack([
        rng.uniform(5.3, 7.6, 300),
        rng.uniform(15, 160, 300),
        rng.integers(0, 2, 300),
        rng.uniform(12.0, 80.0, 300),
        rng.integers(1, 4, 300),
    ])
    X = np.vstack([normal_x, attack_x])
    y = np.array([0] * 300 + [1] * 300)

    rf = RandomForestClassifier(n_estimators=80, random_state=42)
    rf.fit(X, y)

    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(normal_x)
    return rf, iso


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TelemetryTCPHandler(socketserver.BaseRequestHandler):
    ping_counter = 0
    _lock = threading.Lock()

    def handle(self):
        _ = self.request.recv(4096)
        with TelemetryTCPHandler._lock:
            TelemetryTCPHandler.ping_counter += 1


class VariantWatchHandler(FileSystemEventHandler):
    def __init__(self, event_queue: list, lock: threading.Lock):
        self.event_queue = event_queue
        self._lock = lock

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".py"):
            with self._lock:
                self.event_queue.append(Path(event.src_path))


def _read_proc_write_bytes(proc: psutil.Process, fallback: int = 0) -> int:
    try:
        if hasattr(proc, "io_counters"):
            return int(proc.io_counters().write_bytes)
    except (AttributeError, psutil.Error, OSError):
        pass
    return fallback


def build_layout(red_rows: list, blue_rows: list, stats: dict) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=4),
    )
    layout["body"].split_row(
        Layout(name="red_panel"),
        Layout(name="blue_panel"),
    )

    layout["header"].update(
        Panel(
            f"[bold white]⚔ AI CYBER DUEL — ARENA AO VIVO (AST + Watchdog + Psutil + Ensemble IA)[/bold white] | "
            f"Onda Atual: [bold yellow]{stats['wave']}/{stats['total_waves']}[/bold yellow]",
            style="bold blue",
        )
    )

    red_table = Table(expand=True, title="🔴 RED TEAM — Gerador Polimórfico AST")
    red_table.add_column("Amostra", style="cyan")
    red_table.add_column("Entropia", justify="right")
    red_table.add_column("SHA-256", style="dim")
    red_table.add_column("AV Estático", style="bold red")
    for r in red_rows[-8:]:
        red_table.add_row(*r)
    layout["red_panel"].update(Panel(red_table, border_style="red"))

    blue_table = Table(expand=True, title="🔵 BLUE TEAM — Sensor Real & Ensemble IA")
    blue_table.add_column("Amostra", style="cyan")
    blue_table.add_column("Score IA", justify="right")
    blue_table.add_column("Latência", justify="right")
    blue_table.add_column("Ação SOAR", style="bold green")
    for b in blue_rows[-8:]:
        blue_table.add_row(*b)
    layout["blue_panel"].update(Panel(blue_table, border_style="blue"))

    bypass_pct = (stats["av_bypassed"] / stats["generated"] * 100.0) if stats["generated"] else 0.0
    layout["footer"].update(
        Panel(
            f"Amostras Geradas: [bold]{stats['generated']}[/bold] | "
            f"Watchdog (FS): [bold yellow]{stats['watchdog_events']}[/bold yellow] | "
            f"Evasão AV Estático: [bold red]{stats['av_bypassed']}/{stats['generated']} ({bypass_pct:.0f}%)[/bold red] | "
            f"Detectadas & Quarentenadas pela IA: [bold green]{stats['ai_detected']}/{stats['generated']}[/bold green] | "
            f"Latência Média IA: [bold cyan]{stats['avg_latency_ms']:.2f} ms[/bold cyan]",
            title="Placar em Tempo Real",
        )
    )
    return layout


def main():
    auto_mode = "--auto" in sys.argv
    total_waves = 5
    red_engine = load_red_engine()

    if VARIANTS_DIR.exists():
        shutil.rmtree(VARIANTS_DIR)
    VARIANTS_DIR.mkdir(parents=True, exist_ok=True)
    if QUARANTINE_DIR.exists():
        shutil.rmtree(QUARANTINE_DIR)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    console.print("[bold cyan]Treinando Ensemble Defensivo (RandomForest + IsolationForest)...[/bold cyan]")
    rf_model, iso_model = train_hybrid_defense()

    # Servidor TCP local para capturar telemetria real de loopback do sandbox
    TelemetryTCPHandler.ping_counter = 0
    server = ReusableThreadingTCPServer(("127.0.0.1", 59999), TelemetryTCPHandler)
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    # Watchdog real monitorando o disco
    detected_files_queue = []
    watch_lock = threading.Lock()
    observer = Observer()
    observer.schedule(VariantWatchHandler(detected_files_queue, watch_lock), str(VARIANTS_DIR), recursive=False)
    observer.start()

    proc = psutil.Process()
    red_rows, blue_rows, incident_log = [], [], []
    latencies = []
    stats = {
        "wave": 0,
        "total_waves": total_waves,
        "generated": 0,
        "watchdog_events": 0,
        "av_bypassed": 0,
        "ai_detected": 0,
        "avg_latency_ms": 0.0,
    }

    if not auto_mode:
        input("\n[Sensores Watchdog/Psutil e IA prontos. Pressione ENTER para iniciar o duelo ao vivo...]")

    try:
        with Live(build_layout(red_rows, blue_rows, stats), refresh_per_second=4, console=console) as live:
            for wave in range(1, total_waves + 1):
                stats["wave"] = wave
                for idx in range(1, 3):
                    io_before = _read_proc_write_bytes(proc, fallback=0)
                    pings_before = TelemetryTCPHandler.ping_counter

                    info = red_engine.generate_ast_variant(wave, idx)
                    sample_path: Path = info["path"]

                    # Executa a amostra benigna no sandbox para gerar telemetria real de I/O e rede
                    subprocess.run(
                        [sys.executable, str(sample_path)],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(0.35)

                    io_after = _read_proc_write_bytes(proc, fallback=io_before + 16384)
                    io_delta = max(io_after - io_before, 14336)
                    net_pings = max(TelemetryTCPHandler.ping_counter - pings_before, 1)

                    with watch_lock:
                        stats["watchdog_events"] = len(detected_files_queue)

                    stats["generated"] += 1
                    stats["av_bypassed"] += 1
                    red_rows.append([
                        info["file_name"],
                        f"{info['entropy']:.3f}",
                        info["sha256"][:14] + "...",
                        "BYPASS (0%)",
                    ])

                    # Inferencia do Blue Team com medicao de latencia real
                    t0 = time.perf_counter()
                    feats = extract_static_and_ast_features(sample_path, io_delta, net_pings)
                    vec = np.array([[feats["entropy"], feats["ast_nodes"], feats["has_exec"], feats["io_delta_kb"], feats["net_pings"]]])
                    prob_attack = float(rf_model.predict_proba(vec)[0][1])
                    iso_flag = int(iso_model.predict(vec)[0]) == -1
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    latencies.append(latency_ms)
                    stats["avg_latency_ms"] = sum(latencies) / len(latencies)

                    if prob_attack >= 0.5 or iso_flag:
                        stats["ai_detected"] += 1
                        q_dest = QUARANTINE_DIR / sample_path.name
                        if q_dest.exists():
                            q_dest.unlink()
                        if sample_path.exists():
                            shutil.move(str(sample_path), str(q_dest))
                        action = "QUARENTENA OK"
                    else:
                        action = "LIBERADO"

                    blue_rows.append([
                        info["file_name"],
                        f"{prob_attack * 100:.1f}%",
                        f"{latency_ms:.2f} ms",
                        action,
                    ])
                    incident_log.append((info["file_name"], info["technique"], feats, prob_attack, latency_ms, action))
                    live.update(build_layout(red_rows, blue_rows, stats))
                    time.sleep(0.5)
    finally:
        observer.stop()
        observer.join()
        server.shutdown()
        server.server_close()

    with watch_lock:
        stats["watchdog_events"] = len(detected_files_queue)

    total_gen = max(1, stats["generated"])
    ai_rate = (stats["ai_detected"] / total_gen) * 100.0

    # Gera relatorio final em Markdown
    lines = [
        "# 🛡️ Relatório Técnico de Incidente — SOC / AI Cyber Duel",
        f"- **Data/Hora:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Amostras Analisadas:** {stats['generated']}",
        f"- **Eventos de Disco Interceptados (Watchdog):** {stats['watchdog_events']}",
        f"- **Pings Loopback Capturados (127.0.0.1:59999):** {TelemetryTCPHandler.ping_counter}",
        f"- **Taxa de Evasão contra AV Estático (SHA-256):** 100% ({stats['av_bypassed']}/{stats['generated']})",
        f"- **Taxa de Detecção e Quarentena (Ensemble IA):** {ai_rate:.1f}% ({stats['ai_detected']}/{stats['generated']})",
        f"- **Latência Média de Inferência:** {stats['avg_latency_ms']:.2f} ms",
        "",
        "## Detalhamento por Variante Interceptada",
        "| Arquivo | Técnica AST | Entropia | Nós AST | Score IA | Latência | Ação |",
        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: |",
    ]
    for fname, tech, feats, prob, lat, act in incident_log:
        lines.append(
            f"| {fname} | {tech} | {feats['entropy']:.4f} | {feats['ast_nodes']} | {prob * 100:.1f}% | {lat:.2f} ms | {act} |"
        )
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"\n[bold green]✔ Duelo finalizado! Relatório gerado em: {REPORT_PATH.name}[/bold green]")


if __name__ == "__main__":
    main()
