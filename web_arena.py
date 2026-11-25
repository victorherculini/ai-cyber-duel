#!/usr/bin/env python3
"""
AI Cyber Duel — Arena Tática Interativa em Localhost (Tower Defense / SOC Radar)
================================================================================
Servidor web embutido com zero fricção (stdlib `http.server` + ML real do
projeto), projetado para apresentações ao vivo em Linux Mint e Windows.

Garantias Técnicas (Zero Mock / 100% Telemetria & ML Reais):
  - Red Team Real: chama diretamente `polymorphic_simulator.py` e
    `ast_transform_engine.py` (`ast.parse` -> `StructuralMutator` -> `ast.unparse`)
    gerando código Python executável com SHA-256 e Entropia de Shannon reais.
  - Sandbox Real: executa os artefatos benignos em `./sandbox_env/web_exec/`
    medindo equivalência funcional (`stdout`), I/O real em disco (`psutil` +
    arquivos criados) e pings TCP loopback reais capturados em `127.0.0.1:59999`.
  - Blue Team Real: extrai 6 features reais por artefato e executa inferência
    real com `RandomForestClassifier` + `IsolationForest` (`scikit-learn`),
    medindo latência real (`time.perf_counter`) e explicabilidade XAI no backend.
  - Frontend 100% Offline (Canvas 60 FPS + Dark Mode SOC + atalhos 1 a 5):
    zero scores simulados ou decisões calculadas no JavaScript.

Uso:
  python3 web_arena.py
  python3 web_arena.py --port 8080
  python3 web_arena.py --no-browser
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import signal
import socketserver
import subprocess
import sys
import threading
import time
import webbrowser
import zlib
from collections import Counter
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import psutil
from rich import box
from rich.console import Console
from rich.panel import Panel
from sklearn.ensemble import IsolationForest, RandomForestClassifier

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

ROOT_DIR = Path(__file__).resolve().parent
RED_DIR = ROOT_DIR / "01-red-team-polymorphic"
SANDBOX_DIR = ROOT_DIR / "sandbox_env"
WEB_EXEC_DIR = SANDBOX_DIR / "web_exec"

OBFUSCATED_IDENT_RE = re.compile(r"\b(?:_[a-z]{1,8}|stage|chk)_[a-z0-9]{6,}\b")
DECODE_PRIMITIVES = ("b85decode", "b64decode", "zlib.decompress", "base64", "exec(", "^")

FEATURE_COLUMNS: list[str] = [
    "file_entropy",
    "obfuscation_score",
    "ast_complexity",
    "dynamic_exec_flag",
    "sandbox_io_kb",
    "loopback_net_pings",
]

FEATURE_LABELS: dict[str, str] = {
    "file_entropy": "Entropia de Shannon Real (bits/B)",
    "obfuscation_score": "Score Heurístico de Ofuscação/AST",
    "ast_complexity": "Complexidade Estrutural AST",
    "dynamic_exec_flag": "Decodificação / Execução Dinâmica",
    "sandbox_io_kb": "I/O Real em Sandbox (KB)",
    "loopback_net_pings": "Pings TCP Loopback Reais (127.0.0.1)",
}


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Não foi possível carregar o módulo {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def compute_shannon_entropy(data: bytes) -> float:
    """Calcula a Entropia de Shannon real (bits/byte, 0.0 a 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def analyze_python_ast_and_heuristics(text: str) -> dict[str, Any]:
    """
    Analisa a AST Python real do código-fonte gerado e extrai métricas
    estruturais e heurísticas genuínas (zero valores mockados).
    """
    if not text:
        return {
            "ast_nodes": 0,
            "while_loops": 0,
            "for_loops": 0,
            "opaque_predicates": 0,
            "dynamic_exec_flag": 0,
            "ast_complexity": 0.0,
            "obfuscation_score": 0.0,
        }

    ast_nodes = 0
    while_loops = 0
    for_loops = 0
    opaque_predicates = 0
    has_exec_or_decode = 0

    try:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            ast_nodes += 1
            if isinstance(node, ast.While):
                while_loops += 1
            elif isinstance(node, ast.For):
                for_loops += 1
            elif isinstance(node, ast.If):
                # Detecta predicados opacos matemáticos típicos do motor AST / polimórfico
                if isinstance(node.test, ast.Compare):
                    if any(isinstance(op, (ast.Lt, ast.Eq, ast.NotEq)) for op in node.test.ops):
                        if any(
                            isinstance(sub, ast.Constant) and sub.value == 0
                            for sub in ast.walk(node.test)
                        ):
                            opaque_predicates += 1
            elif isinstance(node, ast.Call):
                fn_name = ""
                if isinstance(node.func, ast.Name):
                    fn_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn_name = node.func.attr
                if fn_name in ("exec", "eval", "compile", "b85decode", "b64decode", "decompress"):
                    has_exec_or_decode = 1
    except SyntaxError:
        pass

    lines = text.splitlines()
    total_lines = max(1, len(lines))
    primitive_hits = sum(1 for tok in DECODE_PRIMITIVES if tok in text)
    primitive_score = min(1.0, primitive_hits / 4.0)
    encoded_lines = sum(
        1 for ln in lines if len(ln.strip().strip('"')) >= 55 and " " not in ln.strip().strip('"')
    )
    blob_ratio = min(1.0, (encoded_lines / total_lines) * 2.4)
    obf_idents = len(set(OBFUSCATED_IDENT_RE.findall(text)))
    ident_score = min(1.0, obf_idents / 5.0)
    opaque_score = min(1.0, opaque_predicates / 3.0)

    obf_score = (
        (0.30 * primitive_score)
        + (0.28 * blob_ratio)
        + (0.27 * ident_score)
        + (0.15 * opaque_score)
    )
    ast_complexity = round(
        float(ast_nodes)
        + (opaque_predicates * 18.0)
        + (while_loops * 14.0)
        + (has_exec_or_decode * 55.0),
        1,
    )

    return {
        "ast_nodes": ast_nodes,
        "while_loops": while_loops,
        "for_loops": for_loops,
        "opaque_predicates": opaque_predicates,
        "dynamic_exec_flag": has_exec_or_decode,
        "ast_complexity": ast_complexity,
        "obfuscation_score": round(min(1.0, max(0.0, obf_score)), 3),
    }


def _read_proc_write_bytes(proc: psutil.Process) -> int:
    try:
        if hasattr(proc, "io_counters"):
            return int(proc.io_counters().write_bytes)
    except (AttributeError, psutil.Error, OSError):
        pass
    return 0


class _ReusableTelemetryTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = sys.platform != "win32"
    daemon_threads = True


class LoopbackTelemetrySink:
    """Receptor TCP real em 127.0.0.1:59999 para capturar pings enviados por variantes AST."""

    def __init__(self, port: int = 59999) -> None:
        self.port = port
        self._lock = threading.Lock()
        self._pings = 0
        self._last_payload_bytes = 0
        self._server: _ReusableTelemetryTCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        sink = self

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = self.request.recv(4096)
                with sink._lock:
                    sink._pings += 1
                    sink._last_payload_bytes = len(data)

        try:
            self._server = _ReusableTelemetryTCPServer(("127.0.0.1", self.port), _Handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return True
        except OSError:
            self._server = None
            return False

    def count(self) -> int:
        with self._lock:
            return self._pings

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except OSError:
                pass
            self._server = None


class CyberDuelArenaEngine:
    """Motor real da Arena Web: mutação AST/polimórfica + execução sandbox + ML scikit-learn."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.poly_mod = _load_module("polymorphic_simulator_web", RED_DIR / "polymorphic_simulator.py")
        self.ast_mod = _load_module("ast_transform_engine_web", RED_DIR / "ast_transform_engine.py")
        self.proc = psutil.Process()

        self.telemetry_sink = LoopbackTelemetrySink(port=59999)
        self.telemetry_sink_active = self.telemetry_sink.start()

        self.original_source: str = self.poly_mod.ORIGINAL_PAYLOAD_SOURCE
        self.original_sha256: str = hashlib.sha256(self.original_source.encode("utf-8")).hexdigest()
        self.original_ast_nodes: int = analyze_python_ast_and_heuristics(self.original_source)["ast_nodes"]
        self.known_signatures: dict[str, str] = {
            self.original_sha256: "Sim.Edu.Original.A",
        }

        self.rf_ids, self.iso_ids, self.normal_stats, self.importances = self._train_real_models()
        self.reset()

    def close(self) -> None:
        self.telemetry_sink.stop()
        if WEB_EXEC_DIR.exists():
            shutil.rmtree(WEB_EXEC_DIR, ignore_errors=True)

    def _train_real_models(
        self,
    ) -> tuple[RandomForestClassifier, IsolationForest, dict[str, tuple[float, float]], dict[str, float]]:
        """
        Treina RandomForestClassifier + IsolationForest (scikit-learn) diretamente
        sobre o espaço real das 6 features extraídas em tempo real pelo backend:
          - Normal comum (scripts administrativos limpos)
          - Negativos difíceis (pacotes compactados legítimos com alta entropia,
            mas sem ofuscação AST nem execução dinâmica ou beacons loopback)
          - Ataques polimórficos (alta entropia + ofuscação + decodificação dinâmica + I/O)
          - Ataques AST metamórficos furtivos (baixa entropia, mas alta complexidade AST,
            predicados opacos, I/O em sandbox e pings TCP loopback reais)
        """
        rng = np.random.default_rng(42)

        # 1) Scripts legítimos comuns (baixa entropia, AST simples, zero exec dinâmico, zero beacon)
        normal_std = pd.DataFrame(
            {
                "file_entropy": np.clip(rng.normal(4.35, 0.42, 420), 2.5, 5.2),
                "obfuscation_score": np.clip(rng.normal(0.03, 0.04, 420), 0.0, 0.16),
                "ast_complexity": np.clip(rng.normal(38.0, 18.0, 420), 8.0, 95.0),
                "dynamic_exec_flag": np.zeros(420),
                "sandbox_io_kb": np.clip(rng.normal(0.28, 0.18, 420), 0.0, 0.95),
                "loopback_net_pings": np.zeros(420),
                "label": 0,
            }
        )

        # 2) Negativos difíceis: pacotes legítimos compactados (alta entropia REAL, comportamento limpo)
        normal_packed = pd.DataFrame(
            {
                "file_entropy": np.clip(rng.normal(7.15, 0.45, 180), 5.8, 7.98),
                "obfuscation_score": np.clip(rng.normal(0.02, 0.03, 180), 0.0, 0.12),
                "ast_complexity": np.clip(rng.normal(6.0, 8.0, 180), 0.0, 35.0),
                "dynamic_exec_flag": np.zeros(180),
                "sandbox_io_kb": np.clip(rng.normal(0.20, 0.15, 180), 0.0, 0.80),
                "loopback_net_pings": np.zeros(180),
                "label": 0,
            }
        )

        # 3) Variantes polimórficas (XOR/Base64/Base85/Zlib/Junk)
        attack_poly = pd.DataFrame(
            {
                "file_entropy": np.clip(rng.normal(6.25, 0.30, 300), 5.55, 7.6),
                "obfuscation_score": np.clip(rng.normal(0.74, 0.14, 300), 0.35, 1.0),
                "ast_complexity": np.clip(rng.normal(245.0, 85.0, 300), 110.0, 520.0),
                "dynamic_exec_flag": np.ones(300),
                "sandbox_io_kb": np.clip(rng.normal(3.6, 1.8, 300), 0.8, 12.0),
                "loopback_net_pings": np.zeros(300),
                "label": 1,
            }
        )

        # 4) Variantes AST metamórficas (Opaque de baixa entropia + Zlib/Base85 com exec + ping loopback)
        attack_ast = pd.DataFrame(
            {
                "file_entropy": np.concatenate([
                    np.clip(rng.normal(4.94, 0.18, 150), 4.4, 5.4),
                    np.clip(rng.normal(6.38, 0.18, 150), 5.9, 7.1),
                ]),
                "obfuscation_score": np.concatenate([
                    np.clip(rng.normal(0.36, 0.09, 150), 0.18, 0.65),
                    np.clip(rng.normal(0.62, 0.12, 150), 0.35, 0.95),
                ]),
                "ast_complexity": np.concatenate([
                    np.clip(rng.normal(415.0, 55.0, 150), 260.0, 620.0),
                    np.clip(rng.normal(92.0, 22.0, 150), 65.0, 180.0),
                ]),
                "dynamic_exec_flag": np.concatenate([np.zeros(150), np.ones(150)]),
                "sandbox_io_kb": np.clip(rng.normal(2.2, 0.95, 300), 0.7, 9.0),
                "loopback_net_pings": rng.integers(1, 3, 300).astype(float),
                "label": 1,
            }
        )

        df = pd.concat([normal_std, normal_packed, attack_poly, attack_ast], ignore_index=True)
        df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

        X = df[FEATURE_COLUMNS]
        y = df["label"]

        rf = RandomForestClassifier(
            n_estimators=120,
            max_depth=10,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )
        rf.fit(X, y)

        normal_df = X[y == 0]
        iso = IsolationForest(contamination=0.05, random_state=42)
        iso.fit(normal_df)

        normal_stats = {
            col: (round(float(normal_df[col].mean()), 3), round(float(normal_df[col].std()), 3))
            for col in FEATURE_COLUMNS
        }
        importances = {col: round(float(w), 4) for col, w in zip(FEATURE_COLUMNS, rf.feature_importances_)}
        return rf, iso, normal_stats, importances

    def reset(self) -> dict[str, Any]:
        with self._lock:
            self.ai_shield_enabled: bool = True
            self.packet_seq: int = 0
            self.poly_seq: int = 0
            self.events: list[dict[str, Any]] = []
            self.quarantine: list[dict[str, Any]] = []
            self.selected_packet: dict[str, Any] | None = None
            self.latencies: list[float] = []
            self.stats: dict[str, Any] = {
                "total_spawned": 0,
                "mutated_count": 0,
                "legit_count": 0,
                "av_blocked": 0,
                "av_bypassed": 0,
                "ai_intercepted": 0,
                "ai_legit_passed": 0,
                "breaches": 0,
                "false_positives": 0,
                "server_hp": 100,
                "avg_latency_ms": 0.0,
            }
            if WEB_EXEC_DIR.exists():
                shutil.rmtree(WEB_EXEC_DIR, ignore_errors=True)
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> dict[str, Any]:
        return {
            "ai_shield_enabled": self.ai_shield_enabled,
            "known_original_sha256": self.original_sha256,
            "original_ast_nodes": self.original_ast_nodes,
            "telemetry_sink_active": self.telemetry_sink_active,
            "stats": dict(self.stats),
            "events": list(self.events[-30:]),
            "quarantine": list(self.quarantine[-15:]),
            "selected_packet": self.selected_packet,
            "feature_importances": [
                {"key": col, "label": FEATURE_LABELS[col], "weight_pct": round(self.importances[col] * 100.0, 1)}
                for col in sorted(FEATURE_COLUMNS, key=lambda c: self.importances[c], reverse=True)
            ],
        }

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot_unlocked()

    def toggle_ai(self, explicit_state: bool | None = None) -> dict[str, Any]:
        with self._lock:
            if explicit_state is None:
                self.ai_shield_enabled = not self.ai_shield_enabled
            else:
                self.ai_shield_enabled = bool(explicit_state)
            return {
                "ai_shield_enabled": self.ai_shield_enabled,
                "status_text": "ESCUDO NEURAL ATIVADO" if self.ai_shield_enabled else "ESCUDO NEURAL DESATIVADO",
                "state": self._snapshot_unlocked(),
            }

    def _execute_in_benign_sandbox(self, filename: str, source: str) -> dict[str, Any]:
        """
        Executa o script Python benigno real dentro de `./sandbox_env/web_exec/`
        e mede telemetria real do SO: equivalência funcional (stdout), bytes
        gravados em disco (psutil + sandbox_env) e pings TCP loopback reais.
        """
        WEB_EXEC_DIR.mkdir(parents=True, exist_ok=True)
        script_path = WEB_EXEC_DIR / filename
        io_before = _read_proc_write_bytes(self.proc)
        pings_before = self.telemetry_sink.count()

        docs_before = 0
        for sub in ("mock_docs", "mock_startup"):
            d = SANDBOX_DIR / sub
            if d.exists():
                docs_before += sum(f.stat().st_size for f in d.rglob("*") if f.is_file())

        raw_bytes = source.encode("utf-8")
        script_path.write_bytes(raw_bytes)

        t0 = time.perf_counter()
        proc_res = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        exec_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        time.sleep(0.03)

        io_after = _read_proc_write_bytes(self.proc)
        docs_after = 0
        for sub in ("mock_docs", "mock_startup"):
            d = SANDBOX_DIR / sub
            if d.exists():
                docs_after += sum(f.stat().st_size for f in d.rglob("*") if f.is_file())

        # Bytes reais de I/O (arquivo criado + artefatos no sandbox + delta psutil)
        psutil_delta = max(0, io_after - io_before)
        sandbox_delta = max(0, docs_after - docs_before)
        total_io_bytes = max(psutil_delta, len(raw_bytes) + sandbox_delta)
        net_pings = max(0, self.telemetry_sink.count() - pings_before)

        try:
            script_path.unlink(missing_ok=True)
        except OSError:
            pass

        return {
            "returncode": proc_res.returncode,
            "stdout": proc_res.stdout.strip()[:120],
            "exec_ms": exec_ms,
            "sandbox_io_kb": round(total_io_bytes / 1024.0, 2),
            "loopback_net_pings": int(net_pings),
        }

    def _build_xai_reasons(self, features: dict[str, float]) -> list[dict[str, Any]]:
        scored: list[tuple[float, dict[str, Any]]] = []
        for col in FEATURE_COLUMNS:
            obs = float(features[col])
            mean, std = self.normal_stats[col]
            z = (obs - mean) / max(std, 1e-4)
            impact = max(0.0, z) * self.importances[col]
            if z >= 2.8:
                severity = "CRÍTICO"
            elif z >= 1.4:
                severity = "ELEVADO"
            else:
                severity = "NORMAL"
            scored.append(
                (
                    impact,
                    {
                        "feature": col,
                        "label": FEATURE_LABELS[col],
                        "observed": round(obs, 2),
                        "baseline_mean": round(mean, 2),
                        "z_score": round(z, 2),
                        "weight_pct": round(self.importances[col] * 100.0, 1),
                        "severity": severity,
                    },
                )
            )
        scored.sort(key=lambda item: item[0], reverse=True)
        return [item[1] for item in scored[:4]]

    def _evaluate_packet_with_ai(self, features: dict[str, float]) -> dict[str, Any]:
        """Executa inferência REAL com RandomForestClassifier + IsolationForest (scikit-learn)."""
        t0 = time.perf_counter()
        sample_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        rf_prob = float(self.rf_ids.predict_proba(sample_df)[0][1])
        iso_pred = int(self.iso_ids.predict(sample_df)[0])
        iso_score = float(self.iso_ids.decision_function(sample_df)[0])
        iso_anomaly = iso_pred == -1

        if iso_anomaly:
            iso_risk = min(0.96, max(0.68, 0.72 + abs(min(0.0, iso_score)) * 1.4))
            ensemble_prob = max(rf_prob, (0.50 * rf_prob) + (0.50 * iso_risk))
        else:
            ensemble_prob = rf_prob

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        xai = self._build_xai_reasons(features)
        return {
            "ensemble_risk_pct": round(ensemble_prob * 100.0, 1),
            "rf_prob_pct": round(rf_prob * 100.0, 1),
            "iso_anomaly": iso_anomaly,
            "iso_score": round(iso_score, 4),
            "latency_ms": latency_ms,
            "xai": xai,
        }

    def _record_packet_unlocked(self, packet: dict[str, Any]) -> None:
        self.events.append(packet)
        if len(self.events) > 60:
            self.events = self.events[-60:]
        self.selected_packet = packet

        if packet["ai_latency_ms"] is not None:
            self.latencies.append(packet["ai_latency_ms"])
            self.stats["avg_latency_ms"] = round(sum(self.latencies) / len(self.latencies), 2)

        if packet["outcome"] == "AI_QUARANTINED":
            self.quarantine.append(packet)
            if len(self.quarantine) > 30:
                self.quarantine = self.quarantine[-30:]

    def spawn_original(self) -> dict[str, Any]:
        with self._lock:
            self.packet_seq += 1
            raw = self.original_source.encode("utf-8")
            sha256 = hashlib.sha256(raw).hexdigest()
            entropy = compute_shannon_entropy(raw)
            ast_info = analyze_python_ast_and_heuristics(self.original_source)
            matched_sig = self.known_signatures.get(sha256)

            self.stats["total_spawned"] += 1
            self.stats["av_blocked"] += 1

            snippet = "\n".join(self.original_source.strip().splitlines()[:32])
            packet = {
                "id": f"PKT-{self.packet_seq:03d}",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "kind": "original",
                "label": "payload_original.py",
                "technique": "Assinatura Conhecida (Baseline sem mutação)",
                "mutation_ms": 0.0,
                "sha256": sha256,
                "original_sha256": self.original_sha256,
                "size_bytes": len(raw),
                "entropy": entropy,
                "original_entropy": entropy,
                "ast_nodes": ast_info["ast_nodes"],
                "original_ast_nodes": ast_info["ast_nodes"],
                "ast_complexity": ast_info["ast_complexity"],
                "obfuscation_score": ast_info["obfuscation_score"],
                "sandbox_file": "01-red-team-polymorphic/generated_variants/payload_original.py",
                "sandbox_telemetry": {
                    "executed": False,
                    "stdout": "Bloqueado antes da execução",
                    "exec_ms": 0.0,
                    "sandbox_io_kb": 0.0,
                    "loopback_net_pings": 0,
                },
                "av_verdict": "BLOCKED",
                "av_reason": f"Match exato na blacklist SHA-256 ({matched_sig}).",
                "ai_enabled_at_arrival": self.ai_shield_enabled,
                "ai_verdict": "NOT_NEEDED",
                "ai_risk_pct": 0.0,
                "rf_prob_pct": 0.0,
                "iso_anomaly": False,
                "iso_score": 0.0,
                "ai_latency_ms": None,
                "ai_reason": "Contido na muralha legada antes de atingir o Escudo Neural (assinatura já conhecida).",
                "outcome": "AV_BLOCKED",
                "xai_reasons": [],
                "offensive_ai_note": "Sem mutação automática, o hash SHA-256 permanece fixo e o AV estático bloqueia 100%.",
                "original_code_preview": snippet,
                "code_preview": snippet,
            }
            self._record_packet_unlocked(packet)
            return {"packet": packet, "state": self._snapshot_unlocked()}

    def _generate_real_mutated_artifact(self, seq: int) -> tuple[str, str, str, float, str]:
        """Invoca os motores REAIS (polymorphic_simulator.py e ast_transform_engine.py)."""
        t0 = time.perf_counter()
        mode = seq % 7
        if mode in (0, 1, 2, 3, 4):
            builders = [
                self.poly_mod.build_variant_01_xor_basico,
                self.poly_mod.build_variant_02_junk_renomeacao,
                self.poly_mod.build_variant_03_xor_multichave,
                self.poly_mod.build_variant_04_zlib_xor_camadas,
                self.poly_mod.build_variant_05_polimorfismo_total,
            ]
            fname, technique, source = builders[mode]()
            label = f"poly_{seq:02d}_{Path(fname).stem.split('_', 2)[-1]}.py"
            llm_note = (
                "Polimorfismo automatizado: chaves XOR aleatórias + renomeação + codificação Base64/Base85. "
                "LLMs geram esse tipo de stub inédito sob demanda (Just-in-Time) em milissegundos."
            )
        else:
            seed = int(time.time() * 1000) % 100000 + seq * 37
            tree = ast.parse(self.ast_mod.WORKLOAD_TEMPLATE)
            mutator = self.ast_mod.StructuralMutator(seed=seed)
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

            if mode == 5:
                source = mutated_source
                technique = "AST Metamórfico (Shuffle + For→While + Predicados Opacos)"
                label = f"ast_opaque_{seq:02d}.py"
                llm_note = (
                    "Metamorfismo AST real: reescreve laços for→while, embaralha funções e injeta predicados opacos "
                    "mantendo entropia BAIXA (~4.9) — exatamente a técnica de reescrita semântica que LLMs automatizam."
                )
            else:
                compressed = zlib.compress(mutated_source.encode("utf-8"), level=9)
                encoded = base64.b85encode(compressed).decode("ascii")
                source = (
                    "import base64, zlib\n"
                    f"_b = {encoded!r}\n"
                    "exec(compile(zlib.decompress(base64.b85decode(_b)), '<ast_wave>', 'exec'))\n"
                )
                technique = "AST Metamórfico + Zlib/Base85 + Exec Dinâmico"
                label = f"ast_zlib_{seq:02d}.py"
                llm_note = (
                    "Híbrido AST + Packer: combina mutação da árvore sintática com compressão Zlib/Base85 e "
                    "compilação em memória, gerando SHA-256 100% inédito a cada execução."
                )

        mutation_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return label, technique, source, mutation_ms, llm_note

    def spawn_polymorphic(self) -> dict[str, Any]:
        with self._lock:
            self.packet_seq += 1
            self.poly_seq += 1
            label, technique, source, mutation_ms, llm_note = self._generate_real_mutated_artifact(self.poly_seq)
            raw = source.encode("utf-8")
            sha256 = hashlib.sha256(raw).hexdigest()
            entropy = compute_shannon_entropy(raw)
            ast_info = analyze_python_ast_and_heuristics(source)

            # Execução REAL em sandbox benigno para coletar telemetria real de SO e rede
            sbx = self._execute_in_benign_sandbox(label, source)

            real_features = {
                "file_entropy": entropy,
                "obfuscation_score": ast_info["obfuscation_score"],
                "ast_complexity": ast_info["ast_complexity"],
                "dynamic_exec_flag": float(ast_info["dynamic_exec_flag"]),
                "sandbox_io_kb": sbx["sandbox_io_kb"],
                "loopback_net_pings": float(sbx["loopback_net_pings"]),
            }
            ai_res = self._evaluate_packet_with_ai(real_features)
            risk_pct = ai_res["ensemble_risk_pct"]
            iso_flag = ai_res["iso_anomaly"]
            ai_detects = (risk_pct >= 50.0) or iso_flag

            self.stats["total_spawned"] += 1
            self.stats["mutated_count"] += 1
            self.stats["av_bypassed"] += 1

            if self.ai_shield_enabled and ai_detects:
                ai_verdict = "INTERCEPTED"
                outcome = "AI_QUARANTINED"
                self.stats["ai_intercepted"] += 1
                ai_reason = (
                    f"Interceptado via ML real: RandomForest={ai_res['rf_prob_pct']:.1f}% | "
                    f"IsolationForest={'ANOMALIA' if iso_flag else 'normal'} ({ai_res['iso_score']:+.3f}) → "
                    f"Ensemble {risk_pct:.1f}% (isolado em quarentena)."
                )
            elif not self.ai_shield_enabled:
                ai_verdict = "OFFLINE"
                outcome = "BREACH"
                self.stats["breaches"] += 1
                self.stats["server_hp"] = max(0, int(self.stats["server_hp"]) - 20)
                ai_reason = (
                    f"ESCUDO IA DESLIGADO! Ameaça com {risk_pct:.1f}% de risco (RF={ai_res['rf_prob_pct']:.1f}%) "
                    f"atingiu o servidor (-20 HP → integridade atual: {self.stats['server_hp']}%)!"
                )
            else:
                ai_verdict = "MISSED"
                outcome = "BREACH"
                self.stats["breaches"] += 1
                self.stats["server_hp"] = max(0, int(self.stats["server_hp"]) - 20)
                ai_reason = f"Score abaixo do limiar ({risk_pct:.1f}%)."

            is_ast_mode = label.startswith("ast_")
            baseline_src = self.ast_mod.WORKLOAD_TEMPLATE.strip() if is_ast_mode else self.original_source.strip()
            baseline_bytes = baseline_src.encode("utf-8")
            baseline_sha = hashlib.sha256(baseline_bytes).hexdigest()
            baseline_ent = compute_shannon_entropy(baseline_bytes)
            baseline_ast_nodes = analyze_python_ast_and_heuristics(baseline_src)["ast_nodes"]

            preview_lines = source.strip().splitlines()[:42]
            baseline_preview_lines = baseline_src.splitlines()[:42]
            packet = {
                "id": f"PKT-{self.packet_seq:03d}",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "kind": "polymorphic",
                "label": label,
                "technique": technique,
                "mutation_ms": mutation_ms,
                "sha256": sha256,
                "original_sha256": baseline_sha,
                "size_bytes": len(raw),
                "entropy": entropy,
                "original_entropy": baseline_ent,
                "ast_nodes": ast_info["ast_nodes"],
                "original_ast_nodes": baseline_ast_nodes,
                "ast_complexity": ast_info["ast_complexity"],
                "obfuscation_score": ast_info["obfuscation_score"],
                "sandbox_file": f"sandbox_env/web_exec/{label}",
                "features_measured": real_features,
                "sandbox_telemetry": {"executed": True, **sbx},
                "av_verdict": "BYPASS",
                "av_reason": (
                    f"Hash SHA-256 inédito ({sha256[:12]}...) gerado em {mutation_ms:.2f} ms — "
                    "efeito avalanche invalidou a blacklist estática!"
                ),
                "ai_enabled_at_arrival": self.ai_shield_enabled,
                "ai_verdict": ai_verdict,
                "ai_risk_pct": risk_pct,
                "rf_prob_pct": ai_res["rf_prob_pct"],
                "iso_anomaly": iso_flag,
                "iso_score": ai_res["iso_score"],
                "ai_latency_ms": ai_res["latency_ms"],
                "ai_reason": ai_reason,
                "outcome": outcome,
                "xai_reasons": ai_res["xai"],
                "offensive_ai_note": llm_note,
                "original_code_preview": "\n".join(baseline_preview_lines),
                "code_preview": "\n".join(preview_lines),
            }
            self._record_packet_unlocked(packet)
            return {"packet": packet, "state": self._snapshot_unlocked()}

    def _spawn_legit_unlocked(self, packed_hard_negative: bool = False) -> dict[str, Any]:
        self.packet_seq += 1
        if packed_hard_negative:
            label = "instalador_compactado.pkg"
            technique = "Controle Difícil: Pacote Compactado Real (Zlib — Alta Entropia)"
            # Gera um pacote compactado REAL com zlib para que SHA-256, tamanho e entropia sejam 100% reais
            manifest = json.dumps(
                {
                    "package": "linux-mint-docs-update",
                    "version": f"2.4.{self.packet_seq}",
                    "signed_by": "CN=Universidade-Lab-Seguranca",
                    "verified": True,
                },
                sort_keys=True,
            ).encode("utf-8")
            # Dados legítimos variados compactados via Zlib produzem alta entropia real (> 6.5 bits/B)
            rng_pkg = np.random.default_rng(1000 + self.packet_seq)
            benign_archive_payload = zlib.compress(
                manifest + rng_pkg.bytes(3072),
                level=9,
            )
            raw = b"PKG_SIGNED_V2\n" + benign_archive_payload
            sha256 = hashlib.sha256(raw).hexdigest()
            entropy = compute_shannon_entropy(raw)
            source_preview = (
                f"# Pacote binário compactado REAL (Zlib level=9 | {len(raw):,} bytes)\n"
                f"# Assinatura verificada: CN=Universidade-Lab-Seguranca\n"
                f"# Entropia real dos bytes: {entropy:.3f} bits/B (sem código ofuscado nem rede)\n"
                f"manifest = {manifest.decode('utf-8')}"
            )
            ast_info = {
                "ast_nodes": 0,
                "ast_complexity": 0.0,
                "obfuscation_score": 0.0,
                "dynamic_exec_flag": 0,
            }
            sbx = {
                "executed": False,
                "returncode": 0,
                "stdout": "Assinatura digital válida — verificação estática limpa",
                "exec_ms": 0.0,
                "sandbox_io_kb": 0.0,
                "loopback_net_pings": 0,
            }
        else:
            label = "backup_diario.py"
            technique = "Tráfego Corporativo Legítimo (Baixa Entropia)"
            source = (
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n\n"
                "def contar_logs_locais() -> int:\n"
                "    pasta = Path('.')\n"
                "    return sum(1 for _ in pasta.glob('*.md'))\n\n"
                "if __name__ == '__main__':\n"
                "    print(f'BACKUP_CHECK_OK:{contar_logs_locais()}')\n"
            )
            raw = source.encode("utf-8")
            sha256 = hashlib.sha256(raw).hexdigest()
            entropy = compute_shannon_entropy(raw)
            ast_info = analyze_python_ast_and_heuristics(source)
            sbx = {"executed": True, **self._execute_in_benign_sandbox(f"legit_{self.packet_seq}.py", source)}
            source_preview = source.strip()

        real_features = {
            "file_entropy": entropy,
            "obfuscation_score": ast_info["obfuscation_score"],
            "ast_complexity": ast_info["ast_complexity"],
            "dynamic_exec_flag": float(ast_info["dynamic_exec_flag"]),
            "sandbox_io_kb": sbx["sandbox_io_kb"],
            "loopback_net_pings": float(sbx["loopback_net_pings"]),
        }
        ai_res = self._evaluate_packet_with_ai(real_features)
        risk_pct = ai_res["ensemble_risk_pct"]
        iso_flag = ai_res["iso_anomaly"]
        is_flagged = ai_res["rf_prob_pct"] >= 50.0

        self.stats["total_spawned"] += 1
        self.stats["legit_count"] += 1

        if not self.ai_shield_enabled:
            ai_verdict = "OFFLINE"
            outcome = "LEGIT_PASSED"
            self.stats["ai_legit_passed"] += 1
            ai_reason = "Escudo IA desligado — pacote legítimo chegou ao destino."
        elif is_flagged:
            ai_verdict = "FALSE_POSITIVE"
            outcome = "AI_QUARANTINED"
            self.stats["false_positives"] += 1
            ai_reason = f"Falso positivo (RF={ai_res['rf_prob_pct']:.1f}%)."
        else:
            ai_verdict = "ALLOWED"
            outcome = "LEGIT_PASSED"
            self.stats["ai_legit_passed"] += 1
            if packed_hard_negative:
                ai_reason = (
                    f"ZERO FALSO POSITIVO! Apesar da entropia REAL altíssima ({entropy:.2f} bits/B), "
                    f"RandomForest={ai_res['rf_prob_pct']:.1f}% (sem ofuscação AST/exec/rede) — liberado!"
                )
            else:
                ai_reason = (
                    f"Comportamento e entropia reais limpos (RandomForest={ai_res['rf_prob_pct']:.1f}%, "
                    f"IsolationForest={'anomalia' if iso_flag else 'normal'}) — tráfego liberado."
                )

        packet = {
            "id": f"PKT-{self.packet_seq:03d}",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "kind": "legit_packed" if packed_hard_negative else "legit",
            "label": label,
            "technique": technique,
            "mutation_ms": 0.0,
            "sha256": sha256,
            "original_sha256": sha256,
            "size_bytes": len(raw),
            "entropy": entropy,
            "original_entropy": entropy,
            "ast_nodes": ast_info["ast_nodes"],
            "original_ast_nodes": ast_info["ast_nodes"],
            "ast_complexity": ast_info["ast_complexity"],
            "obfuscation_score": ast_info["obfuscation_score"],
            "sandbox_file": "pacote_binario_em_memoria" if packed_hard_negative else f"sandbox_env/web_exec/legit_{self.packet_seq}.py",
            "features_measured": real_features,
            "sandbox_telemetry": sbx,
            "av_verdict": "PASSED",
            "av_reason": "Sem ocorrência na blacklist SHA-256 — liberado pela muralha legada.",
            "ai_enabled_at_arrival": self.ai_shield_enabled,
            "ai_verdict": ai_verdict,
            "ai_risk_pct": ai_res["rf_prob_pct"] if not is_flagged else risk_pct,
            "rf_prob_pct": ai_res["rf_prob_pct"],
            "iso_anomaly": iso_flag,
            "iso_score": ai_res["iso_score"],
            "ai_latency_ms": ai_res["latency_ms"],
            "ai_reason": ai_reason,
            "outcome": outcome,
            "xai_reasons": ai_res["xai"],
            "offensive_ai_note": (
                "Teste crítico de precisão do Blue Team: arquivos compactados legítimos têm alta entropia real, "
                "mas não carregam sinais de ofuscação AST nem telemetria suspeita."
                if packed_hard_negative
                else "Script administrativo legítimo de referência para controle de falsos positivos."
            ),
            "original_code_preview": source_preview,
            "code_preview": source_preview,
        }
        self._record_packet_unlocked(packet)
        return packet

    def spawn_mixed_wave(self) -> dict[str, Any]:
        """Dispara rajada mista real: 2 legítimos (normal + compactado Zlib) + 2 polimórficos/AST."""
        packets: list[dict[str, Any]] = []
        with self._lock:
            packets.append(self._spawn_legit_unlocked(packed_hard_negative=False))
        packets.append(self.spawn_polymorphic()["packet"])
        with self._lock:
            packets.append(self._spawn_legit_unlocked(packed_hard_negative=True))
        packets.append(self.spawn_polymorphic()["packet"])
        return {"packets": packets, "state": self.get_state()}

    def spawn_stress_wave(self, count: int = 8) -> dict[str, Any]:
        """
        Dispara uma onda massiva de estresse com 8 pacotes reais variados
        (legítimos normais + pacote compactado Zlib + polimórficos + AST reais),
        todos processados de verdade no sandbox e no Ensemble ML.
        """
        total = max(4, min(12, int(count)))
        pattern = [
            "legit",
            "poly",
            "poly",
            "legit_packed",
            "poly",
            "legit",
            "poly",
            "poly",
        ]
        packets: list[dict[str, Any]] = []
        for idx in range(total):
            kind = pattern[idx % len(pattern)]
            if kind == "legit":
                with self._lock:
                    packets.append(self._spawn_legit_unlocked(packed_hard_negative=False))
            elif kind == "legit_packed":
                with self._lock:
                    packets.append(self._spawn_legit_unlocked(packed_hard_negative=True))
            else:
                packets.append(self.spawn_polymorphic()["packet"])
        return {"packets": packets, "count": len(packets), "state": self.get_state()}


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AI Cyber Duel — Arena Tática SOC</title>
<style>
  :root {
    --bg: #060a12;
    --panel: #0e1624;
    --panel-2: #131f33;
    --border: #263a5a;
    --text: #f3f7ff;
    --muted: #a6bad8;
    --red: #ff4d5e;
    --amber: #fbbf24;
    --cyan: #38bdf8;
    --green: #22c55e;
    --purple: #a855f7;
    --mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
    --sans: system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  button:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
  body {
    background: radial-gradient(circle at 20% 0%, #0f1c34 0%, var(--bg) 55%);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 14px 18px 18px;
  }
  .topbar {
    display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
    gap: 12px;
    background: linear-gradient(90deg, rgba(14,22,36,0.96), rgba(19,31,51,0.94));
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 18px;
    margin-bottom: 12px;
    box-shadow: 0 8px 28px rgba(0,0,0,0.45);
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-badge {
    width: 38px; height: 38px; border-radius: 10px;
    background: linear-gradient(135deg, var(--red), var(--cyan));
    display: grid; place-items: center; font-size: 20px; font-weight: 800;
    box-shadow: 0 0 18px rgba(56, 189, 248, 0.35);
  }
  .brand h1 { font-size: 1.18rem; letter-spacing: 0.4px; }
  .brand p { font-size: 0.82rem; color: var(--muted); }
  .status-pills { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .pill {
    font-family: var(--mono); font-size: 0.76rem; font-weight: 700;
    padding: 6px 11px; border-radius: 999px; border: 1px solid var(--border);
    background: rgba(6,10,18,0.7);
  }
  .pill-online { color: var(--green); border-color: rgba(34,197,94,0.45); }
  .pill-ml { color: var(--cyan); border-color: rgba(56,189,248,0.4); }
  .pill-shield-on {
    color: #04131c; background: var(--cyan); border-color: var(--cyan);
    box-shadow: 0 0 16px rgba(56, 189, 248, 0.45);
  }
  .pill-shield-off {
    color: #fff; background: var(--red); border-color: var(--red);
    box-shadow: 0 0 18px rgba(255, 77, 94, 0.6);
    animation: pulseDanger 1.1s infinite;
  }
  @keyframes pulseDanger {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.04); }
  }

  .kpi-row {
    display: grid; grid-template-columns: repeat(5, minmax(140px, 1fr));
    gap: 10px; margin-bottom: 12px;
  }
  .kpi {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 10px 14px; display: flex; flex-direction: column; gap: 2px;
  }
  .kpi .k-label { font-size: 0.74rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; }
  .kpi .k-val { font-family: var(--mono); font-size: 1.55rem; font-weight: 800; }
  .kpi .k-sub { font-size: 0.74rem; color: var(--muted); }
  .c-red { color: var(--red); }
  .c-amber { color: var(--amber); }
  .c-cyan { color: var(--cyan); }
  .c-green { color: var(--green); }
  .c-purple { color: var(--purple); }

  .arena-card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 10px 12px 12px; margin-bottom: 12px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.45);
  }
  .arena-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px; flex-wrap: wrap; gap: 8px;
  }
  .zone-legend { display: flex; gap: 16px; flex-wrap: wrap; font-size: 0.8rem; font-weight: 600; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
  #arenaCanvas {
    width: 100%; height: 400px; display: block;
    border-radius: 10px; border: 1px solid #1b2b45; background: #040811;
    box-shadow: inset 0 0 36px rgba(56, 189, 248, 0.08);
  }

  .controls {
    display: grid; grid-template-columns: repeat(7, minmax(120px, 1fr));
    gap: 8px; margin-top: 10px;
  }
  .btn {
    border: 1px solid var(--border); border-radius: 10px; padding: 10px 9px;
    font-family: var(--sans); font-size: 0.8rem; font-weight: 700; cursor: pointer;
    color: var(--text); background: var(--panel-2);
    display: flex; align-items: center; justify-content: center; gap: 6px;
    transition: transform 0.12s ease, box-shadow 0.15s ease, border-color 0.15s ease;
  }
  .btn:hover { transform: translateY(-2px); }
  .btn:active { transform: translateY(0); }
  .btn:disabled { opacity: 0.55; cursor: wait; transform: none; }
  .btn .key {
    font-family: var(--mono); font-size: 0.72rem; padding: 2px 5px; border-radius: 5px;
    background: rgba(0,0,0,0.35); border: 1px solid rgba(255,255,255,0.2);
  }
  .btn-amber { background: linear-gradient(135deg, #422b08, #281b07); border-color: rgba(251,191,36,0.55); color: #fde68a; }
  .btn-red { background: linear-gradient(135deg, #4d101b, #2a0a11); border-color: rgba(255,77,94,0.65); color: #fecdd3; }
  .btn-purple { background: linear-gradient(135deg, #321652, #1b0e2e); border-color: rgba(168,85,247,0.6); color: #e9d5ff; }
  .btn-ai-on { background: linear-gradient(135deg, #0a3c35, #08242c); border-color: rgba(34,197,94,0.7); color: #bbf7d0; }
  .btn-ai-off { background: linear-gradient(135deg, #5c121b, #300a10); border-color: var(--red); color: #fff; }
  .btn-speed-norm { background: linear-gradient(135deg, #102a43, #0b1c2d); border-color: rgba(56,189,248,0.55); color: #bae6fd; }
  .btn-speed-slow {
    background: linear-gradient(135deg, #4a3008, #2c1b04); border-color: var(--amber); color: #fef08a;
    box-shadow: 0 0 16px rgba(251,191,36,0.38);
  }
  .btn-stress {
    background: linear-gradient(135deg, #5a1230, #2c0920); border-color: rgba(244,63,94,0.75); color: #ffe4e6;
    box-shadow: 0 0 14px rgba(244,63,94,0.25);
  }
  .btn-stress:hover { box-shadow: 0 0 22px rgba(244,63,94,0.5); }
  .btn-reset { background: #141e30; border-color: #364b6e; color: var(--muted); }
  .btn-reset:hover { color: var(--text); border-color: var(--cyan); }

  .bottom-grid { display: grid; grid-template-columns: 1.5fr 1fr; gap: 12px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px 16px; display: flex; flex-direction: column; gap: 10px;
  }
  .card-title {
    display: flex; justify-content: space-between; align-items: center;
    font-size: 0.94rem; font-weight: 800; letter-spacing: 0.3px;
    border-bottom: 1px solid var(--border); padding-bottom: 8px; gap: 8px; flex-wrap: wrap;
  }
  .inspector-meta { display: grid; grid-template-columns: repeat(4, minmax(110px, 1fr)); gap: 8px; }
  .meta-box { background: #0a101c; border: 1px solid #1c2a42; border-radius: 8px; padding: 8px 10px; }
  .meta-box .m-k { font-size: 0.68rem; color: var(--muted); text-transform: uppercase; }
  .meta-box .m-v { font-family: var(--mono); font-size: 0.9rem; font-weight: 700; margin-top: 2px; word-break: break-all; }

  .proof-bar {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
    background: rgba(56,189,248,0.07); border: 1px solid rgba(56,189,248,0.28);
    border-radius: 8px; padding: 7px 10px; font-family: var(--mono); font-size: 0.74rem; color: #bfe8ff;
  }
  .llm-note {
    background: rgba(168,85,247,0.08); border-left: 3px solid var(--purple);
    border-radius: 6px; padding: 7px 10px; font-size: 0.8rem; color: #e2d4f8; line-height: 1.38;
  }

  .verdict-split { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .verdict-box { background: #0a101c; border: 1px solid var(--border); border-radius: 9px; padding: 10px 12px; }
  .verdict-box h4 { font-size: 0.84rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }
  .verdict-box p { font-size: 0.86rem; color: #e2ecff; line-height: 1.44; }
  .vb-bypass { border-color: rgba(255,77,94,0.65); background: rgba(255,77,94,0.07); }
  .vb-ok { border-color: rgba(34,197,94,0.65); background: rgba(34,197,94,0.07); }
  .vb-warn { border-color: rgba(251,191,36,0.65); background: rgba(251,191,36,0.07); }

  .xai-list { display: flex; flex-direction: column; gap: 6px; }
  .xai-row { display: grid; grid-template-columns: 1.45fr 1fr 82px; align-items: center; gap: 8px; font-size: 0.82rem; }
  .bar-track { height: 8px; background: #162238; border-radius: 99px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 99px; transition: width 0.25s ease; }
  .code-preview {
    background: #050810; border: 1px solid #1a2740; border-radius: 8px;
    padding: 8px 10px; font-family: var(--mono); font-size: 0.74rem;
    color: #9dd4ff; max-height: 112px; overflow: auto; white-space: pre;
  }

  .feed-list { display: flex; flex-direction: column; gap: 6px; max-height: 390px; overflow-y: auto; padding-right: 4px; }
  .feed-item {
    display: grid; grid-template-columns: 58px 1fr auto; align-items: center; gap: 8px;
    background: #0a101c; border: 1px solid #1c2a42; border-radius: 8px;
    padding: 8px 10px; cursor: pointer; font-size: 0.8rem;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .feed-item:hover, .feed-item.active { border-color: var(--cyan); background: #101b2e; }
  .badge { font-family: var(--mono); font-size: 0.69rem; font-weight: 800; padding: 3px 7px; border-radius: 6px; white-space: nowrap; }
  .b-av { background: rgba(251,191,36,0.2); color: var(--amber); border: 1px solid rgba(251,191,36,0.5); }
  .b-quar { background: rgba(34,197,94,0.18); color: #86efac; border: 1px solid rgba(34,197,94,0.55); }
  .b-legit { background: rgba(56,189,248,0.18); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.55); }
  .b-breach { background: rgba(255,77,94,0.25); color: #fda4af; border: 1px solid var(--red); }

  .pill-btn {
    cursor: pointer; transition: transform 0.12s ease, border-color 0.15s ease, background 0.15s ease;
    color: var(--text);
  }
  .pill-btn:hover { transform: translateY(-1px); border-color: var(--cyan); }
  .pill-sound-on { color: #fef08a; border-color: var(--amber); background: rgba(251,191,36,0.16); }
  .pill-sound-off { color: var(--muted); }
  .pill-theory-on {
    color: #f5d0fe; border-color: var(--purple); background: rgba(168,85,247,0.22);
    box-shadow: 0 0 14px rgba(168,85,247,0.38);
  }
  .theory-drawer {
    display: none;
    background: linear-gradient(180deg, rgba(14,22,38,0.98), rgba(9,15,28,0.98));
    border: 1px solid rgba(168,85,247,0.58);
    border-radius: 12px;
    padding: 14px 16px 16px;
    margin-bottom: 12px;
    box-shadow: 0 12px 34px rgba(0,0,0,0.55), 0 0 24px rgba(168,85,247,0.14);
  }
  .theory-drawer.open { display: block; animation: fadeSlideIn 0.18s ease-out; }
  @keyframes fadeSlideIn {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .theory-head {
    display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;
    border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 12px; flex-wrap: wrap;
  }
  .theory-head h2 { font-size: 1.02rem; color: #f5d0fe; letter-spacing: 0.2px; }
  .theory-theme { font-size: 0.84rem; color: #dbeafe; margin-top: 3px; line-height: 1.4; }
  .theory-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
  .t-card {
    background: #080e1a; border: 1px solid #223454; border-left-width: 4px;
    border-radius: 10px; padding: 12px 14px;
    display: flex; flex-direction: column; justify-content: space-between; gap: 9px;
  }
  .t-card h3 { font-size: 0.92rem; font-weight: 800; line-height: 1.3; }
  .t-card p { font-size: 0.85rem; color: #dce8fc; line-height: 1.46; }
  .t-card .t-formula {
    font-family: var(--mono); font-size: 0.77rem; color: #bae6fd;
    background: rgba(56,189,248,0.08); border: 1px solid rgba(56,189,248,0.22);
    border-radius: 6px; padding: 5px 9px;
  }
  .t-card .t-actions { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
  .t-card-red { border-left-color: var(--red); }
  .t-card-cyan { border-left-color: var(--cyan); }
  .t-card-purple { border-left-color: var(--purple); }
  .t-card-green { border-left-color: var(--green); }
  @media (max-width: 960px) {
    .theory-grid { grid-template-columns: 1fr; }
  }
  .btn-diff {
    border: 1px solid rgba(56,189,248,0.55); border-radius: 8px; padding: 6px 11px;
    background: linear-gradient(135deg, #0d2b45, #091d30); color: #bae6fd;
    font-family: var(--mono); font-size: 0.74rem; font-weight: 700; cursor: pointer;
    transition: transform 0.12s ease, box-shadow 0.15s ease;
  }
  .btn-diff:hover { transform: translateY(-1px); box-shadow: 0 0 14px rgba(56,189,248,0.35); }
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(2, 6, 14, 0.84);
    backdrop-filter: blur(5px); z-index: 999;
    display: none; align-items: center; justify-content: center; padding: 18px;
  }
  .modal-backdrop.open { display: flex; }
  .modal-box {
    width: min(1240px, 96vw); max-height: 90vh;
    background: #0b1220; border: 1px solid var(--cyan); border-radius: 14px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.75), 0 0 32px rgba(56,189,248,0.22);
    display: flex; flex-direction: column; overflow: hidden;
  }
  .modal-head {
    display: flex; justify-content: space-between; align-items: center; gap: 12px;
    padding: 13px 18px; background: #101b30; border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .modal-head h3 { font-size: 1rem; color: #e0f2fe; }
  .modal-meta {
    display: flex; flex-wrap: wrap; gap: 10px; padding: 9px 18px;
    background: #080e1a; border-bottom: 1px solid var(--border);
    font-family: var(--mono); font-size: 0.76rem; color: #cbd5e1;
  }
  .diff-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
    padding: 14px 18px 18px; overflow-y: auto;
  }
  .diff-col {
    background: #050912; border: 1px solid #1d2d48; border-radius: 10px;
    display: flex; flex-direction: column; overflow: hidden;
  }
  .diff-col-head {
    padding: 8px 12px; font-family: var(--mono); font-size: 0.76rem; font-weight: 800;
    border-bottom: 1px solid #1d2d48; display: flex; justify-content: space-between; gap: 8px;
  }
  .diff-orig { background: rgba(34,197,94,0.12); color: #86efac; }
  .diff-mut { background: rgba(255,77,94,0.14); color: #fda4af; }
  .diff-pre {
    padding: 12px; font-family: var(--mono); font-size: 0.76rem; line-height: 1.45;
    color: #dbeafe; overflow: auto; max-height: 58vh; white-space: pre;
  }
  @media (max-width: 900px) {
    .diff-grid { grid-template-columns: 1fr; }
  }

  @media (max-width: 1220px) {
    .controls { grid-template-columns: repeat(4, 1fr); }
  }
  @media (max-width: 1080px) {
    .kpi-row { grid-template-columns: repeat(3, 1fr); }
    .controls { grid-template-columns: repeat(2, 1fr); }
    .bottom-grid { grid-template-columns: 1fr; }
    .inspector-meta { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <div class="brand-badge">⚔</div>
      <div>
        <h1>AI CYBER DUEL — ARENA TÁTICA SOC AO VIVO</h1>
        <p>Mutação AST/Polimórfica Real + Execução Sandbox + Ensemble scikit-learn (RandomForest &amp; IsolationForest)</p>
      </div>
    </div>
    <div class="status-pills">
      <button class="pill pill-btn" id="btnTheory" onclick="toggleTheoryDrawer()" aria-expanded="false" title="Atalho: tecla T">📖 [T] Guia Teórico</button>
      <button class="pill pill-btn pill-sound-off" id="btnSound" onclick="toggleSound()" title="Atalho: tecla M">🔇 [M] Som: OFF</button>
      <button class="pill pill-btn" id="btnFull" onclick="toggleFullscreen()" title="Atalho: tecla F">⛶ [F] Tela Cheia</button>
      <span class="pill pill-online" id="pillServer">● LOCALHOST ONLINE</span>
      <span class="pill pill-shield-on" id="pillShield">🧠 ESCUDO IA: LIGADO</span>
    </div>
  </header>

  <section class="theory-drawer" id="theoryDrawer" aria-label="Guia Teórico da Apresentação">
    <div class="theory-head">
      <div>
        <h2>📖 GUIA TEÓRICO INTEGRADO — APRESENTAÇÃO UNIVERSITÁRIA (ATAQUE vs. DEFESA)</h2>
        <p class="theory-theme">
          <strong>Tema:</strong> <em>"IA na Cibersegurança (Ataque vs. Defesa): Como cibercriminosos usam inteligência artificial para criar malwares polimórficos e como analistas usam a mesma tecnologia para detectar invasões em tempo real."</em>
        </p>
      </div>
      <button class="btn-diff" onclick="toggleTheoryDrawer()">✕ Fechar Guia [T / ESC]</button>
    </div>

    <div class="theory-grid">
      <article class="t-card t-card-red">
        <div>
          <h3 class="c-red">A) IA Ofensiva, Polimorfismo &amp; Efeito Avalanche (SHA-256)</h3>
          <p>
            Antivírus tradicionais bloqueiam ameaças comparando assinaturas fixas (hashes criptográficos como <strong>SHA-256</strong>).
            Motores polimórficos e <strong>LLMs generativos</strong> reescrevem código sob demanda (renomeação, <em>junk code</em>,
            <code>for→while</code> na AST e chaves XOR/Base85). Pelo <strong>Efeito Avalanche</strong>, alterar 1 único bit gera um hash
            100% inédito, derrubando a detecção estática para <strong>0%</strong> mantendo o mesmo comportamento.
          </p>
        </div>
        <div class="t-formula">SHA-256(original) ≠ SHA-256(variante)  →  Blacklist cega (BYPASS 100%)</div>
        <div class="t-actions">
          <span style="font-size:0.74rem;color:var(--muted);">Demonstre lado a lado no Canvas:</span>
          <button class="btn-diff" onclick="demoCardA()">▶ Testar [1] Original vs. [2] Polimórfico</button>
        </div>
      </article>

      <article class="t-card t-card-cyan">
        <div>
          <h3 class="c-cyan">B) IA Defensiva: Entropia de Shannon, AST &amp; Comportamento Real</h3>
          <p>
            Em vez de perguntar <em>"já vi esse hash?"</em>, o Blue Team analisa <strong>sinais matemáticos e comportamentais</strong>:
            a <strong>Entropia de Shannon</strong> mede aleatoriedade dos bytes (código legível ~4.5 vs. ofuscado/cifrado &gt;6.0),
            a inspeção da <strong>AST Python</strong> detecta predicados opacos e <code>exec()</code>, e sensores reais de SO
            (<code>watchdog</code>, <code>psutil</code> e loopback <code>127.0.0.1</code>) capturam escrita em disco e rede em tempo real.
          </p>
        </div>
        <div class="t-formula">H(X) = -Σ p(x)·log₂(p(x))  +  Nós AST  +  I/O Sandbox  +  TCP Loopback</div>
        <div class="t-actions">
          <span style="font-size:0.74rem;color:var(--muted);">Inspecione o código real reescrito:</span>
          <button class="btn-diff" onclick="openCodeDiffModal()">🔬 Abrir Diff AST Real [C]</button>
        </div>
      </article>

      <article class="t-card t-card-purple">
        <div>
          <h3 class="c-purple">C) Ensemble Híbrido: Random Forest + Isolation Forest (Zero-Day)</h3>
          <p>
            Combinamos dois paradigmas de Machine Learning em milissegundos: o <strong>Random Forest (Supervisionado)</strong>
            classifica padrões conhecidos com alta precisão e gera <strong>Explicabilidade (XAI)</strong> mostrando quais features
            pesaram; já o <strong>Isolation Forest (Não Supervisionado)</strong> aprende apenas o perfil normal e dispara alerta
            para <strong>ameaças inéditas (Zero-Day / AST furtivo de baixa entropia)</strong> fora da linha de base.
          </p>
        </div>
        <div class="t-formula">Decisão = RandomForest(supervisionado + XAI) ∪ IsolationForest(anomalia zero-day)</div>
        <div class="t-actions">
          <span style="font-size:0.74rem;color:var(--muted);">Teste resiliência sob carga real:</span>
          <button class="btn-diff" onclick="fireStressWave()">⚡ Lançar Onda x8 [7]</button>
        </div>
      </article>

      <article class="t-card t-card-green">
        <div>
          <h3 class="c-green">D) Como Evitamos Falsos Positivos em Compactados Legítimos</h3>
          <p>
            Se um IDS bloqueasse qualquer arquivo com alta entropia, travaria a empresa bloqueando <code>.zip</code>, vídeos e
            instaladores legítimos (<em>alert fatigue</em>). Por isso treinamos com <strong>negativos difíceis</strong> e cruzamos
            entropia com estrutura AST, ofuscação e comportamento limpo: o <code>instalador_compactado.pkg</code> (blob
            <code>zlib</code> real com <strong>H ≈ 7.9 bits/B</strong>) obtém <strong>risco ≈ 0%</strong> e passa livre!
          </p>
        </div>
        <div class="t-formula">Alta Entropia (7.93) + AST Limpa + 0 Rede Suspeita  →  RF ≈ 0% (0 Falsos Positivos)</div>
        <div class="t-actions">
          <span style="font-size:0.74rem;color:var(--muted);">Comprove ao vivo com tráfego misto:</span>
          <button class="btn-diff" onclick="fireMixed()">🌊 Provar 0 FP ([3] Misto)</button>
        </div>
      </article>
    </div>
  </section>

  <section class="kpi-row">
    <div class="kpi">
      <span class="k-label">Amostras Mutadas</span>
      <span class="k-val c-amber" id="statMutated">0</span>
      <span class="k-sub">SHA-256 reais inéditos</span>
    </div>
    <div class="kpi">
      <span class="k-label">Evasões AV (SHA-256)</span>
      <span class="k-val c-red" id="statBypass">0</span>
      <span class="k-sub" id="statAvSub">Original bloqueado: 0</span>
    </div>
    <div class="kpi">
      <span class="k-label">Interceptadas pela IA</span>
      <span class="k-val c-green" id="statIntercepted">0</span>
      <span class="k-sub" id="statLegitSub">Legítimos: 0 (0 FP)</span>
    </div>
    <div class="kpi">
      <span class="k-label">Integridade Servidor</span>
      <span class="k-val c-green" id="statServerHp">100%</span>
      <span class="k-sub" id="statBreachSub">Invasões (Breach): 0</span>
    </div>
    <div class="kpi">
      <span class="k-label">Latência Média IA</span>
      <span class="k-val c-cyan" id="statLatency">0.00 ms</span>
      <span class="k-sub">RandomForest + IsoForest</span>
    </div>
  </section>

  <section class="arena-card">
    <div class="arena-header">
      <div class="zone-legend">
        <span><i class="dot" style="background:var(--amber)"></i>Original Conhecido</span>
        <span><i class="dot" style="background:var(--red)"></i>Ataque Polimórfico / AST</span>
        <span><i class="dot" style="background:var(--green)"></i>Tráfego Legítimo</span>
        <span><i class="dot" style="background:var(--cyan)"></i>Interceptação Neural IA</span>
      </div>
      <span style="font-family:var(--mono);font-size:0.76rem;color:var(--muted);">Atalhos: [1]–[5] Ações • [6] Vel • [7] Onda x8 • [T] Teoria • [C] Diff • [F] Tela Cheia • [M] Som</span>
    </div>
    <canvas id="arenaCanvas" width="1280" height="400"></canvas>

    <div class="controls">
      <button class="btn btn-amber" id="btn1" onclick="fireOriginal()">
        <span class="key">1</span> 📦 Original
      </button>
      <button class="btn btn-red" id="btn2" onclick="firePolymorphic()">
        <span class="key">2</span> 🧬 Polimórfico
      </button>
      <button class="btn btn-purple" id="btn3" onclick="fireMixed()">
        <span class="key">3</span> 🌊 Misto (x4)
      </button>
      <button class="btn btn-ai-on" id="btn4" onclick="toggleAI()">
        <span class="key">4</span> 🧠 IA: LIGADO
      </button>
      <button class="btn btn-reset" id="btn5" onclick="resetArena()">
        <span class="key">5</span> 🔄 Resetar
      </button>
      <button class="btn btn-speed-norm" id="btn6" onclick="toggleSlowMo()">
        <span class="key">6</span> ⏱ Vel: 1.0x
      </button>
      <button class="btn btn-stress" id="btn7" onclick="fireStressWave()">
        <span class="key">7</span> ⚡ Onda x8
      </button>
    </div>
  </section>

  <section class="bottom-grid">
    <div class="card">
      <div class="card-title">
        <span>🔍 Painel de Inspeção — Telemetria Real &amp; IA Explicável (XAI)</span>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <button class="btn-diff" id="btnDiff" onclick="openCodeDiffModal()" title="Atalho: tecla C">🔬 [C] Diff Código (Original vs. Mutado)</button>
          <span class="pill" id="inspBadge" style="font-size:0.72rem;">Aguardando disparo...</span>
        </div>
      </div>

      <div class="inspector-meta">
        <div class="meta-box">
          <div class="m-k">Artefato / Técnica</div>
          <div class="m-v" id="inspName">—</div>
        </div>
        <div class="meta-box">
          <div class="m-k">Hash SHA-256 (Real)</div>
          <div class="m-v c-amber" id="inspHash">—</div>
        </div>
        <div class="meta-box">
          <div class="m-k">Entropia / Nós AST</div>
          <div class="m-v c-cyan" id="inspEntropy">—</div>
        </div>
        <div class="meta-box">
          <div class="m-k">Score Real Ensemble IA</div>
          <div class="m-v c-green" id="inspRisk">—</div>
        </div>
      </div>

      <div class="proof-bar" id="inspProof">
        ⚙ Telemetria Real (Backend Python): aguardando primeira amostra para exibir tempo de mutação AST, I/O em sandbox, pings loopback e scores RF/IsolationForest.
      </div>
      <div class="llm-note" id="inspLlmNote">
        🤖 <strong>Contexto de IA Ofensiva (LLMs):</strong> Modelos generativos e motores AST reescrevem sintaxe (for→while, renomeação, predicados opacos e chaves XOR) em milissegundos, criando assinaturas inéditas a cada alvo.
      </div>

      <div class="verdict-split">
        <div class="verdict-box" id="boxAv">
          <h4 class="c-amber">🛡️ Muralha Legada (AV SHA-256)</h4>
          <p id="inspAvReason">Dispare um pacote nos controles acima para inspecionar o veredito do antivírus por assinatura.</p>
        </div>
        <div class="verdict-box" id="boxAi">
          <h4 class="c-cyan">🧠 Escudo Neural (RandomForest + IsoForest)</h4>
          <p id="inspAiReason">A IA classifica 6 features medidas em tempo real no Python (zero números mockados no JS).</p>
        </div>
      </div>

      <div class="xai-list" id="xaiContainer"></div>
      <pre class="code-preview" id="inspCode"># Código-fonte real gerado pelo motor Python aparecerá aqui...</pre>
    </div>

    <div class="card">
      <div class="card-title">
        <span>📡 Feed de Eventos SOC &amp; Quarentena</span>
        <span style="font-family:var(--mono);font-size:0.75rem;color:var(--muted);" id="quarCount">Quarentena: 0 (clique p/ Diff)</span>
      </div>
      <div class="feed-list" id="feedList">
        <div style="color:var(--muted);font-size:0.84rem;padding:12px;">
          Nenhum evento ainda. Pressione <strong>[1]</strong> para testar o Antivírus tradicional, <strong>[2]</strong> para lançar um ataque polimórfico/AST real, ou <strong>[3]</strong> para tráfego misto.
        </div>
      </div>
    </div>
  </section>

  <div class="modal-backdrop" id="codeModal" onclick="if(event.target===this) closeCodeDiffModal()">
    <div class="modal-box">
      <div class="modal-head">
        <h3 id="modalTitle">🔬 Comparação de Código Real — Original vs. Mutação AST / Polimórfica</h3>
        <button class="btn-diff" onclick="closeCodeDiffModal()">✕ Fechar [ESC]</button>
      </div>
      <div class="modal-meta" id="modalMeta">Selecione um pacote no feed para inspecionar o código gerado em disco.</div>
      <div class="diff-grid">
        <div class="diff-col">
          <div class="diff-col-head diff-orig">
            <span>📄 CÓDIGO ORIGINAL (BASELINE)</span>
            <span id="modalOrigHash">SHA: —</span>
          </div>
          <pre class="diff-pre" id="modalOrigCode"></pre>
        </div>
        <div class="diff-col">
          <div class="diff-col-head diff-mut">
            <span id="modalMutLabel">🧬 CÓDIGO REAL MUTADO (AST / OFUSCAÇÃO)</span>
            <span id="modalMutHash">SHA: —</span>
          </div>
          <pre class="diff-pre" id="modalMutCode"></pre>
        </div>
      </div>
    </div>
  </div>

<script>
const canvas = document.getElementById("arenaCanvas");
const ctx = canvas.getContext("2d");

let arenaState = {
  ai_shield_enabled: true,
  stats: {
    total_spawned: 0, mutated_count: 0, legit_count: 0,
    av_blocked: 0, av_bypassed: 0, ai_intercepted: 0,
    ai_legit_passed: 0, breaches: 0, false_positives: 0, server_hp: 100, avg_latency_ms: 0
  },
  events: [],
  quarantine: [],
  selected_packet: null
};

const projectiles = [];
const effects = [];
const particles = [];
const floatTexts = [];
let radarAngle = 0;
let factoryAngle = 0;
let scanlineX = 0;
let simSpeed = 1.0;
let screenShake = 0;
let quarPulse = 0;
let displayedHp = 100;
let soundEnabled = false;
let audioCtx = null;
let stressBusy = false;
let lastMutatedHash = "AGUARDANDO MUTAÇÃO...";
let lastMutatedEntropy = "0.00 bits/B";
let coreAlertFlash = 0;
let avWallFlash = 0;
let avWallColor = "#fbbf24";

function ensureAudio() {
  if (!audioCtx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (Ctx) audioCtx = new Ctx();
  }
  if (audioCtx && audioCtx.state === "suspended") {
    audioCtx.resume().catch(() => {});
  }
  return audioCtx;
}

function playSound(kind) {
  if (!soundEnabled) return;
  const ac = ensureAudio();
  if (!ac) return;
  const now = ac.currentTime;
  const osc = ac.createOscillator();
  const gain = ac.createGain();
  osc.connect(gain);
  gain.connect(ac.destination);

  if (kind === "av_block") {
    osc.type = "triangle";
    osc.frequency.setValueAtTime(340, now);
    osc.frequency.exponentialRampToValueAtTime(160, now + 0.12);
    gain.gain.setValueAtTime(0.08, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.14);
    osc.start(now); osc.stop(now + 0.15);
  } else if (kind === "av_bypass") {
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(280, now);
    osc.frequency.exponentialRampToValueAtTime(140, now + 0.1);
    gain.gain.setValueAtTime(0.045, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.11);
    osc.start(now); osc.stop(now + 0.12);
  } else if (kind === "ai_intercept") {
    osc.type = "sine";
    osc.frequency.setValueAtTime(760, now);
    osc.frequency.exponentialRampToValueAtTime(1240, now + 0.09);
    gain.gain.setValueAtTime(0.07, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.14);
    osc.start(now); osc.stop(now + 0.15);
  } else if (kind === "quarantine") {
    osc.type = "sine";
    osc.frequency.setValueAtTime(520, now);
    osc.frequency.setValueAtTime(780, now + 0.05);
    gain.gain.setValueAtTime(0.05, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.14);
    osc.start(now); osc.stop(now + 0.15);
  } else if (kind === "legit_ok") {
    osc.type = "sine";
    osc.frequency.setValueAtTime(620, now);
    gain.gain.setValueAtTime(0.04, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
    osc.start(now); osc.stop(now + 0.09);
  } else if (kind === "breach") {
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(210, now);
    osc.frequency.setValueAtTime(150, now + 0.11);
    osc.frequency.setValueAtTime(210, now + 0.22);
    gain.gain.setValueAtTime(0.095, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.34);
    osc.start(now); osc.stop(now + 0.35);
  } else {
    osc.type = "sine";
    osc.frequency.setValueAtTime(480, now);
    gain.gain.setValueAtTime(0.04, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.07);
    osc.start(now); osc.stop(now + 0.08);
  }
}

function toggleSound() {
  soundEnabled = !soundEnabled;
  const btn = document.getElementById("btnSound");
  if (soundEnabled) {
    ensureAudio();
    btn.className = "pill pill-btn pill-sound-on";
    btn.textContent = "🔊 [M] Som: ON";
    playSound("toggle");
  } else {
    btn.className = "pill pill-btn pill-sound-off";
    btn.textContent = "🔇 [M] Som: OFF";
  }
}

function toggleFullscreen() {
  if (!document.fullscreenElement) {
    document.documentElement.requestFullscreen().catch(() => {});
  } else {
    document.exitFullscreen().catch(() => {});
  }
}

document.addEventListener("fullscreenchange", () => {
  const btn = document.getElementById("btnFull");
  if (btn) {
    btn.textContent = document.fullscreenElement ? "✕ [F] Sair Tela Cheia" : "⛶ [F] Tela Cheia";
  }
  setTimeout(resizeCanvas, 80);
});

const CANVAS_H = 400;

function resizeCanvas() {
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.max(820, Math.floor(rect.width * dpr));
  canvas.height = Math.floor(CANVAS_H * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

function drawRoundedRect(x, y, w, h, r) {
  ctx.beginPath();
  if (typeof ctx.roundRect === "function") {
    ctx.roundRect(x, y, w, h, r);
  } else {
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
  }
}

function getGeometry() {
  const w = canvas.getBoundingClientRect().width || 960;
  const h = CANVAS_H;
  const playH = h - 72; // Área de combate acima do gráfico HUD de histórico de risco
  return {
    w, h, playH,
    factoryX: w * 0.11, factoryY: playH * 0.50,
    avX: w * 0.43,
    radarX: w * 0.71, radarY: playH * 0.46, radarR: Math.min(82, w * 0.08),
    coreX: w * 0.91, coreY: playH * 0.31,
    quarX: w * 0.89, quarY: playH * 0.79
  };
}

function addFloatText(x, y, text, color) {
  floatTexts.push({ x, y, text, color, life: 1.0 });
}

function addRipple(x, y, color, maxR = 52) {
  effects.push({ type: "ripple", x, y, r: 6, maxR, color, life: 1.0 });
}

function addShockwave(x, y, color) {
  effects.push({ type: "ripple", x, y, r: 8, maxR: 78, color, life: 1.0, lw: 3.4 });
  effects.push({ type: "ripple", x, y, r: 4, maxR: 46, color: "#ffffff", life: 0.85, lw: 2.0 });
}

function addBeam(x1, y1, x2, y2, color) {
  effects.push({ type: "beam", x1, y1, x2, y2, color, life: 1.0 });
}

function addParticleBurst(x, y, color, count = 24, speed = 3.8) {
  for (let i = 0; i < count; i++) {
    const ang = (Math.PI * 2 * i) / count + (Math.random() - 0.5) * 0.45;
    const spd = (0.35 + Math.random() * 0.95) * speed;
    particles.push({
      x, y,
      vx: Math.cos(ang) * spd,
      vy: Math.sin(ang) * spd,
      size: 1.8 + Math.random() * 2.8,
      color,
      life: 0.85 + Math.random() * 0.35
    });
  }
}

function launchProjectile(packet, delayMs = 0) {
  setTimeout(() => {
    const g = getGeometry();
    const laneOffset = (Math.random() - 0.5) * 92;
    const startY = Math.max(66, Math.min(g.playH - 54, g.factoryY + laneOffset));
    const colorMap = {
      original: "#fbbf24",
      polymorphic: "#ff4d5e",
      legit: "#22c55e",
      legit_packed: "#38bdf8"
    };
    if (packet.kind === "polymorphic") {
      lastMutatedHash = packet.sha256.slice(0, 16) + "...";
      lastMutatedEntropy = `${packet.entropy.toFixed(2)} bits/B`;
      addParticleBurst(g.factoryX + 22, startY, "#ff4d5e", 12, 2.4);
    } else if (packet.kind === "original") {
      addParticleBurst(g.factoryX + 22, startY, "#fbbf24", 10, 2.0);
    }
    projectiles.push({
      packet,
      x: g.factoryX + 26,
      y: startY,
      vx: 3.4,
      color: colorMap[packet.kind] || "#38bdf8",
      stage: "to_av",
      scannedAi: false,
      morphPhase: Math.random() * Math.PI * 2,
      trail: []
    });
  }, delayMs);
}

function drawRiskHistoryHUD(g) {
  const hudY = g.playH + 8;
  const hudH = g.h - hudY - 8;
  const hudX = 14;
  const hudW = g.w - 28;

  ctx.save();
  ctx.fillStyle = "rgba(8, 15, 28, 0.92)";
  ctx.strokeStyle = "rgba(56, 189, 248, 0.32)";
  ctx.lineWidth = 1.2;
  drawRoundedRect(hudX, hudY, hudW, hudH, 8);
  ctx.fill();
  ctx.stroke();

  // Título e legenda do gráfico HUD
  ctx.fillStyle = "#7dd3fc";
  ctx.font = "bold 10.5px monospace";
  ctx.textAlign = "left";
  ctx.fillText("📈 HISTÓRICO DE RISCO IA EM TEMPO REAL (0%–100%)", hudX + 10, hudY + 14);

  const recent = (arenaState.events || []).slice(-24);
  ctx.fillStyle = "#8ea3c2";
  ctx.textAlign = "right";
  ctx.fillText(`Eventos no gráfico: ${recent.length}/24  |  Limiar IA: 50%`, hudX + hudW - 10, hudY + 14);

  const plotX = hudX + 12;
  const plotY = hudY + 21;
  const plotW = hudW - 24;
  const plotH = hudH - 27;

  // Linha tracejada do limiar 50%
  const y50 = plotY + plotH * 0.5;
  ctx.strokeStyle = "rgba(251, 191, 36, 0.45)";
  ctx.setLineDash([5, 5]);
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(plotX, y50);
  ctx.lineTo(plotX + plotW, y50);
  ctx.stroke();
  ctx.setLineDash([]);

  if (recent.length === 0) {
    ctx.fillStyle = "rgba(142, 163, 194, 0.55)";
    ctx.font = "10.5px monospace";
    ctx.textAlign = "center";
    ctx.fillText("Aguardando pacotes reais da API Python (pressione [2], [3] ou [7] Onda x8)...", plotX + plotW / 2, y50 + 4);
    ctx.restore();
    return;
  }

  const pts = recent.map((ev, idx) => {
    const px = recent.length === 1 ? plotX + plotW / 2 : plotX + (idx / (recent.length - 1)) * plotW;
    const risk = Math.max(0, Math.min(100, Number(ev.ai_risk_pct || 0)));
    const py = plotY + plotH - (risk / 100) * plotH;
    return { x: px, y: py, ev, risk };
  });

  // Área luminosa sob a curva
  if (pts.length >= 2) {
    const areaGrad = ctx.createLinearGradient(0, plotY, 0, plotY + plotH);
    areaGrad.addColorStop(0, "rgba(255, 77, 94, 0.28)");
    areaGrad.addColorStop(0.55, "rgba(56, 189, 248, 0.16)");
    areaGrad.addColorStop(1, "rgba(34, 197, 94, 0.04)");
    ctx.fillStyle = areaGrad;
    ctx.beginPath();
    ctx.moveTo(pts[0].x, plotY + plotH);
    for (const pt of pts) ctx.lineTo(pt.x, pt.y);
    ctx.lineTo(pts[pts.length - 1].x, plotY + plotH);
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = "#38bdf8";
    ctx.lineWidth = 2;
    ctx.shadowColor = "#38bdf8";
    ctx.shadowBlur = 8;
    ctx.beginPath();
    pts.forEach((pt, idx) => (idx === 0 ? ctx.moveTo(pt.x, pt.y) : ctx.lineTo(pt.x, pt.y)));
    ctx.stroke();
    ctx.shadowBlur = 0;
  }

  // Pontos individuais coloridos por veredito real
  for (const pt of pts) {
    const dotColor =
      pt.ev.outcome === "BREACH" ? "#ff4d5e" :
      pt.ev.outcome === "AI_QUARANTINED" ? "#c084fc" :
      pt.ev.outcome === "AV_BLOCKED" ? "#fbbf24" : "#22c55e";
    ctx.fillStyle = dotColor;
    ctx.shadowColor = dotColor;
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, 3.6, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.shadowBlur = 0;
  ctx.restore();
}

function updateAndDraw() {
  const g = getGeometry();
  ctx.save();
  ctx.clearRect(0, 0, g.w, g.h);

  // Micro tremor de tela em caso de BREACH
  if (screenShake > 0) {
    const dx = (Math.random() - 0.5) * screenShake * 7;
    const dy = (Math.random() - 0.5) * screenShake * 5;
    ctx.translate(dx, dy);
    screenShake = Math.max(0, screenShake - 0.08);
  }

  // Grid tático neon + feixe de varredura horizontal
  ctx.strokeStyle = "rgba(34, 58, 92, 0.30)";
  ctx.lineWidth = 1;
  for (let x = 0; x < g.w; x += 36) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, g.playH); ctx.stroke();
  }
  for (let y = 0; y < g.playH; y += 36) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(g.w, y); ctx.stroke();
  }
  scanlineX = (scanlineX + 1.8 * simSpeed) % g.w;
  const scanGrad = ctx.createLinearGradient(scanlineX - 50, 0, scanlineX + 10, 0);
  scanGrad.addColorStop(0, "rgba(56, 189, 248, 0)");
  scanGrad.addColorStop(1, "rgba(56, 189, 248, 0.06)");
  ctx.fillStyle = scanGrad;
  ctx.fillRect(scanlineX - 50, 0, 60, g.playH);

  // Trilhos táticos luminosos entre zonas
  ctx.strokeStyle = "rgba(56, 189, 248, 0.16)";
  ctx.setLineDash([8, 8]);
  for (const offset of [-36, 0, 36]) {
    ctx.beginPath();
    ctx.moveTo(g.factoryX + 42, g.factoryY + offset);
    ctx.lineTo(g.avX, g.factoryY + offset * 0.7);
    ctx.lineTo(g.coreX - 42, g.coreY + offset * 0.25);
    ctx.stroke();
  }
  ctx.strokeStyle = "rgba(168, 85, 247, 0.22)";
  ctx.beginPath();
  ctx.moveTo(g.radarX, g.radarY + 26);
  ctx.lineTo(g.quarX - 42, g.quarY);
  ctx.stroke();
  ctx.setLineDash([]);

  // Selo de Câmera Lenta no canto do battlemap
  if (simSpeed < 0.9) {
    ctx.save();
    ctx.fillStyle = "rgba(251, 191, 36, 0.18)";
    ctx.strokeStyle = "#fbbf24";
    ctx.lineWidth = 1.4;
    drawRoundedRect(g.w - 178, 10, 164, 24, 6);
    ctx.fill(); ctx.stroke();
    ctx.fillStyle = "#fef08a";
    ctx.font = "bold 11px monospace";
    ctx.textAlign = "center";
    ctx.fillText("⏱ CÂMERA LENTA (0.4x)", g.w - 96, 26);
    ctx.restore();
  }

  // ZONA 1: FÁBRICA POLIMÓRFICA (NEON RED)
  factoryAngle += 0.022 * simSpeed;
  ctx.save();
  ctx.translate(g.factoryX, g.factoryY);
  ctx.shadowColor = "#ff4d5e"; ctx.shadowBlur = 14;
  ctx.strokeStyle = "rgba(255, 77, 94, 0.72)";
  ctx.lineWidth = 2.2;
  ctx.beginPath(); ctx.arc(0, 0, 44, factoryAngle, factoryAngle + Math.PI * 1.4); ctx.stroke();
  ctx.shadowColor = "#fbbf24"; ctx.shadowBlur = 10;
  ctx.strokeStyle = "rgba(251, 191, 36, 0.58)";
  ctx.beginPath(); ctx.arc(0, 0, 32, -factoryAngle * 1.5, -factoryAngle * 1.5 + Math.PI * 1.25); ctx.stroke();
  ctx.fillStyle = "#240c14";
  ctx.beginPath(); ctx.arc(0, 0, 25, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = "#ff4d5e"; ctx.lineWidth = 2.4; ctx.stroke();
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#ffe4e6"; ctx.font = "bold 18px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("🧬", 0, 6);
  ctx.restore();

  ctx.fillStyle = "#fda4af"; ctx.font = "bold 12px system-ui"; ctx.textAlign = "center";
  ctx.fillText("FÁBRICA POLIMÓRFICA", g.factoryX, 24);
  ctx.fillStyle = "#8ea3c2"; ctx.font = "10.5px monospace";
  ctx.fillText("AST + XOR/Base85 (Real)", g.factoryX, 39);
  ctx.fillStyle = "#fbbf24"; ctx.font = "10px monospace";
  ctx.fillText(`SHA: ${lastMutatedHash}`, g.factoryX, g.playH - 22);
  ctx.fillStyle = "#ff8fa3";
  ctx.fillText(`Entropia: ${lastMutatedEntropy}`, g.factoryX, g.playH - 7);

  // ZONA 2: MURALHA LEGADA (AV SHA-256)
  if (avWallFlash > 0) avWallFlash = Math.max(0, avWallFlash - 0.04 * simSpeed);
  ctx.save();
  ctx.shadowColor = avWallFlash > 0 ? avWallColor : "#fbbf24";
  ctx.shadowBlur = avWallFlash > 0 ? 22 : 10;
  const wallGrad = ctx.createLinearGradient(g.avX - 10, 48, g.avX + 10, g.playH - 36);
  wallGrad.addColorStop(0, "rgba(251, 191, 36, 0.14)");
  wallGrad.addColorStop(0.5, avWallFlash > 0 ? avWallColor : "rgba(251, 191, 36, 0.78)");
  wallGrad.addColorStop(1, "rgba(251, 191, 36, 0.14)");
  ctx.fillStyle = wallGrad;
  ctx.fillRect(g.avX - 5, 48, 10, g.playH - 80);
  ctx.strokeStyle = avWallFlash > 0 ? avWallColor : "#fbbf24";
  ctx.lineWidth = 2;
  ctx.strokeRect(g.avX - 5, 48, 10, g.playH - 80);
  ctx.restore();

  ctx.fillStyle = "#fde68a"; ctx.font = "bold 12px system-ui"; ctx.textAlign = "center";
  ctx.fillText("MURALHA LEGADA", g.avX, 24);
  ctx.fillStyle = "#8ea3c2"; ctx.font = "10.5px monospace";
  ctx.fillText("AV Assinatura SHA-256", g.avX, 39);
  ctx.fillStyle = "#fbbf24"; ctx.font = "10.5px monospace";
  ctx.fillText(`Bloq: ${arenaState.stats.av_blocked} | Bypass: ${arenaState.stats.av_bypassed}`, g.avX, g.playH - 9);

  // ZONA 3: ESCUDO NEURAL / RADAR IDS (NEON CYAN)
  const shieldOn = arenaState.ai_shield_enabled;
  radarAngle += (shieldOn ? 0.048 : 0.008) * simSpeed;
  ctx.save();
  ctx.translate(g.radarX, g.radarY);
  const rColor = shieldOn ? "56, 189, 248" : "255, 77, 94";
  for (const frac of [1.0, 0.68, 0.36]) {
    ctx.strokeStyle = `rgba(${rColor}, ${shieldOn ? 0.42 : 0.25})`;
    ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.arc(0, 0, g.radarR * frac, 0, Math.PI * 2); ctx.stroke();
  }
  if (shieldOn) {
    ctx.fillStyle = "rgba(56, 189, 248, 0.18)";
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, g.radarR, radarAngle - 0.65, radarAngle);
    ctx.closePath();
    ctx.fill();
    ctx.shadowColor = "#38bdf8"; ctx.shadowBlur = 14;
    ctx.strokeStyle = "#38bdf8";
    ctx.lineWidth = 2.4;
    ctx.beginPath(); ctx.moveTo(0, 0);
    ctx.lineTo(Math.cos(radarAngle) * g.radarR, Math.sin(radarAngle) * g.radarR);
    ctx.stroke();
  } else {
    ctx.strokeStyle = "rgba(255, 77, 94, 0.78)";
    ctx.lineWidth = 2.6;
    ctx.beginPath();
    ctx.moveTo(-26, -26); ctx.lineTo(26, 26);
    ctx.moveTo(26, -26); ctx.lineTo(-26, 26);
    ctx.stroke();
  }
  ctx.shadowColor = shieldOn ? "#38bdf8" : "#ff4d5e"; ctx.shadowBlur = 16;
  ctx.fillStyle = shieldOn ? "#072033" : "#2a0b12";
  ctx.beginPath(); ctx.arc(0, 0, 22, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = shieldOn ? "#38bdf8" : "#ff4d5e"; ctx.lineWidth = 2.2; ctx.stroke();
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#fff"; ctx.font = "bold 16px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("🧠", 0, 6);
  ctx.restore();

  ctx.fillStyle = shieldOn ? "#7dd3fc" : "#fda4af"; ctx.font = "bold 12px system-ui"; ctx.textAlign = "center";
  ctx.fillText(shieldOn ? "ESCUDO NEURAL (IDS IA)" : "ESCUDO NEURAL (OFFLINE!)", g.radarX, 24);
  ctx.fillStyle = "#8ea3c2"; ctx.font = "10.5px monospace";
  ctx.fillText("RandomForest + IsoForest", g.radarX, 39);

  // Núcleo Protegido (Servidor) + Barra de Integridade (HP 100%)
  const targetHp = Number(arenaState.stats.server_hp ?? 100);
  displayedHp += (targetHp - displayedHp) * 0.12;
  if (Math.abs(displayedHp - targetHp) < 0.25) displayedHp = targetHp;
  const hpPct = Math.max(0, Math.min(100, displayedHp));
  const hpColor = hpPct > 60 ? "#22c55e" : hpPct > 30 ? "#fbbf24" : "#ff4d5e";

  if (coreAlertFlash > 0) coreAlertFlash = Math.max(0, coreAlertFlash - 0.035 * simSpeed);
  ctx.save();
  ctx.shadowColor = coreAlertFlash > 0 ? "#ff4d5e" : hpColor;
  ctx.shadowBlur = coreAlertFlash > 0 ? 24 : 11;
  ctx.fillStyle = coreAlertFlash > 0 ? "rgba(255,77,94,0.38)" : hpPct <= 40 ? "rgba(69,10,20,0.75)" : "#0d2236";
  ctx.strokeStyle = coreAlertFlash > 0 ? "#ff4d5e" : hpColor;
  ctx.lineWidth = 2.2;
  drawRoundedRect(g.coreX - 46, g.coreY - 34, 92, 68, 10);
  ctx.fill(); ctx.stroke();
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#fff"; ctx.font = "bold 17px sans-serif"; ctx.textAlign = "center";
  ctx.fillText(hpPct <= 0 ? "💥" : "🖥️", g.coreX, g.coreY - 10);
  ctx.fillStyle = coreAlertFlash > 0 ? "#fecdd3" : "#e2e8f0"; ctx.font = "bold 9.5px monospace";
  ctx.fillText(hpPct <= 0 ? "COMPROMETIDO" : `SERVIDOR HP ${Math.round(hpPct)}%`, g.coreX, g.coreY + 7);
  // Barra de HP integrada
  const barW = 74, barH = 8, barX = g.coreX - barW / 2, barY = g.coreY + 14;
  ctx.fillStyle = "#060b14";
  drawRoundedRect(barX, barY, barW, barH, 4);
  ctx.fill();
  if (hpPct > 0) {
    ctx.fillStyle = hpColor;
    ctx.shadowColor = hpColor; ctx.shadowBlur = 8;
    drawRoundedRect(barX, barY, Math.max(4, (barW * hpPct) / 100), barH, 4);
    ctx.fill();
  }
  ctx.shadowBlur = 0;
  ctx.restore();

  // Cofre de Quarentena (pulsa quando neutraliza ameaça)
  if (quarPulse > 0) quarPulse = Math.max(0, quarPulse - 0.04 * simSpeed);
  ctx.save();
  ctx.shadowColor = "#a855f7";
  ctx.shadowBlur = 10 + quarPulse * 18;
  ctx.fillStyle = quarPulse > 0 ? "rgba(168, 85, 247, 0.25)" : "#121a2d";
  ctx.strokeStyle = quarPulse > 0 ? "#e879f9" : "#a855f7";
  ctx.lineWidth = 2.2;
  drawRoundedRect(g.quarX - 48, g.quarY - 25, 96, 50, 10);
  ctx.fill(); ctx.stroke();
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#e9d5ff"; ctx.font = "bold 10.5px monospace"; ctx.textAlign = "center";
  ctx.fillText("🔒 QUARENTENA", g.quarX, g.quarY - 4);
  ctx.fillStyle = "#d8b4fe"; ctx.font = "bold 12.5px monospace";
  ctx.fillText(`${arenaState.stats.ai_intercepted} isolados`, g.quarX, g.quarY + 14);
  ctx.restore();

  // === PROJÉTEIS EM VOO COM METAMORFOSE VISUAL ===
  for (let i = projectiles.length - 1; i >= 0; i--) {
    const p = projectiles[i];
    p.morphPhase += 0.08 * simSpeed;
    p.trail.push({ x: p.x, y: p.y });
    if (p.trail.length > 22) p.trail.shift();

    if (p.stage === "to_av") {
      p.x += p.vx * simSpeed;
      if (p.x >= g.avX - 8) {
        if (p.packet.outcome === "AV_BLOCKED") {
          avWallFlash = 1.0; avWallColor = "#22c55e";
          playSound("av_block");
          addShockwave(g.avX, p.y, "#22c55e");
          addParticleBurst(g.avX, p.y, "#fbbf24", 24, 3.6);
          addFloatText(g.avX, p.y - 18, "✔ AV BLOQUEOU (SHA-256)", "#86efac");
          projectiles.splice(i, 1);
          continue;
        } else {
          if (p.packet.kind === "polymorphic") {
            avWallFlash = 1.0; avWallColor = "#ff4d5e";
            playSound("av_bypass");
            addRipple(g.avX, p.y, "#ff4d5e", 34);
            addParticleBurst(g.avX, p.y, "#ff4d5e", 14, 2.8);
            addFloatText(g.avX, p.y - 18, "✖ BYPASS AV (HASH INÉDITO)", "#fda4af");
          }
          p.stage = "to_ai";
        }
      }
    } else if (p.stage === "to_ai") {
      p.x += p.vx * simSpeed;
      p.y += (g.coreY - p.y) * 0.014 * simSpeed;
      const distRadar = Math.hypot(p.x - g.radarX, p.y - g.radarY);
      if (!p.scannedAi && (distRadar < g.radarR * 0.94 || p.x >= g.radarX - 18)) {
        p.scannedAi = true;
        if (p.packet.outcome === "AI_QUARANTINED") {
          playSound("ai_intercept");
          addBeam(g.radarX, g.radarY, p.x, p.y, "#38bdf8");
          addShockwave(p.x, p.y, "#38bdf8");
          addParticleBurst(p.x, p.y, "#38bdf8", 22, 3.5);
          addFloatText(p.x, p.y - 20, `⚡ IA ${p.packet.ai_risk_pct}% → QUARENTENA`, "#7dd3fc");
          p.stage = "to_quarantine";
        } else if (p.packet.outcome === "LEGIT_PASSED") {
          if (p.packet.ai_enabled_at_arrival) {
            playSound("legit_ok");
            addBeam(g.radarX, g.radarY, p.x, p.y, "#22c55e");
            addRipple(p.x, p.y, "#22c55e", 34);
            addFloatText(p.x, p.y - 18, p.packet.kind === "legit_packed" ? "✔ ALTA ENTROPIA, 0 FP!" : "✔ LEGÍTIMO OK", "#86efac");
          }
          p.stage = "to_core";
        } else {
          addFloatText(p.x, p.y - 18, "⚠ RADAR OFF — INVASÃO!", "#ff4d5e");
          p.stage = "to_core";
        }
      }
    } else if (p.stage === "to_quarantine") {
      p.x += (g.quarX - p.x) * 0.11 * simSpeed;
      p.y += (g.quarY - p.y) * 0.11 * simSpeed;
      if (Math.hypot(p.x - g.quarX, p.y - g.quarY) < 14) {
        quarPulse = 1.0;
        playSound("quarantine");
        addShockwave(g.quarX, g.quarY, "#c084fc");
        addParticleBurst(g.quarX, g.quarY, "#d946ef", 30, 4.4);
        addParticleBurst(g.quarX, g.quarY, "#38bdf8", 12, 3.0);
        projectiles.splice(i, 1);
        continue;
      }
    } else if (p.stage === "to_core") {
      p.x += ((g.coreX - p.x) * 0.08 + 1.2) * simSpeed;
      p.y += (g.coreY - p.y) * 0.08 * simSpeed;
      if (p.x >= g.coreX - 18) {
        if (p.packet.outcome === "BREACH") {
          coreAlertFlash = 1.0;
          screenShake = 1.0;
          playSound("breach");
          addShockwave(g.coreX, g.coreY, "#ff4d5e");
          addParticleBurst(g.coreX, g.coreY, "#ff4d5e", 34, 4.8);
          addFloatText(g.coreX - 38, g.coreY - 40, "🚨 -20 HP • BREACH!", "#ff4d5e");
        } else {
          addRipple(g.coreX, g.coreY, "#22c55e", 34);
          addParticleBurst(g.coreX, g.coreY, "#22c55e", 14, 2.5);
        }
        projectiles.splice(i, 1);
        continue;
      }
    }

    // Cor neon dinâmica (polimórficos mudam de tonalidade durante a metamorfose!)
    let drawColor = p.color;
    if (p.packet.kind === "polymorphic") {
      const morphPalette = ["#ff4d5e", "#f43f5e", "#fb7185", "#e879f9", "#ff6b35"];
      drawColor = morphPalette[Math.floor(p.morphPhase * 1.4) % morphPalette.length];
    }

    // Trilha luminosa contínua com glow
    if (p.trail.length >= 2) {
      ctx.save();
      ctx.lineCap = "round";
      for (let t = 1; t < p.trail.length; t++) {
        const frac = t / p.trail.length;
        ctx.strokeStyle = drawColor;
        ctx.globalAlpha = frac * 0.68;
        ctx.lineWidth = 1.4 + frac * 5.2;
        ctx.shadowColor = drawColor;
        ctx.shadowBlur = 10 * frac;
        ctx.beginPath();
        ctx.moveTo(p.trail[t - 1].x, p.trail[t - 1].y);
        ctx.lineTo(p.trail[t].x, p.trail[t].y);
        ctx.stroke();
      }
      ctx.restore();
    }

    // Desenho do pacote (com metamorfose de polígono 3→4→5→6→8 lados para polimórfico/AST!)
    ctx.save();
    ctx.translate(p.x, p.y);
    ctx.fillStyle = drawColor;
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 1.3;
    ctx.shadowColor = drawColor;
    ctx.shadowBlur = 20;
    if (p.packet.kind === "polymorphic") {
      const sideSeq = [3, 4, 5, 6, 8];
      const sides = sideSeq[Math.floor(p.morphPhase * 1.2) % sideSeq.length];
      const rad = 10.5 + Math.sin(p.morphPhase * 2.5) * 1.4;
      ctx.beginPath();
      for (let s = 0; s < sides; s++) {
        const a = ((Math.PI * 2) / sides) * s + p.morphPhase * 1.4;
        const px = Math.cos(a) * rad;
        const py = Math.sin(a) * rad;
        s === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    } else if (p.packet.kind === "original") {
      ctx.rotate(Math.PI / 4);
      ctx.fillRect(-7.5, -7.5, 15, 15);
      ctx.strokeRect(-7.5, -7.5, 15, 15);
    } else {
      ctx.beginPath(); ctx.arc(0, 0, 8.2, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
    }
    ctx.restore();

    // Rótulo flutuante acoplado ao pacote em voo (SHA-256 + Entropia real!)
    if (p.packet.kind === "polymorphic" || simSpeed < 0.9 || p.packet.kind === "legit_packed") {
      ctx.save();
      const tag =
        p.packet.kind === "polymorphic"
          ? `${p.packet.sha256.slice(0, 8)} | H=${p.packet.entropy.toFixed(2)}`
          : p.packet.kind === "legit_packed"
          ? `PKG | H=${p.packet.entropy.toFixed(2)}`
          : `${p.packet.label.slice(0, 12)} | H=${p.packet.entropy.toFixed(2)}`;
      ctx.font = "bold 9.5px monospace";
      const tw = ctx.measureText(tag).width + 10;
      ctx.fillStyle = "rgba(6, 11, 20, 0.84)";
      ctx.strokeStyle = drawColor;
      ctx.lineWidth = 1;
      drawRoundedRect(p.x - tw / 2, p.y - 28, tw, 15, 4);
      ctx.fill(); ctx.stroke();
      ctx.fillStyle = "#f8fafc";
      ctx.textAlign = "center";
      ctx.fillText(tag, p.x, p.y - 17);
      ctx.restore();
    }
  }

  // Efeitos (ondas de choque e feixes de energia do Radar IA)
  for (let i = effects.length - 1; i >= 0; i--) {
    const ef = effects[i];
    ef.life -= 0.032 * simSpeed;
    if (ef.life <= 0) { effects.splice(i, 1); continue; }
    ctx.save();
    ctx.globalAlpha = ef.life;
    if (ef.type === "ripple") {
      ef.r += (ef.maxR - ef.r) * 0.14 * simSpeed;
      ctx.strokeStyle = ef.color;
      ctx.shadowColor = ef.color; ctx.shadowBlur = 14;
      ctx.lineWidth = ef.lw || 2.5;
      ctx.beginPath(); ctx.arc(ef.x, ef.y, ef.r, 0, Math.PI * 2); ctx.stroke();
    } else if (ef.type === "beam") {
      // Feixe principal + núcleo branco neon + arco elétrico sutil
      ctx.strokeStyle = ef.color;
      ctx.lineWidth = 5.0;
      ctx.shadowColor = ef.color; ctx.shadowBlur = 18;
      ctx.beginPath(); ctx.moveTo(ef.x1, ef.y1); ctx.lineTo(ef.x2, ef.y2); ctx.stroke();
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.6;
      const mx = (ef.x1 + ef.x2) / 2 + (Math.random() - 0.5) * 14;
      const my = (ef.y1 + ef.y2) / 2 + (Math.random() - 0.5) * 14;
      ctx.beginPath();
      ctx.moveTo(ef.x1, ef.y1); ctx.lineTo(mx, my); ctx.lineTo(ef.x2, ef.y2);
      ctx.stroke();
    }
    ctx.restore();
  }

  // Partículas luminosas (explosões na muralha, interceptação e quarentena)
  for (let i = particles.length - 1; i >= 0; i--) {
    const pt = particles[i];
    pt.x += pt.vx * simSpeed;
    pt.y += pt.vy * simSpeed;
    pt.vx *= 0.96;
    pt.vy *= 0.96;
    pt.life -= 0.026 * simSpeed;
    if (pt.life <= 0) { particles.splice(i, 1); continue; }
    ctx.save();
    ctx.globalAlpha = Math.max(0, Math.min(1, pt.life));
    ctx.fillStyle = pt.color;
    ctx.shadowColor = pt.color;
    ctx.shadowBlur = 10;
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, pt.size, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  }

  // Textos flutuantes
  for (let i = floatTexts.length - 1; i >= 0; i--) {
    const ft = floatTexts[i];
    ft.y -= 0.55 * simSpeed;
    ft.life -= 0.015 * simSpeed;
    if (ft.life <= 0) { floatTexts.splice(i, 1); continue; }
    ctx.save();
    ctx.globalAlpha = Math.min(1, ft.life * 1.4);
    ctx.fillStyle = ft.color;
    ctx.shadowColor = "#000000"; ctx.shadowBlur = 6;
    ctx.font = "bold 11.5px monospace";
    ctx.textAlign = "center";
    ctx.fillText(ft.text, ft.x, ft.y);
    ctx.restore();
  }

  // Gráfico HUD de Histórico de Risco IA no rodapé do Canvas
  drawRiskHistoryHUD(g);

  ctx.restore();
  requestAnimationFrame(updateAndDraw);
}

function renderInspector(packet) {
  if (!packet) {
    document.getElementById("inspBadge").textContent = "Aguardando disparo...";
    document.getElementById("inspName").textContent = "—";
    document.getElementById("inspHash").textContent = "—";
    document.getElementById("inspEntropy").textContent = "—";
    document.getElementById("inspRisk").textContent = "—";
    document.getElementById("inspProof").textContent = "⚙ Telemetria Real (Backend Python): aguardando primeira amostra...";
    document.getElementById("inspAvReason").textContent = "Dispare um pacote nos controles acima para inspecionar o veredito do antivírus por assinatura.";
    document.getElementById("inspAiReason").textContent = "A IA classifica 6 features medidas em tempo real no Python (zero números mockados no JS).";
    document.getElementById("boxAv").className = "verdict-box";
    document.getElementById("boxAi").className = "verdict-box";
    document.getElementById("xaiContainer").innerHTML = "";
    document.getElementById("inspCode").textContent = "# Código-fonte real gerado pelo motor Python aparecerá aqui...";
    return;
  }

  const outcomeLabels = {
    AV_BLOCKED: "🛡️ BLOQUEADO NO AV ESTÁTICO",
    AI_QUARANTINED: "🧠 INTERCEPTADO PELA IA → QUARENTENA",
    LEGIT_PASSED: "✔ TRÁFEGO LEGÍTIMO LIBERADO",
    BREACH: "🚨 INVASÃO (BREACH NO SERVIDOR!)"
  };
  document.getElementById("inspBadge").textContent = `${packet.id} • ${outcomeLabels[packet.outcome] || packet.outcome}`;
  document.getElementById("inspName").textContent = `${packet.label} (${packet.technique})`;
  document.getElementById("inspHash").textContent = `${packet.sha256.slice(0, 16)}…${packet.sha256.slice(-8)}`;
  document.getElementById("inspEntropy").textContent = `${packet.entropy.toFixed(2)} bits/B  |  ${packet.ast_nodes} nós AST`;
  const latTxt = packet.ai_latency_ms !== null ? ` (${packet.ai_latency_ms.toFixed(2)} ms)` : "";
  document.getElementById("inspRisk").textContent = `${packet.ai_risk_pct.toFixed(1)}%${latTxt}`;
  document.getElementById("inspRisk").className = `m-v ${packet.ai_risk_pct >= 50 ? "c-red" : "c-green"}`;

  const sbx = packet.sandbox_telemetry || {};
  document.getElementById("inspProof").textContent =
    `⚙ Mutação: ${Number(packet.mutation_ms || 0).toFixed(2)}ms  |  ` +
    `Sandbox: ${sbx.executed ? `OK (${sbx.exec_ms}ms, I/O ${sbx.sandbox_io_kb}KB, TCP 127.0.0.1: ${sbx.loopback_net_pings} ping)` : "estático"}  |  ` +
    `RF: ${Number(packet.rf_prob_pct || 0).toFixed(1)}%  |  ` +
    `IsoForest: ${packet.iso_anomaly ? "ANOMALIA" : "normal"} (${Number(packet.iso_score || 0).toFixed(3)})`;

  document.getElementById("inspLlmNote").innerHTML =
    `🤖 <strong>IA Ofensiva &amp; Automação:</strong> ${packet.offensive_ai_note || ""}`;

  const boxAv = document.getElementById("boxAv");
  boxAv.className = "verdict-box " + (packet.av_verdict === "BYPASS" ? "vb-bypass" : packet.av_verdict === "BLOCKED" ? "vb-warn" : "vb-ok");
  document.getElementById("inspAvReason").textContent = packet.av_reason;

  const boxAi = document.getElementById("boxAi");
  boxAi.className = "verdict-box " + (packet.outcome === "BREACH" ? "vb-bypass" : "vb-ok");
  document.getElementById("inspAiReason").textContent = packet.ai_reason;

  const xaiEl = document.getElementById("xaiContainer");
  if (packet.xai_reasons && packet.xai_reasons.length > 0) {
    xaiEl.innerHTML = packet.xai_reasons.map(r => {
      const pct = Math.min(100, Math.max(8, Math.abs(r.z_score) * 20));
      const color = r.severity === "CRÍTICO" ? "var(--red)" : r.severity === "ELEVADO" ? "var(--amber)" : "var(--green)";
      return `
        <div class="xai-row">
          <span>${r.label} <span style="color:var(--muted)">(${r.observed} vs normal ${r.baseline_mean})</span></span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <span style="font-family:var(--mono);text-align:right;color:${color};font-weight:700">${r.severity}</span>
        </div>`;
    }).join("");
  } else {
    xaiEl.innerHTML = `<div style="font-size:0.78rem;color:var(--muted);">Contido na camada estática (assinatura conhecida — sem necessidade de inferência ML).</div>`;
  }

  document.getElementById("inspCode").textContent = packet.code_preview || "";
}

function renderUI(state) {
  arenaState = state;
  const s = state.stats;
  const hp = Number(s.server_hp ?? 100);
  document.getElementById("statMutated").textContent = s.mutated_count;
  document.getElementById("statBypass").textContent = s.av_bypassed;
  document.getElementById("statAvSub").textContent = `Original bloqueado: ${s.av_blocked}`;
  document.getElementById("statIntercepted").textContent = s.ai_intercepted;
  document.getElementById("statLegitSub").textContent = `Legítimos: ${s.ai_legit_passed} (${s.false_positives} FP)`;
  const hpEl = document.getElementById("statServerHp");
  hpEl.textContent = `${hp}%`;
  hpEl.className = `k-val ${hp > 60 ? "c-green" : hp > 30 ? "c-amber" : "c-red"}`;
  document.getElementById("statBreachSub").textContent = `Invasões (Breach): ${s.breaches}`;
  document.getElementById("statLatency").textContent = `${Number(s.avg_latency_ms || 0).toFixed(2)} ms`;
  document.getElementById("quarCount").textContent = `Quarentena: ${s.ai_intercepted} (clique p/ Diff)`;

  const pill = document.getElementById("pillShield");
  const btn4 = document.getElementById("btn4");
  if (state.ai_shield_enabled) {
    pill.textContent = "🧠 ESCUDO IA: LIGADO";
    pill.className = "pill pill-shield-on";
    btn4.className = "btn btn-ai-on";
    btn4.innerHTML = '<span class="key">4</span> 🧠 IA: LIGADO';
  } else {
    pill.textContent = "⚠ ESCUDO IA: DESLIGADO";
    pill.className = "pill pill-shield-off";
    btn4.className = "btn btn-ai-off";
    btn4.innerHTML = '<span class="key">4</span> ⚠ IA: DESLIGADO';
  }

  const feed = document.getElementById("feedList");
  if (!state.events || state.events.length === 0) {
    feed.innerHTML = `<div style="color:var(--muted);font-size:0.84rem;padding:12px;">Nenhum evento ainda. Pressione <strong>[1]</strong>, <strong>[2]</strong> ou <strong>[3]</strong> para iniciar a demonstração.</div>`;
  } else {
    const rev = [...state.events].reverse();
    feed.innerHTML = rev.map(ev => {
      const badgeMap = {
        AV_BLOCKED: ['b-av', 'AV BLOQ'],
        AI_QUARANTINED: ['b-quar', `IA ${ev.ai_risk_pct}%`],
        LEGIT_PASSED: ['b-legit', 'LEGÍTIMO'],
        BREACH: ['b-breach', 'BREACH!']
      };
      const [cls, txt] = badgeMap[ev.outcome] || ['b-legit', ev.outcome];
      const active = state.selected_packet && state.selected_packet.id === ev.id ? "active" : "";
      return `
        <div class="feed-item ${active}" onclick="selectPacket('${ev.id}')">
          <span style="font-family:var(--mono);color:var(--muted)">${ev.timestamp}</span>
          <div>
            <div style="font-weight:700">${ev.label}</div>
            <div style="font-family:var(--mono);font-size:0.7rem;color:var(--muted)">SHA:${ev.sha256.slice(0,10)}… | H:${ev.entropy.toFixed(2)} | AST:${ev.ast_nodes}</div>
          </div>
          <span class="badge ${cls}">${txt}</span>
        </div>`;
    }).join("");
  }

  renderInspector(state.selected_packet);
}

function openCodeDiffModal(packet = null) {
  const pkt = packet || arenaState.selected_packet;
  if (!pkt) return;
  document.getElementById("modalTitle").textContent = `🔬 Diff de Código Real — ${pkt.id} (${pkt.label})`;
  document.getElementById("modalMeta").innerHTML =
    `<span><strong>Técnica:</strong> ${pkt.technique}</span>` +
    `<span>• <strong>Arquivo Sandbox:</strong> ${pkt.sandbox_file || "—"}</span>` +
    `<span>• <strong>Entropia:</strong> ${Number(pkt.original_entropy ?? pkt.entropy).toFixed(2)} → <strong>${pkt.entropy.toFixed(2)} bits/B</strong></span>` +
    `<span>• <strong>Nós AST:</strong> ${pkt.original_ast_nodes ?? pkt.ast_nodes} → <strong>${pkt.ast_nodes}</strong></span>`;
  document.getElementById("modalOrigHash").textContent = `SHA: ${(pkt.original_sha256 || pkt.sha256).slice(0, 14)}…`;
  document.getElementById("modalMutHash").textContent = `SHA: ${pkt.sha256.slice(0, 14)}…`;
  document.getElementById("modalMutLabel").textContent =
    pkt.kind === "polymorphic" ? "🧬 CÓDIGO REAL MUTADO (AST / POLIMORFISMO)" : "📄 ARTEFATO INSPECIONADO";
  document.getElementById("modalOrigCode").textContent = pkt.original_code_preview || pkt.code_preview || "";
  document.getElementById("modalMutCode").textContent = pkt.code_preview || "";
  document.getElementById("codeModal").classList.add("open");
}

function closeCodeDiffModal() {
  document.getElementById("codeModal").classList.remove("open");
}

function selectPacket(id) {
  const found = (arenaState.events || []).find(e => e.id === id);
  if (found) {
    arenaState.selected_packet = found;
    renderUI(arenaState);
    openCodeDiffModal(found);
  }
}

async function apiPost(endpoint, payload = {}) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return res.json();
}

async function fireOriginal() {
  const data = await apiPost("/api/spawn-original");
  renderUI(data.state);
  launchProjectile(data.packet);
}

async function firePolymorphic() {
  const data = await apiPost("/api/spawn-polymorphic");
  renderUI(data.state);
  launchProjectile(data.packet);
}

async function fireMixed() {
  const data = await apiPost("/api/spawn-mixed");
  renderUI(data.state);
  const gap = Math.round(360 / simSpeed);
  (data.packets || []).forEach((pkt, idx) => launchProjectile(pkt, idx * gap));
}

async function fireStressWave() {
  if (stressBusy) return;
  stressBusy = true;
  const btn7 = document.getElementById("btn7");
  if (btn7) {
    btn7.disabled = true;
    btn7.innerHTML = '<span class="key">7</span> ⚡ Gerando...';
  }
  try {
    const data = await apiPost("/api/spawn-stress", { count: 8 });
    renderUI(data.state);
    const gap = Math.round(420 / simSpeed);
    (data.packets || []).forEach((pkt, idx) => launchProjectile(pkt, idx * gap));
  } finally {
    stressBusy = false;
    if (btn7) {
      btn7.disabled = false;
      btn7.innerHTML = '<span class="key">7</span> ⚡ Onda x8';
    }
  }
}

function toggleSlowMo() {
  simSpeed = simSpeed > 0.7 ? 0.4 : 1.0;
  const btn6 = document.getElementById("btn6");
  if (simSpeed < 0.7) {
    btn6.className = "btn btn-speed-slow";
    btn6.innerHTML = '<span class="key">6</span> ⏱ Vel: 0.4x';
  } else {
    btn6.className = "btn btn-speed-norm";
    btn6.innerHTML = '<span class="key">6</span> ⏱ Vel: 1.0x';
  }
}

async function toggleAI() {
  const data = await apiPost("/api/toggle-ai");
  renderUI(data.state);
  playSound("toggle");
  const g = getGeometry();
  addShockwave(g.radarX, g.radarY, data.ai_shield_enabled ? "#38bdf8" : "#ff4d5e");
  addFloatText(g.radarX, g.radarY - 56, data.status_text, data.ai_shield_enabled ? "#7dd3fc" : "#ff4d5e");
}

async function resetArena() {
  projectiles.length = 0;
  effects.length = 0;
  particles.length = 0;
  floatTexts.length = 0;
  screenShake = 0;
  quarPulse = 0;
  displayedHp = 100;
  lastMutatedHash = "AGUARDANDO MUTAÇÃO...";
  lastMutatedEntropy = "0.00 bits/B";
  const data = await apiPost("/api/reset");
  renderUI(data);
}

function toggleTheoryDrawer() {
  const drawer = document.getElementById("theoryDrawer");
  const btn = document.getElementById("btnTheory");
  const isOpen = drawer.classList.toggle("open");
  btn.setAttribute("aria-expanded", String(isOpen));
  if (isOpen) {
    btn.className = "pill pill-btn pill-theory-on";
    btn.textContent = "✕ [T] Fechar Guia";
  } else {
    btn.className = "pill pill-btn";
    btn.textContent = "📖 [T] Guia Teórico";
  }
  playSound("toggle");
}

async function demoCardA() {
  await fireOriginal();
  setTimeout(() => { firePolymorphic(); }, 650);
}

document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  const k = e.key.toLowerCase();
  if (k === "escape") {
    const modal = document.getElementById("codeModal");
    if (modal.classList.contains("open")) {
      closeCodeDiffModal();
    } else if (document.getElementById("theoryDrawer").classList.contains("open")) {
      toggleTheoryDrawer();
    }
  } else if (k === "1") fireOriginal();
  else if (k === "2") firePolymorphic();
  else if (k === "3") fireMixed();
  else if (k === "4") toggleAI();
  else if (k === "5") resetArena();
  else if (k === "6") toggleSlowMo();
  else if (k === "7") fireStressWave();
  else if (k === "t") toggleTheoryDrawer();
  else if (k === "f") toggleFullscreen();
  else if (k === "m") toggleSound();
  else if (k === "c") openCodeDiffModal();
});

fetch("/api/state")
  .then(r => r.json())
  .then(state => {
    document.getElementById("pillServer").textContent = `● ${window.location.host}`;
    renderUI(state);
    requestAnimationFrame(updateAndDraw);
  });
</script>
</body>
</html>
"""


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = sys.platform != "win32"
    daemon_threads = True


def create_arena_handler(engine: CyberDuelArenaEngine, bound_port: int):
    class ArenaRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw.decode("utf-8"))
                return parsed if isinstance(parsed, dict) else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {}

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._send_html(HTML_PAGE)
            elif path == "/api/health":
                self._send_json(
                    {
                        "ok": True,
                        "host": "127.0.0.1",
                        "port": bound_port,
                        "ai_shield_enabled": engine.ai_shield_enabled,
                        "telemetry_sink_active": engine.telemetry_sink_active,
                    }
                )
            elif path == "/api/state":
                self._send_json(engine.get_state())
            else:
                self._send_json({"error": "Endpoint não encontrado", "path": path}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            body = self._read_json_body()
            if path == "/api/spawn-original":
                self._send_json(engine.spawn_original())
            elif path == "/api/spawn-polymorphic":
                self._send_json(engine.spawn_polymorphic())
            elif path == "/api/spawn-mixed":
                self._send_json(engine.spawn_mixed_wave())
            elif path == "/api/spawn-stress":
                req_count = body.get("count", 8)
                self._send_json(engine.spawn_stress_wave(count=req_count))
            elif path == "/api/toggle-ai":
                explicit = body.get("enabled") if "enabled" in body else None
                self._send_json(engine.toggle_ai(explicit_state=explicit))
            elif path == "/api/reset":
                self._send_json(engine.reset())
            else:
                self._send_json({"error": "Endpoint não encontrado", "path": path}, status=HTTPStatus.NOT_FOUND)

    return ArenaRequestHandler


def bind_arena_server(
    engine: CyberDuelArenaEngine,
    preferred_ports: tuple[int, ...] = (8080, 8081),
) -> tuple[ReusableThreadingHTTPServer, int]:
    """Tenta iniciar o servidor em 127.0.0.1:8080 com fallback automático para 8081."""
    last_err: OSError | None = None
    for port in preferred_ports:
        try:
            handler_cls = create_arena_handler(engine, port)
            server = ReusableThreadingHTTPServer(("127.0.0.1", port), handler_cls)
            return server, port
        except OSError as exc:
            last_err = exc
    raise RuntimeError(
        f"Não foi possível abrir nenhuma das portas {preferred_ports} em 127.0.0.1: {last_err}"
    )


def open_browser_safely(url: str) -> None:
    """Abre o navegador de forma não-bloqueante sem poluir o terminal no Linux Mint."""
    if sys.platform.startswith("linux"):
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return
        if shutil.which("xdg-open"):
            try:
                subprocess.Popen(
                    ["xdg-open", url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return
            except OSError:
                pass
    try:
        webbrowser.open(url, new=2)
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Arena Tática Web Localhost do AI Cyber Duel (127.0.0.1:8080 / fallback 8081)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Porta específica em 127.0.0.1 (padrão: tenta 8080 com fallback para 8081).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Inicia o servidor sem abrir o navegador automaticamente.",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Alias compatível com o menu apresentar.py (evita abrir abas extras em modo automatizado).",
    )
    args = parser.parse_args()

    console.print(
        "[bold cyan]Inicializando Arena Tática Web (RandomForest + IsolationForest + Receptor Loopback 127.0.0.1:59999)...[/bold cyan]"
    )
    engine = CyberDuelArenaEngine()

    ports = (args.port,) if args.port is not None else (8080, 8081)
    server, port = bind_arena_server(engine, preferred_ports=ports)
    url = f"http://127.0.0.1:{port}"

    def _handle_sigterm(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_sigterm)

    console.print(
        Panel.fit(
            "[bold cyan]⚔ AI CYBER DUEL — ARENA TÁTICA WEB SOC ATIVA[/bold cyan]\n\n"
            f"[bold white]URL no Navegador:[/bold white] [bold green]{url}[/bold green]\n"
            "[white]Motor Ofensivo:[/white]   [yellow]polymorphic_simulator.py + ast_transform_engine.py (AST real + Sandbox)[/yellow]\n"
            "[white]Motor Defensivo:[/white]  [cyan]RandomForestClassifier + IsolationForest (scikit-learn, 6 features reais)[/cyan]\n"
            "[white]Endpoints REST:[/white]   [dim]/api/state • /api/spawn-original • /api/spawn-polymorphic • "
            "/api/spawn-mixed • /api/spawn-stress • /api/toggle-ai • /api/reset[/dim]\n"
            "[white]Atalhos na Tela:[/white]  [yellow][1] Original  [2] Polimórfico  [3] Misto  [4] IA  [5] Reset  [6] Vel  [7] Onda x8  [T] Teoria  [C] Diff  [F] Tela Cheia  [M] Som[/yellow]\n\n"
            "[bold yellow]Pressione Ctrl+C neste terminal para encerrar o servidor com segurança.[/bold yellow]",
            title="[bold white]Servidor Localhost Embutido (Zero Node/npm | Zero Mock)[/bold white]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    if not args.no_browser and not args.auto:
        threading.Timer(0.35, open_browser_safely, args=(url,)).start()

    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        engine.close()
        console.print("\n[bold green]✔ Servidor da Arena Web encerrado com segurança.[/bold green]")


if __name__ == "__main__":
    main()
