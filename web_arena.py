#!/usr/bin/env python3
"""
AI Cyber Duel — Arena Tática Interativa em Localhost (Tower Defense / SOC Radar)
================================================================================
Servidor web embutido com zero fricção (apenas stdlib `http.server` + ML real do
projeto), projetado para apresentações ao vivo em Linux Mint e Windows.

Recursos:
  - Backend REST local (ThreadingHTTPServer em 127.0.0.1:8080, fallback 8081)
  - Mutação real em memória via motor polimórfico + motor AST (SHA-256 + Entropia)
  - Detecção real via RandomForestClassifier + IsolationForest + Explicabilidade XAI
  - Interface web 100% offline (Canvas 60 FPS + Dark Mode SOC + atalhos 1 a 5)
  - Abertura automática no navegador e encerramento limpo com Ctrl+C

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
import signal
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
BLUE_DIR = ROOT_DIR / "02-blue-team-realtime-ids"

OBFUSCATED_IDENT_RE = re.compile(r"\b(?:_[a-z]{1,8}|stage|chk)_[a-z0-9]{6,}\b")
DECODE_PRIMITIVES = ("b85decode", "b64decode", "zlib.decompress", "base64", "exec(", "^")


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


def compute_obfuscation_score(text: str) -> float:
    """Calcula o score heurístico estático real de ofuscação (0.0 a 1.0)."""
    if not text:
        return 0.0
    lines = text.splitlines()
    total_lines = max(1, len(lines))
    primitive_hits = sum(1 for tok in DECODE_PRIMITIVES if tok in text)
    primitive_score = min(1.0, primitive_hits / 4.0)
    encoded_lines = sum(
        1 for ln in lines if len(ln.strip().strip('"')) >= 55 and " " not in ln.strip().strip('"')
    )
    blob_ratio = min(1.0, (encoded_lines / total_lines) * 2.4)
    obf_idents = len(set(OBFUSCATED_IDENT_RE.findall(text)))
    ident_score = min(1.0, obf_idents / 6.0)
    score = (0.35 * primitive_score) + (0.35 * blob_ratio) + (0.30 * ident_score)
    return round(min(1.0, max(0.0, score)), 3)


def count_ast_nodes(text: str) -> int:
    """Conta o número real de nós na Abstract Syntax Tree do código Python."""
    try:
        tree = ast.parse(text)
        return sum(1 for _ in ast.walk(tree))
    except SyntaxError:
        return 0


class CyberDuelArenaEngine:
    """Motor real da Arena Web combinando geradores Red Team + Ensemble ML Blue Team."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.poly_mod = _load_module("polymorphic_simulator_web", RED_DIR / "polymorphic_simulator.py")
        self.ast_mod = _load_module("ast_transform_engine_web", RED_DIR / "ast_transform_engine.py")
        self.tel_mod = _load_module("generate_telemetry_data_web", BLUE_DIR / "generate_telemetry_data.py")

        self.feature_cols: list[str] = list(self.tel_mod.FEATURE_COLUMNS)
        self.feature_labels: dict[str, str] = dict(self.tel_mod.FEATURE_LABELS)

        self.original_source: str = self.poly_mod.ORIGINAL_PAYLOAD_SOURCE
        self.original_sha256: str = hashlib.sha256(self.original_source.encode("utf-8")).hexdigest()
        self.known_signatures: dict[str, str] = {
            self.original_sha256: "Sim.Edu.Original.A",
        }

        self.rf_ids, self.iso_ids, self.normal_stats, self.importances = self._train_models()
        self.reset()

    def _train_models(
        self,
    ) -> tuple[RandomForestClassifier, IsolationForest, dict[str, tuple[float, float]], dict[str, float]]:
        if self.tel_mod.DATASET_PATH.exists():
            df = pd.read_csv(self.tel_mod.DATASET_PATH, encoding="utf-8")
        else:
            df = self.tel_mod.generate_dataset(n_samples=2000, seed=42, output_path=self.tel_mod.DATASET_PATH)

        df = df.dropna(subset=self.feature_cols + ["label"]).reset_index(drop=True)
        X = df[self.feature_cols]
        y = df["label"]

        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
        )
        rf.fit(X, y)

        normal_df = X[y == 0]
        iso = IsolationForest(contamination=0.06, random_state=42)
        iso.fit(normal_df)

        normal_stats = {
            col: (round(float(normal_df[col].mean()), 3), round(float(normal_df[col].std()), 3))
            for col in self.feature_cols
        }
        importances = {col: round(float(w), 4) for col, w in zip(self.feature_cols, rf.feature_importances_)}
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
                "avg_latency_ms": 0.0,
            }
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> dict[str, Any]:
        return {
            "ai_shield_enabled": self.ai_shield_enabled,
            "known_original_sha256": self.original_sha256,
            "stats": dict(self.stats),
            "events": list(self.events[-30:]),
            "quarantine": list(self.quarantine[-15:]),
            "selected_packet": self.selected_packet,
            "feature_importances": [
                {"key": col, "label": self.feature_labels[col], "weight_pct": round(self.importances[col] * 100.0, 1)}
                for col in sorted(self.feature_cols, key=lambda c: self.importances[c], reverse=True)
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

    def _build_xai_reasons(self, features: dict[str, float]) -> list[dict[str, Any]]:
        scored: list[tuple[float, dict[str, Any]]] = []
        for col in self.feature_cols:
            obs = float(features[col])
            mean, std = self.normal_stats[col]
            z = (obs - mean) / max(std, 1e-4)
            impact = max(0.0, z) * self.importances[col]
            if z >= 2.8:
                severity = "CRÍTICO"
            elif z >= 1.5:
                severity = "ELEVADO"
            else:
                severity = "NORMAL"
            scored.append(
                (
                    impact,
                    {
                        "feature": col,
                        "label": self.feature_labels[col],
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

    def _evaluate_packet_with_ai(self, features: dict[str, float]) -> tuple[float, bool, float, list[dict[str, Any]]]:
        t0 = time.perf_counter()
        sample_df = pd.DataFrame([features], columns=self.feature_cols)
        rf_prob = float(self.rf_ids.predict_proba(sample_df)[0][1])
        iso_pred = int(self.iso_ids.predict(sample_df)[0])
        iso_score = float(self.iso_ids.decision_function(sample_df)[0])
        iso_anomaly = iso_pred == -1

        # Ensemble real: combina probabilidade supervisionada (RandomForest) com
        # score de anomalia nao supervisionado (IsolationForest) para pegar AST furtivo
        if iso_anomaly:
            iso_risk = min(0.96, max(0.68, 0.72 + abs(min(0.0, iso_score)) * 1.4))
            ensemble_prob = max(rf_prob, (0.45 * rf_prob) + (0.55 * iso_risk))
        else:
            ensemble_prob = rf_prob

        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        xai = self._build_xai_reasons(features)
        return round(ensemble_prob * 100.0, 1), iso_anomaly, latency_ms, xai

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
            obf = compute_obfuscation_score(self.original_source)
            ast_nodes = count_ast_nodes(self.original_source)
            matched_sig = self.known_signatures.get(sha256)

            self.stats["total_spawned"] += 1
            self.stats["av_blocked"] += 1

            snippet = "\n".join(self.original_source.strip().splitlines()[:12])
            packet = {
                "id": f"PKT-{self.packet_seq:03d}",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "kind": "original",
                "label": "payload_original.py",
                "technique": "Assinatura Conhecida (Baseline sem mutação)",
                "sha256": sha256,
                "size_bytes": len(raw),
                "entropy": entropy,
                "ast_nodes": ast_nodes,
                "obfuscation_score": obf,
                "av_verdict": "BLOCKED",
                "av_reason": f"Match exato na blacklist SHA-256 ({matched_sig}).",
                "ai_enabled_at_arrival": self.ai_shield_enabled,
                "ai_verdict": "NOT_NEEDED",
                "ai_risk_pct": 0.0,
                "iso_anomaly": False,
                "ai_latency_ms": None,
                "ai_reason": "Contido antes de atingir o Escudo Neural — assinatura estática já conhecida.",
                "outcome": "AV_BLOCKED",
                "xai_reasons": [],
                "code_preview": snippet,
            }
            self._record_packet_unlocked(packet)
            return {"packet": packet, "state": self._snapshot_unlocked()}

    def _generate_real_mutated_artifact(self, seq: int) -> tuple[str, str, str, dict[str, float]]:
        """Gera uma variante real polimórfica ou AST em memória com telemetria comportamental."""
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
            telemetry_profiles = [
                {"process_spawn_rate": 8.6, "suspicious_api_calls": 17.0, "anomalous_net_connections": 5.0, "cpu_burst_ratio": 4.2},
                {"process_spawn_rate": 10.4, "suspicious_api_calls": 20.0, "anomalous_net_connections": 6.0, "cpu_burst_ratio": 4.8},
                {"process_spawn_rate": 11.9, "suspicious_api_calls": 24.0, "anomalous_net_connections": 8.0, "cpu_burst_ratio": 5.5},
                {"process_spawn_rate": 13.3, "suspicious_api_calls": 27.0, "anomalous_net_connections": 9.0, "cpu_burst_ratio": 6.1},
                {"process_spawn_rate": 15.2, "suspicious_api_calls": 31.0, "anomalous_net_connections": 11.0, "cpu_burst_ratio": 6.9},
            ]
            behav = telemetry_profiles[mode]
            label = f"poly_{seq:02d}_{Path(fname).stem.split('_', 2)[-1]}.py"
        else:
            # Mutação estrutural real via AST (for->while, shuffle, predicados opacos + opcional Zlib/B85)
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
                behav = {
                    "process_spawn_rate": 12.6,
                    "suspicious_api_calls": 25.0,
                    "anomalous_net_connections": 9.0,
                    "cpu_burst_ratio": 5.2,
                }
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
                behav = {
                    "process_spawn_rate": 14.8,
                    "suspicious_api_calls": 29.0,
                    "anomalous_net_connections": 10.0,
                    "cpu_burst_ratio": 6.4,
                }

        raw = source.encode("utf-8")
        features = {
            "file_entropy": compute_shannon_entropy(raw),
            "obfuscation_score": compute_obfuscation_score(source),
            **behav,
        }
        return label, technique, source, features

    def spawn_polymorphic(self) -> dict[str, Any]:
        with self._lock:
            self.packet_seq += 1
            self.poly_seq += 1
            label, technique, source, features = self._generate_real_mutated_artifact(self.poly_seq)
            raw = source.encode("utf-8")
            sha256 = hashlib.sha256(raw).hexdigest()
            ast_nodes = count_ast_nodes(source)

            risk_pct, iso_flag, latency_ms, xai = self._evaluate_packet_with_ai(features)
            ai_detects = (risk_pct >= 50.0) or iso_flag

            self.stats["total_spawned"] += 1
            self.stats["mutated_count"] += 1
            self.stats["av_bypassed"] += 1

            if self.ai_shield_enabled and ai_detects:
                ai_verdict = "INTERCEPTED"
                outcome = "AI_QUARANTINED"
                self.stats["ai_intercepted"] += 1
                ai_reason = (
                    f"Interceptado em voo pelo Ensemble IA ({risk_pct:.1f}% risco"
                    f"{' + anomalia IsolationForest' if iso_flag else ''}) e isolado na quarentena."
                )
            elif not self.ai_shield_enabled:
                ai_verdict = "OFFLINE"
                outcome = "BREACH"
                self.stats["breaches"] += 1
                ai_reason = (
                    f"ESCUDO IA DESLIGADO! Ameaça com {risk_pct:.1f}% de risco atingiu o servidor sem contenção."
                )
            else:
                ai_verdict = "MISSED"
                outcome = "BREACH"
                self.stats["breaches"] += 1
                ai_reason = f"Score abaixo do limiar ({risk_pct:.1f}%)."

            preview_lines = source.strip().splitlines()[:12]
            packet = {
                "id": f"PKT-{self.packet_seq:03d}",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "kind": "polymorphic",
                "label": label,
                "technique": technique,
                "sha256": sha256,
                "size_bytes": len(raw),
                "entropy": features["file_entropy"],
                "ast_nodes": ast_nodes,
                "obfuscation_score": features["obfuscation_score"],
                "av_verdict": "BYPASS",
                "av_reason": (
                    f"Hash inédito ({sha256[:12]}...) não existe na blacklist — "
                    "efeito avalanche do SHA-256 causou evasão total!"
                ),
                "ai_enabled_at_arrival": self.ai_shield_enabled,
                "ai_verdict": ai_verdict,
                "ai_risk_pct": risk_pct,
                "iso_anomaly": iso_flag,
                "ai_latency_ms": latency_ms,
                "ai_reason": ai_reason,
                "outcome": outcome,
                "xai_reasons": xai,
                "code_preview": "\n".join(preview_lines),
            }
            self._record_packet_unlocked(packet)
            return {"packet": packet, "state": self._snapshot_unlocked()}

    def _spawn_legit_unlocked(self, packed_hard_negative: bool = False) -> dict[str, Any]:
        self.packet_seq += 1
        if packed_hard_negative:
            label = "instalador_compactado.pkg"
            technique = "Controle Difícil: Pacote Legítimo Compactado (Alta Entropia)"
            source = (
                "# Pacote administrativo assinado e compactado (teste de Falso Positivo)\n"
                "def instalar_atualizacao_assinada():\n"
                "    return {'assinatura': 'VALIDA', 'origem': 'repositorio_oficial'}\n"
            )
            features = {
                "file_entropy": 6.24,
                "obfuscation_score": 0.21,
                "process_spawn_rate": 2.1,
                "suspicious_api_calls": 2.0,
                "anomalous_net_connections": 0.0,
                "cpu_burst_ratio": 1.95,
            }
            sha256 = hashlib.sha256(f"legit_pkg_{self.packet_seq}".encode("utf-8")).hexdigest()
            size_bytes = 48250
            ast_nodes = 18
        else:
            label = "backup_diario.py"
            technique = "Tráfego Corporativo Legítimo (Baixa Entropia)"
            source = (
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n\n"
                "def executar_backup_rotineiro(destino: Path) -> int:\n"
                "    arquivos = list(destino.glob('*.log'))\n"
                "    return len(arquivos)\n"
            )
            raw = source.encode("utf-8")
            features = {
                "file_entropy": compute_shannon_entropy(raw),
                "obfuscation_score": compute_obfuscation_score(source),
                "process_spawn_rate": 1.2,
                "suspicious_api_calls": 1.0,
                "anomalous_net_connections": 0.0,
                "cpu_burst_ratio": 1.15,
            }
            sha256 = hashlib.sha256(f"legit_backup_{self.packet_seq}".encode("utf-8")).hexdigest()
            size_bytes = len(raw)
            ast_nodes = count_ast_nodes(source)

        risk_pct, iso_flag, latency_ms, xai = self._evaluate_packet_with_ai(features)
        is_flagged = risk_pct >= 50.0

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
            ai_reason = f"Falso positivo ({risk_pct:.1f}%)."
        else:
            ai_verdict = "ALLOWED"
            outcome = "LEGIT_PASSED"
            self.stats["ai_legit_passed"] += 1
            if packed_hard_negative:
                ai_reason = (
                    f"ZERO FALSO POSITIVO! Apesar da alta entropia ({features['file_entropy']:.2f} bits/B), "
                    f"o comportamento de processos/rede é limpo (risco IA: {risk_pct:.1f}%) — liberado!"
                )
            else:
                ai_reason = f"Comportamento e entropia normais (risco IA: {risk_pct:.1f}%) — tráfego liberado."

        packet = {
            "id": f"PKT-{self.packet_seq:03d}",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "kind": "legit_packed" if packed_hard_negative else "legit",
            "label": label,
            "technique": technique,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "entropy": features["file_entropy"],
            "ast_nodes": ast_nodes,
            "obfuscation_score": features["obfuscation_score"],
            "av_verdict": "PASSED",
            "av_reason": "Sem ocorrência na blacklist SHA-256 — liberado pela muralha legada.",
            "ai_enabled_at_arrival": self.ai_shield_enabled,
            "ai_verdict": ai_verdict,
            "ai_risk_pct": risk_pct,
            "iso_anomaly": iso_flag,
            "ai_latency_ms": latency_ms,
            "ai_reason": ai_reason,
            "outcome": outcome,
            "xai_reasons": xai,
            "code_preview": source.strip(),
        }
        self._record_packet_unlocked(packet)
        return packet

    def spawn_mixed_wave(self) -> dict[str, Any]:
        """Dispara uma rajada realista mista: 2 legítimos (1 normal + 1 compactado) + 2 polimórficos/AST."""
        packets: list[dict[str, Any]] = []
        with self._lock:
            packets.append(self._spawn_legit_unlocked(packed_hard_negative=False))
        packets.append(self.spawn_polymorphic()["packet"])
        with self._lock:
            packets.append(self._spawn_legit_unlocked(packed_hard_negative=True))
        packets.append(self.spawn_polymorphic()["packet"])
        return {"packets": packets, "state": self.get_state()}


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
    --border: #22324d;
    --text: #eef4ff;
    --muted: #8ea3c2;
    --red: #ff4d5e;
    --amber: #fbbf24;
    --cyan: #38bdf8;
    --green: #22c55e;
    --purple: #a855f7;
    --mono: ui-monospace, "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
    --sans: system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: radial-gradient(circle at 20% 0%, #0f1c34 0%, var(--bg) 55%);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 14px 18px 18px;
  }
  .topbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
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
  .status-pills { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .pill {
    font-family: var(--mono); font-size: 0.78rem; font-weight: 700;
    padding: 6px 12px; border-radius: 999px; border: 1px solid var(--border);
    background: rgba(6,10,18,0.7);
  }
  .pill-online { color: var(--green); border-color: rgba(34,197,94,0.45); }
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
    display: grid;
    grid-template-columns: repeat(5, minmax(140px, 1fr));
    gap: 10px;
    margin-bottom: 12px;
  }
  .kpi {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 14px;
    display: flex; flex-direction: column; gap: 2px;
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
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 10px 12px 12px;
    margin-bottom: 12px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.45);
  }
  .arena-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px; flex-wrap: wrap; gap: 8px;
  }
  .zone-legend {
    display: flex; gap: 16px; flex-wrap: wrap; font-size: 0.8rem; font-weight: 600;
  }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
  #arenaCanvas {
    width: 100%;
    height: 330px;
    display: block;
    border-radius: 10px;
    border: 1px solid #1b2b45;
    background: #060b14;
  }

  .controls {
    display: grid;
    grid-template-columns: repeat(5, minmax(150px, 1fr));
    gap: 10px;
    margin-top: 10px;
  }
  .btn {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 11px 12px;
    font-family: var(--sans);
    font-size: 0.86rem;
    font-weight: 700;
    cursor: pointer;
    color: var(--text);
    background: var(--panel-2);
    display: flex; align-items: center; justify-content: center; gap: 8px;
    transition: transform 0.12s ease, box-shadow 0.15s ease, border-color 0.15s ease;
  }
  .btn:hover { transform: translateY(-2px); }
  .btn:active { transform: translateY(0); }
  .btn .key {
    font-family: var(--mono); font-size: 0.74rem;
    padding: 2px 6px; border-radius: 5px; background: rgba(0,0,0,0.35);
    border: 1px solid rgba(255,255,255,0.2);
  }
  .btn-amber { background: linear-gradient(135deg, #422b08, #281b07); border-color: rgba(251,191,36,0.55); color: #fde68a; }
  .btn-amber:hover { box-shadow: 0 0 18px rgba(251,191,36,0.3); }
  .btn-red { background: linear-gradient(135deg, #4d101b, #2a0a11); border-color: rgba(255,77,94,0.65); color: #fecdd3; }
  .btn-red:hover { box-shadow: 0 0 20px rgba(255,77,94,0.38); }
  .btn-purple { background: linear-gradient(135deg, #321652, #1b0e2e); border-color: rgba(168,85,247,0.6); color: #e9d5ff; }
  .btn-purple:hover { box-shadow: 0 0 18px rgba(168,85,247,0.35); }
  .btn-ai-on { background: linear-gradient(135deg, #0a3c35, #08242c); border-color: rgba(34,197,94,0.7); color: #bbf7d0; }
  .btn-ai-off { background: linear-gradient(135deg, #5c121b, #300a10); border-color: var(--red); color: #fff; }
  .btn-reset { background: #141e30; border-color: #364b6e; color: var(--muted); }
  .btn-reset:hover { color: var(--text); border-color: var(--cyan); }

  .bottom-grid {
    display: grid;
    grid-template-columns: 1.45fr 1fr;
    gap: 12px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 16px;
    display: flex; flex-direction: column; gap: 10px;
  }
  .card-title {
    display: flex; justify-content: space-between; align-items: center;
    font-size: 0.94rem; font-weight: 800; letter-spacing: 0.3px;
    border-bottom: 1px solid var(--border); padding-bottom: 8px;
  }
  .inspector-meta {
    display: grid; grid-template-columns: repeat(4, minmax(110px, 1fr)); gap: 8px;
  }
  .meta-box {
    background: #0a101c; border: 1px solid #1c2a42; border-radius: 8px; padding: 8px 10px;
  }
  .meta-box .m-k { font-size: 0.68rem; color: var(--muted); text-transform: uppercase; }
  .meta-box .m-v { font-family: var(--mono); font-size: 0.92rem; font-weight: 700; margin-top: 2px; word-break: break-all; }

  .verdict-split {
    display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
  }
  .verdict-box {
    background: #0a101c; border: 1px solid var(--border); border-radius: 9px; padding: 10px 12px;
  }
  .verdict-box h4 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 5px; }
  .verdict-box p { font-size: 0.83rem; color: #d5e2f7; line-height: 1.38; }
  .vb-bypass { border-color: rgba(255,77,94,0.65); background: rgba(255,77,94,0.07); }
  .vb-ok { border-color: rgba(34,197,94,0.65); background: rgba(34,197,94,0.07); }
  .vb-warn { border-color: rgba(251,191,36,0.65); background: rgba(251,191,36,0.07); }

  .xai-list { display: flex; flex-direction: column; gap: 6px; }
  .xai-row {
    display: grid; grid-template-columns: 1.4fr 1fr 78px; align-items: center; gap: 8px;
    font-size: 0.78rem;
  }
  .bar-track { height: 8px; background: #162238; border-radius: 99px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 99px; transition: width 0.25s ease; }
  .code-preview {
    background: #050810; border: 1px solid #1a2740; border-radius: 8px;
    padding: 8px 10px; font-family: var(--mono); font-size: 0.74rem;
    color: #9dd4ff; max-height: 112px; overflow: auto; white-space: pre;
  }

  .feed-list {
    display: flex; flex-direction: column; gap: 6px;
    max-height: 325px; overflow-y: auto; padding-right: 4px;
  }
  .feed-item {
    display: grid; grid-template-columns: 58px 1fr auto; align-items: center; gap: 8px;
    background: #0a101c; border: 1px solid #1c2a42; border-radius: 8px;
    padding: 8px 10px; cursor: pointer; font-size: 0.8rem;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .feed-item:hover, .feed-item.active {
    border-color: var(--cyan); background: #101b2e;
  }
  .badge {
    font-family: var(--mono); font-size: 0.69rem; font-weight: 800;
    padding: 3px 7px; border-radius: 6px; white-space: nowrap;
  }
  .b-av { background: rgba(251,191,36,0.2); color: var(--amber); border: 1px solid rgba(251,191,36,0.5); }
  .b-quar { background: rgba(34,197,94,0.18); color: #86efac; border: 1px solid rgba(34,197,94,0.55); }
  .b-legit { background: rgba(56,189,248,0.18); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.55); }
  .b-breach { background: rgba(255,77,94,0.25); color: #fda4af; border: 1px solid var(--red); }

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
        <p>Fábrica Polimórfica / AST (Red Team) vs. Antivírus SHA-256 vs. Escudo Neural IDS (Blue Team)</p>
      </div>
    </div>
    <div class="status-pills">
      <span class="pill pill-online" id="pillServer">● LOCALHOST ONLINE</span>
      <span class="pill pill-shield-on" id="pillShield">🧠 ESCUDO IA: LIGADO</span>
    </div>
  </header>

  <section class="kpi-row">
    <div class="kpi">
      <span class="k-label">Amostras Mutadas</span>
      <span class="k-val c-amber" id="statMutated">0</span>
      <span class="k-sub">Hashes SHA-256 inéditos</span>
    </div>
    <div class="kpi">
      <span class="k-label">Evasões AV (SHA-256)</span>
      <span class="k-val c-red" id="statBypass">0</span>
      <span class="k-sub" id="statAvSub">Original bloqueado: 0</span>
    </div>
    <div class="kpi">
      <span class="k-label">Interceptadas pela IA</span>
      <span class="k-val c-green" id="statIntercepted">0</span>
      <span class="k-sub">Isoladas na quarentena</span>
    </div>
    <div class="kpi">
      <span class="k-label">Legítimos / Invasões</span>
      <span class="k-val"><span class="c-cyan" id="statLegit">0</span> <span style="color:#475569">/</span> <span class="c-red" id="statBreach">0</span></span>
      <span class="k-sub" id="statFpSub">Falsos positivos: 0</span>
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
      <span style="font-family:var(--mono);font-size:0.76rem;color:var(--muted);">Atalhos no teclado: [1] [2] [3] [4] [5]</span>
    </div>
    <canvas id="arenaCanvas" width="1280" height="340"></canvas>

    <div class="controls">
      <button class="btn btn-amber" id="btn1" onclick="fireOriginal()">
        <span class="key">1</span> 📦 Pacote Original
      </button>
      <button class="btn btn-red" id="btn2" onclick="firePolymorphic()">
        <span class="key">2</span> 🧬 Ataque Polimórfico
      </button>
      <button class="btn btn-purple" id="btn3" onclick="fireMixed()">
        <span class="key">3</span> 🌊 Tráfego Misto (x4)
      </button>
      <button class="btn btn-ai-on" id="btn4" onclick="toggleAI()">
        <span class="key">4</span> 🧠 Escudo IA: LIGADO
      </button>
      <button class="btn btn-reset" id="btn5" onclick="resetArena()">
        <span class="key">5</span> 🔄 Resetar Arena
      </button>
    </div>
  </section>

  <section class="bottom-grid">
    <div class="card">
      <div class="card-title">
        <span>🔍 Painel de Inspeção — Assinatura Estática vs. IA Explicável (XAI)</span>
        <span class="pill" id="inspBadge" style="font-size:0.72rem;">Aguardando disparo...</span>
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
          <div class="m-k">Score de Risco IA</div>
          <div class="m-v c-green" id="inspRisk">—</div>
        </div>
      </div>

      <div class="verdict-split">
        <div class="verdict-box" id="boxAv">
          <h4 class="c-amber">🛡️ Muralha Legada (AV SHA-256)</h4>
          <p id="inspAvReason">Dispare um pacote nos controles acima para inspecionar o veredito do antivírus por assinatura.</p>
        </div>
        <div class="verdict-box" id="boxAi">
          <h4 class="c-cyan">🧠 Escudo Neural (IDS + IsolationForest)</h4>
          <p id="inspAiReason">A IA avalia Entropia de Shannon, ofuscação AST e telemetria comportamental em milissegundos.</p>
        </div>
      </div>

      <div class="xai-list" id="xaiContainer"></div>
      <pre class="code-preview" id="inspCode"># Código-fonte / payload inspecionado aparecerá aqui em tempo real...</pre>
    </div>

    <div class="card">
      <div class="card-title">
        <span>📡 Feed de Eventos SOC & Quarentena</span>
        <span style="font-family:var(--mono);font-size:0.75rem;color:var(--muted);" id="quarCount">Quarentena: 0</span>
      </div>
      <div class="feed-list" id="feedList">
        <div style="color:var(--muted);font-size:0.84rem;padding:12px;">
          Nenhum evento ainda. Pressione <strong>[1]</strong> para testar o Antivírus tradicional, <strong>[2]</strong> para lançar um ataque polimórfico, ou <strong>[3]</strong> para tráfego misto.
        </div>
      </div>
    </div>
  </section>

<script>
const canvas = document.getElementById("arenaCanvas");
const ctx = canvas.getContext("2d");

let arenaState = {
  ai_shield_enabled: true,
  stats: {
    total_spawned: 0, mutated_count: 0, legit_count: 0,
    av_blocked: 0, av_bypassed: 0, ai_intercepted: 0,
    ai_legit_passed: 0, breaches: 0, false_positives: 0, avg_latency_ms: 0
  },
  events: [],
  quarantine: [],
  selected_packet: null
};

const projectiles = [];
const effects = [];
const floatTexts = [];
let radarAngle = 0;
let factoryAngle = 0;
let lastMutatedHash = "AGUARDANDO MUTAÇÃO...";
let lastMutatedEntropy = "0.00 bits/B";
let coreAlertFlash = 0;
let avWallFlash = 0;
let avWallColor = "#fbbf24";

function resizeCanvas() {
  const rect = canvas.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.max(820, Math.floor(rect.width * dpr));
  canvas.height = Math.floor(330 * dpr);
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
  const h = 330;
  return {
    w, h,
    factoryX: w * 0.12, factoryY: h * 0.48,
    avX: w * 0.44,
    radarX: w * 0.72, radarY: h * 0.44, radarR: Math.min(82, w * 0.082),
    coreX: w * 0.91, coreY: h * 0.34,
    quarX: w * 0.89, quarY: h * 0.78
  };
}

function addFloatText(x, y, text, color) {
  floatTexts.push({ x, y, text, color, life: 1.0 });
}

function addRipple(x, y, color, maxR = 46) {
  effects.push({ type: "ripple", x, y, r: 6, maxR, color, life: 1.0 });
}

function addBeam(x1, y1, x2, y2, color) {
  effects.push({ type: "beam", x1, y1, x2, y2, color, life: 1.0 });
}

function launchProjectile(packet, delayMs = 0) {
  setTimeout(() => {
    const g = getGeometry();
    const laneOffset = (Math.random() - 0.5) * 86;
    const startY = Math.max(64, Math.min(g.h - 70, g.factoryY + laneOffset));
    const colorMap = {
      original: "#fbbf24",
      polymorphic: "#ff4d5e",
      legit: "#22c55e",
      legit_packed: "#38bdf8"
    };
    if (packet.kind === "polymorphic") {
      lastMutatedHash = packet.sha256.slice(0, 18) + "...";
      lastMutatedEntropy = `${packet.entropy.toFixed(2)} bits/B`;
    }
    projectiles.push({
      packet,
      x: g.factoryX + 26,
      y: startY,
      targetY: startY,
      vx: 3.5 + Math.random() * 0.65,
      color: colorMap[packet.kind] || "#38bdf8",
      stage: "to_av",
      passedAv: false,
      scannedAi: false,
      trail: []
    });
  }, delayMs);
}

function updateAndDraw() {
  const g = getGeometry();
  ctx.clearRect(0, 0, g.w, g.h);

  // Grid tático de fundo
  ctx.strokeStyle = "rgba(34, 50, 77, 0.32)";
  ctx.lineWidth = 1;
  for (let x = 0; x < g.w; x += 36) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, g.h); ctx.stroke();
  }
  for (let y = 0; y < g.h; y += 36) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(g.w, y); ctx.stroke();
  }

  // Faixas de fluxo
  ctx.strokeStyle = "rgba(56, 189, 248, 0.14)";
  ctx.setLineDash([8, 8]);
  ctx.beginPath();
  ctx.moveTo(g.factoryX + 42, g.factoryY);
  ctx.lineTo(g.coreX - 34, g.coreY);
  ctx.stroke();
  ctx.setLineDash([]);

  // === ZONA 1: FÁBRICA POLIMÓRFICA (ESQUERDA) ===
  factoryAngle += 0.018;
  ctx.save();
  ctx.translate(g.factoryX, g.factoryY);
  ctx.strokeStyle = "rgba(255, 77, 94, 0.55)";
  ctx.lineWidth = 2;
  ctx.beginPath(); ctx.arc(0, 0, 44, factoryAngle, factoryAngle + Math.PI * 1.4); ctx.stroke();
  ctx.strokeStyle = "rgba(251, 191, 36, 0.45)";
  ctx.beginPath(); ctx.arc(0, 0, 32, -factoryAngle * 1.4, -factoryAngle * 1.4 + Math.PI * 1.2); ctx.stroke();
  ctx.fillStyle = "#240c14";
  ctx.beginPath(); ctx.arc(0, 0, 26, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = "#ff4d5e"; ctx.lineWidth = 2.2; ctx.stroke();
  ctx.fillStyle = "#ffe4e6"; ctx.font = "bold 18px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("🧬", 0, 6);
  ctx.restore();

  ctx.fillStyle = "#fda4af"; ctx.font = "bold 12px system-ui"; ctx.textAlign = "center";
  ctx.fillText("FÁBRICA POLIMÓRFICA", g.factoryX, 26);
  ctx.fillStyle = "#8ea3c2"; ctx.font = "11px monospace";
  ctx.fillText("Red Team / AST", g.factoryX, 42);
  ctx.fillStyle = "#fbbf24"; ctx.font = "10.5px monospace";
  ctx.fillText(`SHA: ${lastMutatedHash}`, g.factoryX, g.h - 32);
  ctx.fillStyle = "#ff8fa3";
  ctx.fillText(`Entropia: ${lastMutatedEntropy}`, g.factoryX, g.h - 15);

  // === ZONA 2: MURALHA LEGADA (CENTRO - AV SHA-256) ===
  if (avWallFlash > 0) avWallFlash -= 0.04;
  ctx.save();
  const wallGrad = ctx.createLinearGradient(g.avX - 10, 46, g.avX + 10, g.h - 46);
  wallGrad.addColorStop(0, "rgba(251, 191, 36, 0.15)");
  wallGrad.addColorStop(0.5, avWallFlash > 0 ? avWallColor : "rgba(251, 191, 36, 0.72)");
  wallGrad.addColorStop(1, "rgba(251, 191, 36, 0.15)");
  ctx.fillStyle = wallGrad;
  ctx.fillRect(g.avX - 5, 48, 10, g.h - 92);
  ctx.strokeStyle = avWallFlash > 0 ? avWallColor : "#fbbf24";
  ctx.lineWidth = 2;
  ctx.strokeRect(g.avX - 5, 48, 10, g.h - 92);
  ctx.restore();

  ctx.fillStyle = "#fde68a"; ctx.font = "bold 12px system-ui"; ctx.textAlign = "center";
  ctx.fillText("MURALHA LEGADA", g.avX, 26);
  ctx.fillStyle = "#8ea3c2"; ctx.font = "11px monospace";
  ctx.fillText("AV Assinatura SHA-256", g.avX, 42);
  ctx.fillStyle = "#fbbf24"; ctx.font = "10.5px monospace";
  ctx.fillText(`Bloq: ${arenaState.stats.av_blocked} | Bypass: ${arenaState.stats.av_bypassed}`, g.avX, g.h - 16);

  // === ZONA 3: ESCUDO NEURAL / RADAR IDS (DIREITA) ===
  const shieldOn = arenaState.ai_shield_enabled;
  radarAngle += shieldOn ? 0.045 : 0.008;
  ctx.save();
  ctx.translate(g.radarX, g.radarY);
  const rColor = shieldOn ? "56, 189, 248" : "255, 77, 94";
  for (const frac of [1.0, 0.68, 0.36]) {
    ctx.strokeStyle = `rgba(${rColor}, ${shieldOn ? 0.35 : 0.25})`;
    ctx.lineWidth = 1.4;
    ctx.beginPath(); ctx.arc(0, 0, g.radarR * frac, 0, Math.PI * 2); ctx.stroke();
  }
  if (shieldOn) {
    ctx.fillStyle = "rgba(56, 189, 248, 0.16)";
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, g.radarR, radarAngle - 0.55, radarAngle);
    ctx.closePath();
    ctx.fill();
    ctx.strokeStyle = "#38bdf8";
    ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(0, 0);
    ctx.lineTo(Math.cos(radarAngle) * g.radarR, Math.sin(radarAngle) * g.radarR);
    ctx.stroke();
  } else {
    ctx.strokeStyle = "rgba(255, 77, 94, 0.7)";
    ctx.lineWidth = 2.4;
    ctx.beginPath();
    ctx.moveTo(-26, -26); ctx.lineTo(26, 26);
    ctx.moveTo(26, -26); ctx.lineTo(-26, 26);
    ctx.stroke();
  }
  ctx.fillStyle = shieldOn ? "#072033" : "#2a0b12";
  ctx.beginPath(); ctx.arc(0, 0, 22, 0, Math.PI * 2); ctx.fill();
  ctx.strokeStyle = shieldOn ? "#38bdf8" : "#ff4d5e"; ctx.lineWidth = 2; ctx.stroke();
  ctx.fillStyle = "#fff"; ctx.font = "bold 16px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("🧠", 0, 6);
  ctx.restore();

  ctx.fillStyle = shieldOn ? "#7dd3fc" : "#fda4af"; ctx.font = "bold 12px system-ui"; ctx.textAlign = "center";
  ctx.fillText(shieldOn ? "ESCUDO NEURAL (IDS IA)" : "ESCUDO NEURAL (OFFLINE!)", g.radarX, 26);
  ctx.fillStyle = "#8ea3c2"; ctx.font = "11px monospace";
  ctx.fillText("RandomForest + IsoForest", g.radarX, 42);

  // Núcleo Protegido (Servidor)
  if (coreAlertFlash > 0) coreAlertFlash -= 0.035;
  ctx.save();
  ctx.fillStyle = coreAlertFlash > 0 ? "rgba(255,77,94,0.38)" : "#0d2236";
  ctx.strokeStyle = coreAlertFlash > 0 ? "#ff4d5e" : "#22c55e";
  ctx.lineWidth = 2.2;
  drawRoundedRect(g.coreX - 42, g.coreY - 30, 84, 60, 10);
  ctx.fill(); ctx.stroke();
  ctx.fillStyle = "#fff"; ctx.font = "bold 18px sans-serif"; ctx.textAlign = "center";
  ctx.fillText("🖥️", g.coreX, g.coreY - 2);
  ctx.fillStyle = coreAlertFlash > 0 ? "#fecdd3" : "#86efac"; ctx.font = "bold 10.5px monospace";
  ctx.fillText("SERVIDOR", g.coreX, g.coreY + 18);
  ctx.restore();

  // Cofre de Quarentena
  ctx.save();
  ctx.fillStyle = "#121a2d";
  ctx.strokeStyle = "#a855f7";
  ctx.lineWidth = 2;
  drawRoundedRect(g.quarX - 48, g.quarY - 26, 96, 52, 10);
  ctx.fill(); ctx.stroke();
  ctx.fillStyle = "#e9d5ff"; ctx.font = "bold 11px monospace"; ctx.textAlign = "center";
  ctx.fillText("🔒 QUARENTENA", g.quarX, g.quarY - 4);
  ctx.fillStyle = "#c084fc"; ctx.font = "bold 13px monospace";
  ctx.fillText(`${arenaState.stats.ai_intercepted} isolados`, g.quarX, g.quarY + 15);
  ctx.restore();

  // === ATUALIZA PROJÉTEIS EM VOO ===
  for (let i = projectiles.length - 1; i >= 0; i--) {
    const p = projectiles[i];
    p.trail.push({ x: p.x, y: p.y });
    if (p.trail.length > 14) p.trail.shift();

    if (p.stage === "to_av") {
      p.x += p.vx;
      if (p.x >= g.avX - 8) {
        if (p.packet.outcome === "AV_BLOCKED") {
          avWallFlash = 1.0; avWallColor = "#22c55e";
          addRipple(g.avX, p.y, "#22c55e", 42);
          addFloatText(g.avX, p.y - 16, "✔ AV BLOQUEOU (SHA-256)", "#86efac");
          projectiles.splice(i, 1);
          continue;
        } else {
          if (p.packet.kind === "polymorphic") {
            avWallFlash = 1.0; avWallColor = "#ff4d5e";
            addRipple(g.avX, p.y, "#ff4d5e", 30);
            addFloatText(g.avX, p.y - 16, "✖ BYPASS AV (HASH INÉDITO)", "#fda4af");
          }
          p.stage = "to_ai";
        }
      }
    } else if (p.stage === "to_ai") {
      p.x += p.vx;
      p.y += (g.coreY - p.y) * 0.014;
      const distRadar = Math.hypot(p.x - g.radarX, p.y - g.radarY);
      if (!p.scannedAi && (distRadar < g.radarR * 0.92 || p.x >= g.radarX - 18)) {
        p.scannedAi = true;
        if (p.packet.outcome === "AI_QUARANTINED") {
          addBeam(g.radarX, g.radarY, p.x, p.y, "#38bdf8");
          addRipple(p.x, p.y, "#38bdf8", 44);
          addFloatText(p.x, p.y - 18, `⚡ IA ${p.packet.ai_risk_pct}% → QUARENTENA`, "#7dd3fc");
          p.stage = "to_quarantine";
        } else if (p.packet.outcome === "LEGIT_PASSED") {
          if (p.packet.ai_enabled_at_arrival) {
            addBeam(g.radarX, g.radarY, p.x, p.y, "#22c55e");
            addFloatText(p.x, p.y - 16, p.packet.kind === "legit_packed" ? "✔ ALTA ENTROPIA, 0 FP!" : "✔ LEGÍTIMO OK", "#86efac");
          }
          p.stage = "to_core";
        } else {
          addFloatText(p.x, p.y - 16, "⚠ RADAR OFF — INVASÃO!", "#ff4d5e");
          p.stage = "to_core";
        }
      }
    } else if (p.stage === "to_quarantine") {
      p.x += (g.quarX - p.x) * 0.11;
      p.y += (g.quarY - p.y) * 0.11;
      if (Math.hypot(p.x - g.quarX, p.y - g.quarY) < 12) {
        addRipple(g.quarX, g.quarY, "#a855f7", 36);
        projectiles.splice(i, 1);
        continue;
      }
    } else if (p.stage === "to_core") {
      p.x += (g.coreX - p.x) * 0.08 + 1.2;
      p.y += (g.coreY - p.y) * 0.08;
      if (p.x >= g.coreX - 16) {
        if (p.packet.outcome === "BREACH") {
          coreAlertFlash = 1.0;
          addRipple(g.coreX, g.coreY, "#ff4d5e", 58);
          addFloatText(g.coreX - 30, g.coreY - 34, "🚨 BREACH NO SERVIDOR!", "#ff4d5e");
        } else {
          addRipple(g.coreX, g.coreY, "#22c55e", 32);
        }
        projectiles.splice(i, 1);
        continue;
      }
    }

    // Desenha rastro
    for (let t = 0; t < p.trail.length; t++) {
      const alpha = (t / p.trail.length) * 0.55;
      ctx.fillStyle = p.color;
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(p.trail[t].x, p.trail[t].y, 2.2 + (t / p.trail.length) * 3.5, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    // Desenha pacote
    ctx.save();
    ctx.translate(p.x, p.y);
    ctx.fillStyle = p.color;
    ctx.shadowColor = p.color;
    ctx.shadowBlur = 14;
    if (p.packet.kind === "polymorphic") {
      ctx.beginPath();
      for (let s = 0; s < 6; s++) {
        const a = (Math.PI / 3) * s + radarAngle;
        const px = Math.cos(a) * 9.5;
        const py = Math.sin(a) * 9.5;
        s === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
      }
      ctx.closePath(); ctx.fill();
    } else if (p.packet.kind === "original") {
      ctx.rotate(Math.PI / 4);
      ctx.fillRect(-7, -7, 14, 14);
    } else {
      ctx.beginPath(); ctx.arc(0, 0, 8, 0, Math.PI * 2); ctx.fill();
    }
    ctx.restore();
  }

  // Efeitos (feixes e ondas)
  for (let i = effects.length - 1; i >= 0; i--) {
    const ef = effects[i];
    ef.life -= 0.032;
    if (ef.life <= 0) { effects.splice(i, 1); continue; }
    ctx.save();
    ctx.globalAlpha = ef.life;
    if (ef.type === "ripple") {
      ef.r += (ef.maxR - ef.r) * 0.14;
      ctx.strokeStyle = ef.color;
      ctx.lineWidth = 2.5;
      ctx.beginPath(); ctx.arc(ef.x, ef.y, ef.r, 0, Math.PI * 2); ctx.stroke();
    } else if (ef.type === "beam") {
      ctx.strokeStyle = ef.color;
      ctx.lineWidth = 3.2;
      ctx.shadowColor = ef.color; ctx.shadowBlur = 12;
      ctx.beginPath(); ctx.moveTo(ef.x1, ef.y1); ctx.lineTo(ef.x2, ef.y2); ctx.stroke();
    }
    ctx.restore();
  }

  // Textos flutuantes
  for (let i = floatTexts.length - 1; i >= 0; i--) {
    const ft = floatTexts[i];
    ft.y -= 0.55;
    ft.life -= 0.016;
    if (ft.life <= 0) { floatTexts.splice(i, 1); continue; }
    ctx.save();
    ctx.globalAlpha = Math.min(1, ft.life * 1.4);
    ctx.fillStyle = ft.color;
    ctx.font = "bold 11.5px monospace";
    ctx.textAlign = "center";
    ctx.fillText(ft.text, ft.x, ft.y);
    ctx.restore();
  }

  requestAnimationFrame(updateAndDraw);
}

function renderInspector(packet) {
  if (!packet) {
    document.getElementById("inspBadge").textContent = "Aguardando disparo...";
    document.getElementById("inspName").textContent = "—";
    document.getElementById("inspHash").textContent = "—";
    document.getElementById("inspEntropy").textContent = "—";
    document.getElementById("inspRisk").textContent = "—";
    document.getElementById("inspAvReason").textContent = "Dispare um pacote nos controles acima para inspecionar o veredito do antivírus por assinatura.";
    document.getElementById("inspAiReason").textContent = "A IA avalia Entropia de Shannon, ofuscação AST e telemetria comportamental em milissegundos.";
    document.getElementById("boxAv").className = "verdict-box";
    document.getElementById("boxAi").className = "verdict-box";
    document.getElementById("xaiContainer").innerHTML = "";
    document.getElementById("inspCode").textContent = "# Código-fonte / payload inspecionado aparecerá aqui em tempo real...";
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

  const boxAv = document.getElementById("boxAv");
  boxAv.className = "verdict-box " + (packet.av_verdict === "BYPASS" ? "vb-bypass" : packet.av_verdict === "BLOCKED" ? "vb-warn" : "vb-ok");
  document.getElementById("inspAvReason").textContent = packet.av_reason;

  const boxAi = document.getElementById("boxAi");
  boxAi.className = "verdict-box " + (packet.outcome === "BREACH" ? "vb-bypass" : "vb-ok");
  document.getElementById("inspAiReason").textContent = packet.ai_reason;

  const xaiEl = document.getElementById("xaiContainer");
  if (packet.xai_reasons && packet.xai_reasons.length > 0) {
    xaiEl.innerHTML = packet.xai_reasons.map(r => {
      const pct = Math.min(100, Math.max(8, Math.abs(r.z_score) * 22));
      const color = r.severity === "CRÍTICO" ? "var(--red)" : r.severity === "ELEVADO" ? "var(--amber)" : "var(--green)";
      return `
        <div class="xai-row">
          <span>${r.label} <span style="color:var(--muted)">(${r.observed} vs normal ${r.baseline_mean})</span></span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <span style="font-family:var(--mono);text-align:right;color:${color};font-weight:700">${r.severity}</span>
        </div>`;
    }).join("");
  } else {
    xaiEl.innerHTML = `<div style="font-size:0.78rem;color:var(--muted);">Contido na camada estática (assinatura conhecida — sem necessidade de inferência comportamental).</div>`;
  }

  document.getElementById("inspCode").textContent = packet.code_preview || "";
}

function renderUI(state) {
  arenaState = state;
  const s = state.stats;
  document.getElementById("statMutated").textContent = s.mutated_count;
  document.getElementById("statBypass").textContent = s.av_bypassed;
  document.getElementById("statAvSub").textContent = `Original bloqueado: ${s.av_blocked}`;
  document.getElementById("statIntercepted").textContent = s.ai_intercepted;
  document.getElementById("statLegit").textContent = s.ai_legit_passed;
  document.getElementById("statBreach").textContent = s.breaches;
  document.getElementById("statFpSub").textContent = `Falsos positivos: ${s.false_positives}`;
  document.getElementById("statLatency").textContent = `${Number(s.avg_latency_ms || 0).toFixed(2)} ms`;
  document.getElementById("quarCount").textContent = `Quarentena: ${s.ai_intercepted}`;

  const pill = document.getElementById("pillShield");
  const btn4 = document.getElementById("btn4");
  if (state.ai_shield_enabled) {
    pill.textContent = "🧠 ESCUDO IA: LIGADO";
    pill.className = "pill pill-shield-on";
    btn4.className = "btn btn-ai-on";
    btn4.innerHTML = '<span class="key">4</span> 🧠 Escudo IA: LIGADO';
  } else {
    pill.textContent = "⚠ ESCUDO IA: DESLIGADO";
    pill.className = "pill pill-shield-off";
    btn4.className = "btn btn-ai-off";
    btn4.innerHTML = '<span class="key">4</span> ⚠ Escudo IA: DESLIGADO';
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

function selectPacket(id) {
  const found = (arenaState.events || []).find(e => e.id === id);
  if (found) {
    arenaState.selected_packet = found;
    renderUI(arenaState);
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
  (data.packets || []).forEach((pkt, idx) => launchProjectile(pkt, idx * 340));
}

async function toggleAI() {
  const data = await apiPost("/api/toggle-ai");
  renderUI(data.state);
  const g = getGeometry();
  addRipple(g.radarX, g.radarY, data.ai_shield_enabled ? "#38bdf8" : "#ff4d5e", 76);
  addFloatText(g.radarX, g.radarY - 56, data.status_text, data.ai_shield_enabled ? "#7dd3fc" : "#ff4d5e");
}

async function resetArena() {
  projectiles.length = 0;
  effects.length = 0;
  floatTexts.length = 0;
  lastMutatedHash = "AGUARDANDO MUTAÇÃO...";
  lastMutatedEntropy = "0.00 bits/B";
  const data = await apiPost("/api/reset");
  renderUI(data);
}

document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  if (e.key === "1") fireOriginal();
  else if (e.key === "2") firePolymorphic();
  else if (e.key === "3") fireMixed();
  else if (e.key === "4") toggleAI();
  else if (e.key === "5") resetArena();
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
    # No Linux Mint, SO_REUSEADDR evita EADDRINUSE apos Ctrl+C (TIME_WAIT).
    # No Windows, SO_REUSEADDR permite bind duplicado em porta ativa, impedindo
    # o fallback 8080 -> 8081; portanto so ativamos fora do Windows.
    allow_reuse_address = sys.platform != "win32"
    daemon_threads = True


def create_arena_handler(engine: CyberDuelArenaEngine, bound_port: int):
    """Cria a classe handler vinculada à instância do motor da arena."""

    class ArenaRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Silencia logs ruidosos padrão no terminal da apresentação
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
    """Abre o navegador local sem travar o servidor (compatível com Linux Mint e Windows)."""
    if sys.platform.startswith("linux") and not (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    ):
        return
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

    console.print("[bold cyan]Inicializando Arena Tática Web (treinando RandomForest + IsolationForest)...[/bold cyan]")
    engine = CyberDuelArenaEngine()

    ports = (args.port,) if args.port is not None else (8080, 8081)
    server, port = bind_arena_server(engine, preferred_ports=ports)
    url = f"http://127.0.0.1:{port}"

    stop_event = threading.Event()

    def _handle_sigterm(_signum: int, _frame: Any) -> None:
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_sigterm)

    console.print(
        Panel.fit(
            "[bold cyan]⚔ AI CYBER DUEL — ARENA TÁTICA WEB SOC ATIVA[/bold cyan]\n\n"
            f"[bold white]URL no Navegador:[/bold white] [bold green]{url}[/bold green]\n"
            "[white]Endpoints REST:[/white]   [dim]/api/state • /api/spawn-original • /api/spawn-polymorphic • "
            "/api/spawn-mixed • /api/toggle-ai • /api/reset[/dim]\n"
            "[white]Atalhos na Tela:[/white]  [yellow][1] Original  [2] Polimórfico  [3] Misto  [4] Escudo IA  [5] Reset[/yellow]\n\n"
            "[bold yellow]Pressione Ctrl+C neste terminal para encerrar o servidor com segurança.[/bold yellow]",
            title="[bold white]Servidor Localhost Embutido (Zero Node/npm)[/bold white]",
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
        console.print("\n[bold green]✔ Servidor da Arena Web encerrado com segurança.[/bold green]")


if __name__ == "__main__":
    main()
