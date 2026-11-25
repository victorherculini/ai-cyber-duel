#!/usr/bin/env python3
"""
Motor de Transformacao Estrutural via AST (Abstract Syntax Tree).
Demonstra como alteracoes na arvore sintatica mudam assinaturas estaticas
preservando a equivalencia funcional em um ambiente sandbox benigno.
"""

import ast
import base64
import hashlib
import math
import random
import string
import sys
import zlib
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

BASE_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = BASE_DIR.parent / "sandbox_env"
VARIANTS_DIR = BASE_DIR / "generated_variants"

WORKLOAD_TEMPLATE = '''
import json
import socket
import time
from pathlib import Path

def step_scan_docs(base_path):
    docs_dir = Path(base_path) / "mock_docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    items = []
    for idx in range(3):
        sample = docs_dir / f"config_node_{idx}.conf"
        sample.write_text(f"node={idx};status=ok;env=lab\\n", encoding="utf-8")
        items.append({"file": sample.name, "size": sample.stat().st_size})
    return items

def step_aggregate(records):
    payload = {"timestamp": time.time(), "count": len(records), "records": records}
    return json.dumps(payload)

def step_local_ping(serialized_data):
    try:
        with socket.create_connection(("127.0.0.1", 59999), timeout=0.30) as sock:
            sock.sendall(serialized_data.encode("utf-8"))
    except OSError:
        pass

def run_audit_workflow():
    base = Path(__file__).resolve().parents[2] / "sandbox_env"
    data = step_scan_docs(base)
    blob = step_aggregate(data)
    step_local_ping(blob)
    status_file = base / "mock_startup" / "audit_heartbeat.log"
    status_file.parent.mkdir(parents=True, exist_ok=True)
    status_file.write_text("WORKFLOW_EXECUTED_OK\\n", encoding="utf-8")
    return len(data)

if __name__ == "__main__":
    run_audit_workflow()
'''


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class StructuralMutator(ast.NodeTransformer):
    """Reescreve a AST do Python: converte loops for->while, renomeia funcoes e injeta dead code."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.func_map = {}

    def _rand_name(self, prefix="fn"):
        suffix = "".join(self.rng.choices(string.ascii_lowercase, k=6))
        return f"{prefix}_{suffix}"

    def visit_Module(self, node: ast.Module):
        # Pré-mapeia funções step_* antes de renomear chamadas (independente da ordem)
        for stmt in node.body:
            if isinstance(stmt, ast.FunctionDef) and stmt.name.startswith("step_"):
                self.func_map[stmt.name] = self._rand_name("stage")
        self.generic_visit(node)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        if node.name in self.func_map:
            node.name = self.func_map[node.name]

        # Injeta bloco morto matematico (opaque predicate) no inicio da funcao
        var_name = self._rand_name("chk")
        val = self.rng.randint(10, 99)
        dead_stmt = ast.parse(
            f"{var_name} = ({val} * 2) - {val}\nif {var_name} < 0:\n    {var_name} = 0"
        ).body
        node.body = dead_stmt + node.body
        return node

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id in self.func_map:
            node.func.id = self.func_map[node.func.id]
        return node

    def visit_For(self, node: ast.For):
        """Converte 'for idx in range(N):' em um laco 'while' equivalente."""
        self.generic_visit(node)
        if (
            isinstance(node.target, ast.Name)
            and isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Name)
            and node.iter.func.id == "range"
            and len(node.iter.args) == 1
        ):
            idx_var = node.target.id
            limit_expr = node.iter.args[0]
            init_assign = ast.Assign(
                targets=[ast.Name(id=idx_var, ctx=ast.Store())],
                value=ast.Constant(value=0),
            )
            inc_assign = ast.AugAssign(
                target=ast.Name(id=idx_var, ctx=ast.Store()),
                op=ast.Add(),
                value=ast.Constant(value=1),
            )
            while_node = ast.While(
                test=ast.Compare(
                    left=ast.Name(id=idx_var, ctx=ast.Load()),
                    ops=[ast.Lt()],
                    comparators=[limit_expr],
                ),
                body=node.body + [inc_assign],
                orelse=node.orelse,
            )
            return [init_assign, while_node]
        return node


def generate_ast_variant(wave_id: int, variant_idx: int) -> dict:
    VARIANTS_DIR.mkdir(parents=True, exist_ok=True)
    seed = wave_id * 100 + variant_idx
    rng = random.Random(seed)

    tree = ast.parse(WORKLOAD_TEMPLATE)
    mutator = StructuralMutator(seed=seed)
    mutated_tree = mutator.visit(tree)

    # Embaralha a ordem das definicoes de funcoes independentes na arvore
    imports = [n for n in mutated_tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    funcs = [n for n in mutated_tree.body if isinstance(n, ast.FunctionDef)]
    others = [n for n in mutated_tree.body if not isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
    rng.shuffle(funcs)
    mutated_tree.body = imports + funcs + others
    ast.fix_missing_locations(mutated_tree)

    mutated_source = ast.unparse(mutated_tree)
    ast_nodes_count = sum(1 for _ in ast.walk(mutated_tree))

    # Camada extra opcional de compressao + Base85 em ondas pares para elevar entropia
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

    file_name = f"wave_{wave_id:02d}_variant_{variant_idx:02d}.py"
    out_path = VARIANTS_DIR / file_name
    out_bytes = final_code.encode("utf-8")
    out_path.write_bytes(out_bytes)

    return {
        "file_name": file_name,
        "path": out_path,
        "sha256": hashlib.sha256(out_bytes).hexdigest(),
        "entropy": shannon_entropy(out_bytes),
        "ast_nodes": ast_nodes_count,
        "technique": technique,
    }


if __name__ == "__main__":
    console.print(Panel.fit("[bold red]RED TEAM — Motor Polimórfico via AST (Abstract Syntax Tree)[/bold red]"))
    table = Table(title="Amostras Geradas com Mutação Sintática Real")
    table.add_column("Arquivo", style="cyan")
    table.add_column("Técnica AST", style="yellow")
    table.add_column("Nós AST", justify="right")
    table.add_column("Entropia", justify="right", style="magenta")
    table.add_column("SHA-256 (Prefixo)", style="green")

    for w in range(1, 4):
        for v in range(1, 3):
            info = generate_ast_variant(w, v)
            table.add_row(
                info["file_name"],
                info["technique"],
                str(info["ast_nodes"]),
                f"{info['entropy']:.4f}",
                info["sha256"][:24] + "...",
            )
    console.print(table)
