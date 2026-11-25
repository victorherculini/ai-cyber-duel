#!/usr/bin/env python3
"""
AI Cyber Duel — Módulo 01 (Red Team): Simulador de Motor Polimórfico
====================================================================
Script 100% educacional e inofensivo que demonstra o conceito de polimorfismo
de código e evasão de análise estática por hash (SHA-256).

Técnicas demonstradas (aplicadas a um payload benigno de texto):
  1. Renomeação dinâmica de variáveis e funções
  2. Inserção de código morto (junk code) e predicados opacos benignos
  3. Criptografia XOR com chaves variáveis (simples, dupla camada e rotativa)
  4. Codificação Base64/Base85 e compressão Zlib (elevando a Entropia de Shannon)

Uso:
  python3 01-red-team-polymorphic/polymorphic_simulator.py
  python3 01-red-team-polymorphic/polymorphic_simulator.py --auto
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import math
import secrets
import string
import subprocess
import sys
import time
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table

# Garante saída UTF-8 consistente no Windows e no Linux Mint
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "generated_variants"

BENIGN_MESSAGE = "Simulacao de Payload Ativo - [DEMO EDUCACIONAL INOFENSIVA]"

# Payload original determinístico (sempre gera o mesmo SHA-256 em Windows e Linux)
ORIGINAL_PAYLOAD_SOURCE = '''#!/usr/bin/env python3
"""
Payload benigno de referencia para demonstracao academica (AI Cyber Duel).
Este script nao realiza nenhuma acao maliciosa: apenas exibe uma mensagem
de demonstracao no terminal para comprovar equivalencia funcional.
"""


def obter_mensagem_padrao() -> str:
    """Retorna a mensagem padrao utilizada na demonstracao em sala."""
    return "Simulacao de Payload Ativo - [DEMO EDUCACIONAL INOFENSIVA]"


def executar_payload_benigno() -> str:
    """Executa a simulacao benigna e retorna a mensagem exibida."""
    mensagem = obter_mensagem_padrao()
    print(mensagem)
    return mensagem


if __name__ == "__main__":
    executar_payload_benigno()
'''


@dataclass
class VariantReport:
    filename: str
    path: Path
    techniques: str
    sha256: str
    entropy: float
    size_bytes: int


def pause(auto: bool, prompt: str = "\n[Pressione ENTER para continuar a demonstração...]") -> None:
    """Pausa estratégica para explicação ao vivo no projetor."""
    if not auto:
        input(prompt)


def compute_sha256(file_path: Path) -> str:
    """Calcula o hash criptográfico SHA-256 de um arquivo."""
    data = file_path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def compute_shannon_entropy(data: bytes) -> float:
    """
    Calcula a Entropia de Shannon (em bits por byte, intervalo 0.0 a 8.0).
    Fórmula: H(X) = -sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    return entropy


def random_identifier(prefix: str = "v") -> str:
    """Gera um identificador Python válido e aleatório para renomeação dinâmica."""
    alphabet = string.ascii_lowercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(7))
    return f"_{prefix}_{suffix}"


def xor_bytes(payload: bytes, key: bytes) -> bytes:
    """Aplica XOR byte a byte com chave dinâmica repetida."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(payload))


def rotating_xor_bytes(payload: bytes, key: bytes, salt: int) -> bytes:
    """Aplica XOR com chave rotativa dependente da posição do byte."""
    key_len = len(key)
    return bytes(
        b ^ ((key[i % key_len] + ((i * salt) & 0xFF)) & 0xFF)
        for i, b in enumerate(payload)
    )


def pack_benign_blob(message: str, padding_size: int) -> bytes:
    """
    Empacota a mensagem benigna com cabeçalho de tamanho (2 bytes big-endian)
    seguido de preenchimento aleatório inofensivo, simulando seções de dados
    criptografados presentes em artefatos polimórficos reais.
    """
    msg_bytes = message.encode("utf-8")
    header = len(msg_bytes).to_bytes(2, byteorder="big")
    benign_padding = secrets.token_bytes(padding_size)
    return header + msg_bytes + benign_padding


def generate_junk_block(num_statements: int = 4, indent: str = "") -> str:
    """
    Gera blocos de código morto (junk code) sintaticamente válidos e inofensivos
    que alteram drasticamente a estrutura AST e o hash do arquivo.
    """
    lines: list[str] = []
    for _ in range(num_statements):
        kind = secrets.randbelow(4)
        var_a = random_identifier("j")
        var_b = random_identifier("k")
        n1 = secrets.randbelow(899) + 100
        n2 = secrets.randbelow(89) + 11
        if kind == 0:
            lines.append(f"{indent}{var_a} = ({n1} * {n2}) ^ {secrets.randbelow(255)}")
        elif kind == 1:
            token = secrets.token_hex(8)
            lines.append(f'{indent}{var_a} = "{token}"[::-1]')
        elif kind == 2:
            lines.append(
                f"{indent}{var_a} = sum((i * {n2}) % 13 for i in range({secrets.randbelow(6) + 3}))"
            )
        else:
            lines.append(
                f"{indent}{var_b} = [{n1}, {n2}, ({n1} + {n2}) % 97]; _ = len({var_b})"
            )
    return "\n".join(lines)


def generate_dummy_function() -> str:
    """Cria uma função auxiliar benigna nunca executada (ou com retorno descartado)."""
    fn_name = random_identifier("helper")
    arg_name = random_identifier("arg")
    acc_name = random_identifier("acc")
    mod_val = secrets.randbelow(53) + 17
    seed_val = secrets.randbelow(900) + 100
    return (
        f"def {fn_name}({arg_name}: int = {seed_val}) -> int:\n"
        f"    {acc_name} = ({arg_name} ^ 0x5A) + {mod_val}\n"
        f"    for _i in range(3):\n"
        f"        {acc_name} = ({acc_name} * 7 + _i) % 1009\n"
        f"    return {acc_name}\n"
    )


def format_multiline_literal(encoded_str: str, chunk_size: int = 76) -> str:
    """Formata uma string longa codificada em linhas legíveis de Python."""
    chunks = [
        encoded_str[i : i + chunk_size]
        for i in range(0, len(encoded_str), chunk_size)
    ]
    joined = "\n".join(f'    "{chunk}"' for chunk in chunks)
    return f"(\n{joined}\n)"


def build_variant_01_xor_basico() -> tuple[str, str, str]:
    """Variante 1: Renomeação dinâmica + XOR com chave aleatória de 16B + Base64."""
    key = secrets.token_bytes(16)
    blob = pack_benign_blob(BENIGN_MESSAGE, padding_size=750)
    encrypted = xor_bytes(blob, key)
    b64_payload = base64.b64encode(encrypted).decode("ascii")
    b64_key = base64.b64encode(key).decode("ascii")

    fn_dec = random_identifier("dec")
    fn_run = random_identifier("run")
    v_blob = random_identifier("blob")
    v_key = random_identifier("key")
    v_raw = random_identifier("raw")
    v_len = random_identifier("ln")
    v_msg = random_identifier("msg")

    code = f'''#!/usr/bin/env python3
"""Variante Polimorfica 01 (Simulacao Benigna — AI Cyber Duel)."""

import base64

{v_blob} = {format_multiline_literal(b64_payload)}
{v_key} = "{b64_key}"


def {fn_dec}(data_b64: str, key_b64: str) -> bytes:
    raw = base64.b64decode(data_b64.encode("ascii"))
    k = base64.b64decode(key_b64.encode("ascii"))
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(raw))


def {fn_run}() -> str:
    {v_raw} = {fn_dec}({v_blob}, {v_key})
    {v_len} = int.from_bytes({v_raw}[:2], byteorder="big")
    {v_msg} = {v_raw}[2 : 2 + {v_len}].decode("utf-8")
    print({v_msg})
    return {v_msg}


if __name__ == "__main__":
    {fn_run}()
'''
    return (
        "variante_01_xor_basico.py",
        "Renomeação + XOR 16B + Base64",
        code,
    )


def build_variant_02_junk_renomeacao() -> tuple[str, str, str]:
    """Variante 2: Junk code extenso + funções falsas + XOR 24B + Base85."""
    key = secrets.token_bytes(24)
    blob = pack_benign_blob(BENIGN_MESSAGE, padding_size=1400)
    encrypted = xor_bytes(blob, key)
    b85_payload = base64.b85encode(encrypted).decode("ascii")
    b85_key = base64.b85encode(key).decode("ascii")

    fn_dec = random_identifier("unpack")
    fn_run = random_identifier("exec")
    v_blob = random_identifier("seg")
    v_key = random_identifier("kref")
    v_raw = random_identifier("buf")
    v_len = random_identifier("sz")
    v_msg = random_identifier("out")

    dummy_fn_1 = generate_dummy_function()
    dummy_fn_2 = generate_dummy_function()
    junk_top = generate_junk_block(4, indent="    ")
    junk_mid = generate_junk_block(4, indent="    ")

    code = f'''#!/usr/bin/env python3
"""Variante Polimorfica 02 (Simulacao Benigna — AI Cyber Duel)."""

import base64

{dummy_fn_1}
{v_blob} = {format_multiline_literal(b85_payload)}
{v_key} = "{b85_key}"


{dummy_fn_2}
def {fn_dec}(enc: str, k_txt: str) -> bytes:
{junk_top}
    raw = base64.b85decode(enc.encode("ascii"))
    k = base64.b85decode(k_txt.encode("ascii"))
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(raw))


def {fn_run}() -> str:
{junk_mid}
    {v_raw} = {fn_dec}({v_blob}, {v_key})
    {v_len} = int.from_bytes({v_raw}[:2], byteorder="big")
    {v_msg} = {v_raw}[2 : 2 + {v_len}].decode("utf-8")
    print({v_msg})
    return {v_msg}


if __name__ == "__main__":
    {fn_run}()
'''
    return (
        "variante_02_junk_renomeacao.py",
        "Junk Code + Renomeação + XOR 24B + Base85",
        code,
    )


def build_variant_03_xor_multichave() -> tuple[str, str, str]:
    """Variante 3: Dupla camada XOR com 2 chaves distintas + Base85 + Junk Code."""
    key1 = secrets.token_bytes(20)
    key2 = secrets.token_bytes(29)
    blob = pack_benign_blob(BENIGN_MESSAGE, padding_size=2200)
    layer1 = xor_bytes(blob, key1)
    layer2 = xor_bytes(layer1, key2)
    b85_payload = base64.b85encode(layer2).decode("ascii")
    b85_k1 = base64.b85encode(key1).decode("ascii")
    b85_k2 = base64.b85encode(key2).decode("ascii")

    fn_x = random_identifier("mix")
    fn_main = random_identifier("entry")
    v_data = random_identifier("cipher")
    v_k1 = random_identifier("ka")
    v_k2 = random_identifier("kb")
    v_s1 = random_identifier("stage1")
    v_s2 = random_identifier("stage2")
    v_msg = random_identifier("txt")

    junk = generate_junk_block(3, indent="    ")

    code = f'''#!/usr/bin/env python3
"""Variante Polimorfica 03 (Simulacao Benigna — AI Cyber Duel)."""

import base64

{v_k1} = "{b85_k1}"
{v_k2} = "{b85_k2}"
{v_data} = {format_multiline_literal(b85_payload)}


def {fn_x}(stream: bytes, key: bytes) -> bytes:
    n = len(key)
    return bytes(val ^ key[idx % n] for idx, val in enumerate(stream))


def {fn_main}() -> str:
{junk}
    raw = base64.b85decode({v_data}.encode("ascii"))
    {v_s1} = {fn_x}(raw, base64.b85decode({v_k2}.encode("ascii")))
    {v_s2} = {fn_x}({v_s1}, base64.b85decode({v_k1}.encode("ascii")))
    size = int.from_bytes({v_s2}[:2], byteorder="big")
    {v_msg} = {v_s2}[2 : 2 + size].decode("utf-8")
    print({v_msg})
    return {v_msg}


if __name__ == "__main__":
    {fn_main}()
'''
    return (
        "variante_03_xor_multichave.py",
        "XOR Dupla Camada + Base85 + Junk Code",
        code,
    )


def build_variant_04_zlib_xor_camadas() -> tuple[str, str, str]:
    """Variante 4: Compressão Zlib + XOR 32B + Base85 + Predicado Opaco Benigno."""
    key = secrets.token_bytes(32)
    blob = pack_benign_blob(BENIGN_MESSAGE, padding_size=3000)
    compressed = zlib.compress(blob, level=9)
    encrypted = xor_bytes(compressed, key)
    b85_payload = base64.b85encode(encrypted).decode("ascii")
    b85_key = base64.b85encode(key).decode("ascii")

    fn_restore = random_identifier("inflate")
    fn_gate = random_identifier("check")
    v_blob = random_identifier("pack")
    v_key = random_identifier("seed")
    v_msg = random_identifier("res")
    opaque_n = secrets.randbelow(50) + 10

    code = f'''#!/usr/bin/env python3
"""Variante Polimorfica 04 (Simulacao Benigna — AI Cyber Duel)."""

import base64
import zlib

{v_blob} = {format_multiline_literal(b85_payload)}
{v_key} = "{b85_key}"


def {fn_gate}(n: int) -> bool:
    # Predicado opaco benigno: n * (n + 1) e sempre par
    return ((n * (n + 1)) % 2) == 0


def {fn_restore}() -> str:
    if not {fn_gate}({opaque_n}):
        return ""
    raw = base64.b85decode({v_blob}.encode("ascii"))
    k = base64.b85decode({v_key}.encode("ascii"))
    decrypted = bytes(b ^ k[i % len(k)] for i, b in enumerate(raw))
    plain = zlib.decompress(decrypted)
    ln = int.from_bytes(plain[:2], byteorder="big")
    {v_msg} = plain[2 : 2 + ln].decode("utf-8")
    print({v_msg})
    return {v_msg}


if __name__ == "__main__":
    {fn_restore}()
'''
    return (
        "variante_04_zlib_xor_camadas.py",
        "Zlib + XOR 32B + Base85 + Predicado Opaco",
        code,
    )


def build_variant_05_polimorfismo_total() -> tuple[str, str, str]:
    """Variante 5: Polimorfismo completo (Zlib + XOR rotativo + Base85 + Junk + Renomeação)."""
    key = secrets.token_bytes(48)
    salt = secrets.randbelow(200) + 13
    blob = pack_benign_blob(BENIGN_MESSAGE, padding_size=4200)
    compressed = zlib.compress(blob, level=9)
    encrypted = rotating_xor_bytes(compressed, key, salt=salt)
    b85_payload = base64.b85encode(encrypted).decode("ascii")
    b85_key = base64.b85encode(key).decode("ascii")

    fn_unroll = random_identifier("morph")
    fn_exec = random_identifier("dispatch")
    v_blob = random_identifier("vault")
    v_key = random_identifier("ring")
    v_salt = random_identifier("stride")
    v_msg = random_identifier("banner")

    dummy_fn = generate_dummy_function()
    junk_a = generate_junk_block(3, indent="    ")
    junk_b = generate_junk_block(2, indent="    ")

    code = f'''#!/usr/bin/env python3
"""Variante Polimorfica 05 (Simulacao Benigna — AI Cyber Duel)."""

import base64
import zlib

{v_salt} = {salt}
{v_key} = "{b85_key}"
{v_blob} = {format_multiline_literal(b85_payload)}

{dummy_fn}

def {fn_unroll}(enc_text: str, key_text: str, stride: int) -> bytes:
{junk_a}
    raw = base64.b85decode(enc_text.encode("ascii"))
    k = base64.b85decode(key_text.encode("ascii"))
    klen = len(k)
    unmasked = bytes(
        b ^ ((k[i % klen] + ((i * stride) & 0xFF)) & 0xFF)
        for i, b in enumerate(raw)
    )
    return zlib.decompress(unmasked)


def {fn_exec}() -> str:
{junk_b}
    buf = {fn_unroll}({v_blob}, {v_key}, {v_salt})
    length = int.from_bytes(buf[:2], byteorder="big")
    {v_msg} = buf[2 : 2 + length].decode("utf-8")
    print({v_msg})
    return {v_msg}


if __name__ == "__main__":
    {fn_exec}()
'''
    return (
        "variante_05_polimorfismo_total.py",
        "Polimorfismo Total (Zlib + XOR Rotativo + Base85 + Junk)",
        code,
    )


def format_entropy(value: float) -> str:
    """Estiliza a Entropia de Shannon conforme nível de suspeição."""
    if value >= 5.75:
        return f"[bold red]{value:.2f} bits/B (ALTA)[/bold red]"
    if value >= 5.20:
        return f"[bold yellow]{value:.2f} bits/B (MÉDIA)[/bold yellow]"
    return f"[bold green]{value:.2f} bits/B (NORMAL)[/bold green]"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulador de Motor Polimórfico (Red Team Educacional)"
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Executa sem pausas interativas (ideal para ensaios rápidos ou CI).",
    )
    args = parser.parse_args()

    console.clear()
    console.print(
        Panel.fit(
            "[bold red]MÓDULO 01 — RED TEAM: MOTOR POLIMÓRFICO SIMULADO[/bold red]\n"
            "[white]Demonstração prática de mutação automática de código e evasão de hash (SHA-256)[/white]\n"
            "[dim]Aviso: Simulação 100% benigna e acadêmica — zero código malicioso real.[/dim]",
            border_style="red",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )

    # Prepara pasta de saída usando pathlib.Path (100% multiplataforma)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for old_file in OUTPUT_DIR.glob("*.py"):
        old_file.unlink()

    # Etapa 1: Salva e analisa o payload benigno original
    original_path = OUTPUT_DIR / "payload_original.py"
    original_path.write_text(ORIGINAL_PAYLOAD_SOURCE, encoding="utf-8", newline="\n")
    original_bytes = original_path.read_bytes()
    original_hash = compute_sha256(original_path)
    original_entropy = compute_shannon_entropy(original_bytes)

    console.print("\n[bold cyan]ETAPA 1/3 — Payload Benigno Original (Antes da Mutação)[/bold cyan]")
    console.print(
        Panel(
            Syntax(ORIGINAL_PAYLOAD_SOURCE.strip(), "python", theme="monokai", line_numbers=True),
            title="[bold white]payload_original.py[/bold white]",
            subtitle=(
                f"[green]SHA-256: {original_hash[:24]}...[/green] | "
                f"[green]Entropia: {original_entropy:.2f} bits/byte[/green]"
            ),
            border_style="cyan",
        )
    )

    pause(args.auto)

    # Etapa 2: Gera as 5 variantes polimórficas
    console.print("\n[bold red]ETAPA 2/3 — Executando Motor Polimórfico (Gerando 5 Variantes)[/bold red]")
    builders = [
        build_variant_01_xor_basico,
        build_variant_02_junk_renomeacao,
        build_variant_03_xor_multichave,
        build_variant_04_zlib_xor_camadas,
        build_variant_05_polimorfismo_total,
    ]

    reports: list[VariantReport] = [
        VariantReport(
            filename=original_path.name,
            path=original_path,
            techniques="Código Original (Baseline Conhecido)",
            sha256=original_hash,
            entropy=original_entropy,
            size_bytes=len(original_bytes),
        )
    ]

    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=32, complete_style="red"),
        TextColumn("[bold white]{task.completed}/{task.total}[/bold white]"),
        console=console,
    ) as progress:
        task = progress.add_task("[red]Mutando payload com chaves e AST dinâmicas...", total=len(builders))
        for builder in builders:
            filename, techniques, source = builder()
            # Valida sintaxe Python real antes de salvar
            compile(source, filename, "exec")
            target_path = OUTPUT_DIR / filename
            target_path.write_text(source, encoding="utf-8", newline="\n")
            file_bytes = target_path.read_bytes()
            reports.append(
                VariantReport(
                    filename=filename,
                    path=target_path,
                    techniques=techniques,
                    sha256=compute_sha256(target_path),
                    entropy=compute_shannon_entropy(file_bytes),
                    size_bytes=len(file_bytes),
                )
            )
            if not args.auto:
                time.sleep(0.35)
            progress.advance(task)

    # Tabela comparativa de impacto visual no projetor
    table = Table(
        title="Comparativo Polimórfico — Mesmo Comportamento, Assinaturas Totalmente Diferentes",
        box=box.ROUNDED,
        header_style="bold white on red",
        show_lines=True,
    )
    table.add_column("Nome do Arquivo", style="bold cyan", no_wrap=True)
    table.add_column("Técnicas Aplicadas", style="white")
    table.add_column("Hash SHA-256", style="yellow", no_wrap=True)
    table.add_column("Entropia de Shannon", justify="right", no_wrap=True)
    table.add_column("Tamanho", justify="right", style="dim", no_wrap=True)

    for item in reports:
        short_hash = f"{item.sha256[:10]}...{item.sha256[-8:]}"
        hash_display = f"[bold green]{short_hash}[/bold green]" if item.filename == "payload_original.py" else short_hash
        table.add_row(
            item.filename,
            item.techniques,
            hash_display,
            format_entropy(item.entropy),
            f"{item.size_bytes:,} B",
        )

    console.print()
    console.print(table)

    unique_hashes = len({r.sha256 for r in reports})
    console.print(
        Panel(
            f"[bold green]✔ Artefatos salvos em:[/bold green] [cyan]{OUTPUT_DIR}[/cyan]\n"
            f"[bold yellow]• Hashes SHA-256 únicos gerados:[/bold yellow] [bold white]{unique_hashes} de {len(reports)} (100% distintos!)[/bold white]\n"
            f"[bold red]• Salto de Entropia:[/bold red] de [green]{original_entropy:.2f}[/green] bits/byte "
            f"para até [bold red]{max(r.entropy for r in reports):.2f}[/bold red] bits/byte.\n"
            "[dim]Observação: Note que a entropia elevada é exatamente a pista estatística que a IA defensiva usará depois![/dim]",
            title="[bold white]Resumo da Mutação Polimórfica[/bold white]",
            border_style="yellow",
        )
    )

    pause(args.auto)

    # Etapa 3: Prova de equivalência funcional + prévia do código mutado
    console.print("\n[bold cyan]ETAPA 3/3 — Prova de Equivalência Funcional (Código Mutado em Ação)[/bold cyan]")
    sample_variant = reports[-1]
    preview_lines = sample_variant.path.read_text(encoding="utf-8").splitlines()[:22]
    preview_snippet = "\n".join(preview_lines) + "\n# ... (restante do bloco ofuscado em Base85 + XOR rotativo)"

    console.print(
        Panel(
            Syntax(preview_snippet, "python", theme="monokai", line_numbers=True),
            title=f"[bold red]Trecho de {sample_variant.filename} (Completamente Irreconhecível!)[/bold red]",
            border_style="red",
        )
    )

    # Executa o original e a variante 5 em subprocessos benignos para provar mesma saída
    orig_exec = subprocess.run(
        [sys.executable, str(original_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    var_exec = subprocess.run(
        [sys.executable, str(sample_variant.path)],
        capture_output=True,
        text=True,
        check=True,
    )

    equiv_table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan")
    equiv_table.add_column("Artefato Executado", style="bold white")
    equiv_table.add_column("Saída Produzida no Terminal", style="bold green")
    equiv_table.add_row(original_path.name, orig_exec.stdout.strip())
    equiv_table.add_row(sample_variant.filename, var_exec.stdout.strip())

    console.print(
        Panel(
            equiv_table,
            title="[bold green]✔ Equivalência Funcional Comprovada[/bold green]",
            subtitle="[white]Próximo passo: python3 01-red-team-polymorphic/static_av_bypass_demo.py[/white]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()
