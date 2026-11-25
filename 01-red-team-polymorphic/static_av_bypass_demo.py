#!/usr/bin/env python3
"""
AI Cyber Duel — Módulo 01 (Red Team): Demonstração de Evasão de AV Estático
===========================================================================
Simula um Antivírus tradicional baseado em banco de assinaturas SHA-256.
Comprova visualmente que o AV bloqueia 100% da versão original conhecida,
mas apresenta 0% de detecção sobre as 5 variantes polimórficas recém-geradas.

Uso:
  python3 01-red-team-polymorphic/static_av_bypass_demo.py
  python3 01-red-team-polymorphic/static_av_bypass_demo.py --auto
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

BASE_DIR = Path(__file__).resolve().parent
VARIANTS_DIR = BASE_DIR / "generated_variants"

# Mesmo código-fonte canônico da amostra original conhecida pelo AV
KNOWN_ORIGINAL_SOURCE = '''#!/usr/bin/env python3
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

KNOWN_ORIGINAL_SHA256 = hashlib.sha256(KNOWN_ORIGINAL_SOURCE.encode("utf-8")).hexdigest()

# Banco de assinaturas estáticas simulado (Threat Intelligence SHA-256)
SIGNATURE_DATABASE: dict[str, str] = {
    KNOWN_ORIGINAL_SHA256: "Sim.Edu.Original.A",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f": "Legacy.Trojan.01",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "EmptyFile.Ref",
}


def pause(auto: bool, prompt: str = "\n[Pressione ENTER para continuar a demonstração...]") -> None:
    if not auto:
        input(prompt)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulador de Antivírus Tradicional por Assinaturas SHA-256"
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
            "[bold yellow]ANTIVÍRUS TRADICIONAL — DETECÇÃO POR ASSINATURAS (SHA-256)[/bold yellow]\n"
            "[white]Simulando um mecanismo clássico de Threat Intelligence baseado em hash exato[/white]",
            border_style="yellow",
            box=box.DOUBLE,
            padding=(1, 3),
        )
    )

    if not VARIANTS_DIR.exists():
        console.print(
            Panel(
                "[bold red]Erro:[/bold red] A pasta [cyan]generated_variants/[/cyan] ainda não existe.\n"
                "Execute primeiro o motor polimórfico:\n\n"
                "  [bold green]python3 01-red-team-polymorphic/polymorphic_simulator.py[/bold green]",
                border_style="red",
                title="Pré-requisito Ausente",
            )
        )
        sys.exit(1)

    target_files = sorted(VARIANTS_DIR.glob("*.py"))
    if not target_files:
        console.print(
            Panel(
                "[bold red]Nenhum arquivo .py encontrado em generated_variants/.[/bold red]\n"
                "Execute primeiro: [bold green]python3 01-red-team-polymorphic/polymorphic_simulator.py[/bold green]",
                border_style="red",
            )
        )
        sys.exit(1)

    # Garante que payload_original.py apareça primeiro na demonstração
    target_files.sort(key=lambda p: (0 if p.name == "payload_original.py" else 1, p.name))

    # Exibe o banco de assinaturas conhecidas do AV
    db_table = Table(
        title="Banco de Assinaturas Estáticas Carregado (Blacklist SHA-256)",
        box=box.ROUNDED,
        header_style="bold black on yellow",
    )
    db_table.add_column("Nome da Assinatura", style="bold white")
    db_table.add_column("Hash SHA-256 Registrado", style="cyan")

    for sig_hash, sig_name in SIGNATURE_DATABASE.items():
        highlight = f"[bold green]{sig_name}[/bold green]" if sig_hash == KNOWN_ORIGINAL_SHA256 else sig_name
        db_table.add_row(highlight, f"{sig_hash[:24]}...{sig_hash[-12:]}")

    console.print()
    console.print(db_table)

    pause(args.auto, "\n[Pressione ENTER para iniciar a varredura do Antivírus tradicional...]")

    # Executa varredura com barra de progresso
    scan_results: list[tuple[str, str, bool, str]] = []
    console.print()
    with Progress(
        SpinnerColumn(style="bold yellow"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=32, complete_style="yellow"),
        TextColumn("[bold white]{task.completed}/{task.total}[/bold white]"),
        console=console,
    ) as progress:
        task = progress.add_task("[yellow]Escaneando arquivos em generated_variants/...", total=len(target_files))
        for file_path in target_files:
            file_hash = sha256_file(file_path)
            matched_sig = SIGNATURE_DATABASE.get(file_hash)
            detected = matched_sig is not None
            scan_results.append(
                (file_path.name, file_hash, detected, matched_sig or "Nenhuma assinatura encontrada")
            )
            if not args.auto:
                time.sleep(0.4)
            progress.advance(task)

    # Monta tabela de resultado da varredura
    result_table = Table(
        title="Relatório de Varredura — Antivírus Baseado em Assinaturas (SHA-256)",
        box=box.ROUNDED,
        header_style="bold white on blue",
        show_lines=True,
    )
    result_table.add_column("Arquivo Analisado", style="bold cyan", no_wrap=True)
    result_table.add_column("Hash SHA-256", style="dim white", no_wrap=True)
    result_table.add_column("Decisão do Antivírus", justify="center", no_wrap=True)
    result_table.add_column("Detalhe / Motivo", style="white")

    orig_total = 0
    orig_blocked = 0
    poly_total = 0
    poly_blocked = 0

    for filename, file_hash, detected, detail in scan_results:
        is_original = filename == "payload_original.py"
        if is_original:
            orig_total += 1
            if detected:
                orig_blocked += 1
        else:
            poly_total += 1
            if detected:
                poly_blocked += 1

        if detected:
            status_badge = "[bold white on green] ✔ BLOQUEADO [/bold white on green]"
            detail_fmt = f"[green]Assinatura: {detail}[/green]"
        else:
            status_badge = "[bold white on red] ✖ EVADIDO (LIBERADO) [/bold white on red]"
            detail_fmt = "[red]Hash desconhecido — passou sem alertas![/red]"

        result_table.add_row(
            filename,
            f"{file_hash[:10]}...{file_hash[-8:]}",
            status_badge,
            detail_fmt,
        )

    console.print()
    console.print(result_table)

    poly_rate = (poly_blocked / poly_total * 100.0) if poly_total else 0.0
    orig_rate = (orig_blocked / orig_total * 100.0) if orig_total else 0.0

    # Painel dramático de conclusão da falha estática
    console.print(
        Panel(
            f"[bold green]• Versão Original Conhecida:[/bold green] "
            f"[bold white]{orig_blocked}/{orig_total} bloqueada ({orig_rate:.0f}%)[/bold white]\n"
            f"[bold red]• Variantes Polimórficas:[/bold red]    "
            f"[bold red]{poly_blocked}/{poly_total} detectadas ({poly_rate:.0f}% — EVASÃO TOTAL!)[/bold red]\n\n"
            "[bold yellow]Por que o Antivírus falhou?[/bold yellow]\n"
            "Funções hash criptográficas (SHA-256) possuem [bold]efeito avalanche[/bold]: alterar\n"
            "uma única variável, inserir código morto ou trocar a chave XOR gera uma assinatura\n"
            "100% inédita. Contra polimorfismo automatizado por IA, listas estáticas ficam cegas.\n\n"
            "[bold cyan]Próximo passo (Blue Team — Defesa com Machine Learning):[/bold cyan]\n"
            "  [bold white]python3 02-blue-team-realtime-ids/train_and_detect_ids.py[/bold white]",
            title="[bold red]⚠ VEREDITO: FALHA CRÍTICA DA ANÁLISE ESTÁTICA[/bold red]",
            border_style="red",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()
