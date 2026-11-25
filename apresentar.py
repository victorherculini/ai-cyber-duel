#!/usr/bin/env python3
"""
AI Cyber Duel — Menu Interativo de Apresentação Ao Vivo
=======================================================
Central de comando para executar todos os módulos da demonstração com uma
única tecla no projetor (compatível com Linux Mint e Windows, Python 3.10+).

Uso:
  python3 apresentar.py
  python3 apresentar.py --auto
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

ROOT_DIR = Path(__file__).resolve().parent
VARIANTS_DIR = ROOT_DIR / "01-red-team-polymorphic" / "generated_variants"
SANDBOX_DIR = ROOT_DIR / "sandbox_env"
QUARANTINE_DIR = ROOT_DIR / "quarantine"
TELEMETRY_CSV = ROOT_DIR / "02-blue-team-realtime-ids" / "telemetry_dataset.csv"
REPORT_PATH = ROOT_DIR / "RELATORIO_INCIDENTE_SOC.md"
DASHBOARD_PATH = ROOT_DIR / "dashboard_soc.png"

MENU_SCRIPTS: dict[str, tuple[str, Path, bool]] = {
    "1": (
        "Gerador Polimórfico Básico",
        ROOT_DIR / "01-red-team-polymorphic" / "polymorphic_simulator.py",
        True,
    ),
    "2": (
        "Teste no Antivírus Tradicional SHA-256",
        ROOT_DIR / "01-red-team-polymorphic" / "static_av_bypass_demo.py",
        True,
    ),
    "3": (
        "Treinar e Rodar IDS Defensivo com IA",
        ROOT_DIR / "02-blue-team-realtime-ids" / "train_and_detect_ids.py",
        True,
    ),
    "4": (
        "Motor Avançado de Mutação AST",
        ROOT_DIR / "01-red-team-polymorphic" / "ast_transform_engine.py",
        False,
    ),
    "5": (
        "Arena Ao Vivo Split-Screen",
        ROOT_DIR / "arena_duel_live.py",
        True,
    ),
    "7": (
        "Gráficos Visuais SOC (Terminal + dashboard_soc.png)",
        ROOT_DIR / "visual_analytics.py",
        True,
    ),
}

TEMP_ARTIFACTS: list[tuple[str, Path]] = [
    ("Variantes geradas (Red Team)", VARIANTS_DIR),
    ("Ambiente sandbox benigno", SANDBOX_DIR),
    ("Quarentena SOAR", QUARANTINE_DIR),
    ("Dataset de telemetria CSV", TELEMETRY_CSV),
    ("Relatório técnico SOC", REPORT_PATH),
    ("Dashboard gráfico SOC (PNG)", DASHBOARD_PATH),
]


def read_single_key(prompt: str) -> str:
    """
    Lê uma única tecla sem exigir ENTER quando em terminal interativo
    (Linux Mint via termios/tty e Windows via msvcrt). Em modo não-TTY,
    faz fallback transparente para input().
    """
    console.print(prompt, end="", highlight=False)
    sys.stdout.flush()

    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            return "0"
        return line.strip()[:1]

    if sys.platform == "win32":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x03", "\x04"):
            raise KeyboardInterrupt
        if ch in ("\x00", "\xe0"):
            _ = msvcrt.getwch()
            return ""
        console.print(ch if ch.isprintable() else "")
        return ch.strip()

    import termios
    import tty

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    if ch in ("\x03", "\x04"):
        raise KeyboardInterrupt
    console.print(ch if ch.isprintable() else "")
    return ch.strip()


def wait_return_to_menu(auto_mode: bool) -> None:
    """Aguarda confirmação antes de voltar ao menu principal."""
    if auto_mode:
        return
    if sys.stdin.isatty():
        read_single_key("\n[dim]Pressione qualquer tecla para voltar ao menu...[/dim] ")
    else:
        input("\n[Pressione ENTER para voltar ao menu...]")


def render_menu(auto_mode: bool) -> None:
    """Desenha o painel principal do menu interativo adaptado à resolução do projetor."""
    console.clear()
    term_w, term_h = console.size.width, console.size.height

    poly_count = len(list(VARIANTS_DIR.glob("variante_*.py"))) if VARIANTS_DIR.exists() else 0
    quarantine_count = len(list(QUARANTINE_DIR.glob("*.py"))) if QUARANTINE_DIR.exists() else 0
    report_badge = "[bold green]OK[/bold green]" if REPORT_PATH.exists() else "[dim]Não gerado[/dim]"
    png_badge = "[bold green]OK[/bold green]" if DASHBOARD_PATH.exists() else "[dim]Não gerado[/dim]"
    mode_badge = "[bold yellow]AUTO (--auto)[/bold yellow]" if auto_mode else "[bold cyan]INTERATIVO[/bold cyan]"
    os_label = f"{platform.system()} | Python {platform.python_version()}"
    res_style = "green" if term_w >= 96 else "yellow"
    res_note = "" if term_w >= 96 else " (compacto)"

    console.print(
        Panel.fit(
            "[bold white]⚔ AI CYBER DUEL — CENTRAL DE APRESENTAÇÃO AO VIVO[/bold white]\n"
            f"[dim]{os_label}  •  Terminal: [{res_style}]{term_w}x{term_h}{res_note}[/{res_style}]  •  Modo: {mode_badge}[/dim]\n"
            f"[white]Variantes:[/white] [cyan]{poly_count}[/cyan]  |  "
            f"[white]Quarentena:[/white] [yellow]{quarantine_count}[/yellow]  |  "
            f"[white]Relatório SOC:[/white] {report_badge}  |  "
            f"[white]Dashboard PNG:[/white] {png_badge}",
            border_style="blue",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    menu_table = Table(
        title="Selecione a Etapa da Demonstração (1 tecla)",
        box=box.ROUNDED,
        header_style="bold white on dark_blue",
        show_lines=True,
        expand=term_w < 100,
    )
    menu_table.add_column("Tecla", justify="center", style="bold yellow", no_wrap=True)
    menu_table.add_column("Módulo / Ação", style="bold white")
    menu_table.add_column("Camada", style="cyan", no_wrap=True)

    menu_table.add_row("[1]", "Gerador Polimórfico Básico", "[red]Red Team[/red]")
    menu_table.add_row("[2]", "Teste no Antivírus Tradicional SHA-256", "[yellow]Defesa Legada[/yellow]")
    menu_table.add_row("[3]", "Treinar e Rodar IDS Defensivo com IA", "[blue]Blue Team (ML)[/blue]")
    menu_table.add_row("[4]", "Motor Avançado de Mutação AST", "[red]Red Team (AST)[/red]")
    menu_table.add_row("[5]", "Arena Ao Vivo Split-Screen", "[magenta]Duelo Real SO[/magenta]")
    menu_table.add_row("[6]", "Exibir Relatório Técnico Gerado (RELATORIO_INCIDENTE_SOC.md)", "[green]Relatório SOC[/green]")
    menu_table.add_row("[7]", "Gráficos Visuais SOC (Terminal + dashboard_soc.png)", "[cyan]Visual Analytics[/cyan]")
    menu_table.add_row("[0]", "Limpar artefatos temporários e sair", "[dim]Limpeza / Sair[/dim]")

    console.print()
    console.print(menu_table)


def run_module_script(choice: str, auto_mode: bool) -> int:
    """Executa o script selecionado usando o mesmo interpretador Python (sys.executable)."""
    title, script_path, supports_auto = MENU_SCRIPTS[choice]
    if not script_path.exists():
        console.print(
            Panel(
                f"[bold red]Arquivo não encontrado:[/bold red] [cyan]{script_path}[/cyan]",
                title="Erro de Caminho",
                border_style="red",
            )
        )
        return 1

    cmd = [sys.executable, str(script_path)]
    if auto_mode and supports_auto:
        cmd.append("--auto")

    console.print(
        f"\n[bold cyan]▶ Executando [{choice}] {title}...[/bold cyan]\n"
        f"[dim]Comando: {' '.join(cmd)}[/dim]\n"
    )
    try:
        result = subprocess.run(cmd, cwd=str(ROOT_DIR), check=False)
        if result.returncode != 0:
            console.print(
                f"\n[bold yellow]⚠ O módulo encerrou com código {result.returncode}.[/bold yellow]"
            )
        return result.returncode
    except KeyboardInterrupt:
        console.print("\n[yellow]Execução interrompida pelo apresentador (Ctrl+C).[/yellow]")
        return 130


def show_soc_report() -> None:
    """Renderiza o relatório técnico RELATORIO_INCIDENTE_SOC.md no terminal."""
    console.clear()
    if not REPORT_PATH.exists():
        console.print(
            Panel(
                "[bold yellow]O relatório técnico ainda não foi gerado.[/bold yellow]\n\n"
                "Execute primeiro a opção [bold magenta][5] Arena Ao Vivo Split-Screen[/bold magenta] "
                "para capturar telemetria real (`watchdog` + `psutil`) e gerar o arquivo "
                "[cyan]RELATORIO_INCIDENTE_SOC.md[/cyan].",
                title="Relatório SOC Ausente",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
        return

    content = REPORT_PATH.read_text(encoding="utf-8")
    console.print(
        Panel(
            Markdown(content),
            title=f"[bold green]Relatório Técnico SOC — {REPORT_PATH.name}[/bold green]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


def cleanup_artifacts() -> None:
    """Remove todos os artefatos temporários de demonstração antes de encerrar."""
    table = Table(
        title="Limpeza de Artefatos Temporários",
        box=box.ROUNDED,
        header_style="bold white on dark_blue",
    )
    table.add_column("Artefato", style="white")
    table.add_column("Caminho", style="cyan")
    table.add_column("Status", justify="center")

    for label, path in TEMP_ARTIFACTS:
        rel = str(path.relative_to(ROOT_DIR))
        if not path.exists():
            table.add_row(label, rel, "[dim]Já limpo[/dim]")
            continue
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            table.add_row(label, rel, "[bold green]✔ Removido[/bold green]")
        except OSError as exc:
            table.add_row(label, rel, f"[bold red]✖ Erro: {exc}[/bold red]")

    console.print()
    console.print(table)
    console.print(
        Panel.fit(
            "[bold green]✔ Ambiente limpo! Apresentação encerrada com segurança.[/bold green]",
            border_style="green",
        )
    )


def handle_choice(choice: str, auto_mode: bool) -> tuple[bool, int]:
    """Processa uma opção do menu. Retorna (continuar_loop, codigo_retorno)."""
    if choice in MENU_SCRIPTS:
        rc = run_module_script(choice, auto_mode)
        wait_return_to_menu(auto_mode)
        return True, rc
    if choice == "6":
        show_soc_report()
        wait_return_to_menu(auto_mode)
        return True, 0
    if choice == "0":
        cleanup_artifacts()
        return False, 0

    console.print(
        f"\n[bold red]Opção inválida:[/bold red] {choice!r}. Escolha uma tecla de [bold yellow]0[/bold yellow] a [bold yellow]7[/bold yellow]."
    )
    wait_return_to_menu(auto_mode)
    return True, 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Menu interativo de apresentação ao vivo do AI Cyber Duel."
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Passa --auto para os scripts executados (sem pausas internas).",
    )
    parser.add_argument(
        "--choice",
        choices=["0", "1", "2", "3", "4", "5", "6", "7"],
        help="Executa uma única opção do menu e encerra (útil para testes automatizados).",
    )
    args = parser.parse_args()

    if args.choice is not None:
        _, rc = handle_choice(args.choice, auto_mode=True)
        sys.exit(rc)

    try:
        while True:
            render_menu(args.auto)
            choice = read_single_key("\n[bold cyan]Digite a tecla da opção [0-7]:[/bold cyan] ")
            keep_running, _ = handle_choice(choice, args.auto)
            if not keep_running:
                break
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Menu encerrado via Ctrl+C (artefatos preservados).[/yellow]")


if __name__ == "__main__":
    main()
