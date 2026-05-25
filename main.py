#!/usr/bin/env python3
"""
AST Security Scanner — Point d'entrée principal
Analyse un repo GitHub avec Claude Opus pour détecter les failles de sécurité

Usage:
    python main.py --repo https://github.com/org/repo --api-key sk-ant-...
    python main.py --repo https://github.com/org/repo  # utilise ANTHROPIC_API_KEY
    python main.py --repo https://github.com/org/repo --branch develop --max-chunks 20
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ajoute le dossier courant au path
sys.path.insert(0, str(Path(__file__).parent))

from downloader import RepoDownloader
from ast_chunker import ASTChunker
from context_builder import ContextBuilder
from analyzer import OpusAnalyzer
from report import ReportGenerator
import anthropic

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyse de sécurité de code source via Claude Opus"
    )
    parser.add_argument(
        "--repo", required=True,
        help="URL du repo GitHub (ex: https://github.com/org/repo)"
    )
    parser.add_argument(
        "--branch", default="main",
        help="Branche à analyser (défaut: main)"
    )
    parser.add_argument(
        "--api-key",
        help="Clé API Anthropic (ou via ANTHROPIC_API_KEY)"
    )
    parser.add_argument(
        "--github-token",
        help="Token GitHub pour les repos privés (ou via GITHUB_TOKEN)"
    )
    parser.add_argument(
        "--max-chunks", type=int, default=None,
        help="Limite le nombre de chunks analysés (utile pour tester)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=4,
        help="Nombre d'appels API parallèles (défaut: 4)"
    )
    parser.add_argument(
        "--output", default=None,
        help="Chemin du rapport HTML (défaut: reports/rapport_<repo>_<date>.html)"
    )
    parser.add_argument(
        "--skip-tests", action="store_true", default=True,
        help="Ignore les fichiers de test (défaut: True)"
    )
    parser.add_argument(
        "--no-cross-analysis", action="store_true",
        help="Désactive l'analyse transversale (plus rapide)"
    )
    return parser.parse_args()


def print_banner():
    console.print(Panel.fit(
        "[bold white]🔐 AST Security Scanner[/bold white]\n"
        "[dim]Analyse de code source via Claude Opus[/dim]",
        border_style="cyan"
    ))


def print_chunk_overview(analyses):
    """Affiche un tableau récapitulatif des chunks avant analyse."""
    table = Table(title="Chunks à analyser", show_header=True, header_style="bold cyan")
    table.add_column("Fichier", style="dim", max_width=50)
    table.add_column("Feature", style="cyan")
    table.add_column("Chunks", justify="right")
    table.add_column("Priorité", justify="right")

    total_chunks = 0
    for analysis in analyses[:20]:  # Top 20
        table.add_row(
            analysis.file_path,
            analysis.feature,
            str(len(analysis.chunks)),
            str(analysis.priority)
        )
        total_chunks += len(analysis.chunks)

    if len(analyses) > 20:
        table.add_row(f"... et {len(analyses)-20} autres fichiers", "", "", "")

    console.print(table)
    console.print(f"\n[bold]Total : {len(analyses)} fichiers → {total_chunks} chunks[/bold]")
    return total_chunks


def main():
    print_banner()
    args = parse_args()

    # ── Résolution des clés ──────────────────────────────────────────────────
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]❌ Clé API Anthropic manquante.[/red]")
        console.print("   Utilise --api-key ou définit ANTHROPIC_API_KEY")
        sys.exit(1)

    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")

    # ── Dossier de sortie ────────────────────────────────────────────────────
    reports_dir = Path(__file__).parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    repo_name = args.repo.rstrip("/").split("/")[-1]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = Path(args.output) if args.output else reports_dir / f"rapport_{repo_name}_{timestamp}.html"

    downloader = None

    try:
        # ── ÉTAPE 1 : Téléchargement du repo ────────────────────────────────
        console.rule("[bold]Étape 1 : Téléchargement du repo")
        downloader = RepoDownloader(github_token=github_token)
        repo_path = downloader.download(args.repo, branch=args.branch)

        # ── ÉTAPE 2 : Parsing AST et chunking ───────────────────────────────
        console.rule("[bold]Étape 2 : Parsing AST et chunking")
        chunker = ASTChunker(skip_tests=args.skip_tests)
        file_analyses = chunker.process_repo(repo_path)

        if not file_analyses:
            console.print("[red]❌ Aucun fichier de code trouvé dans le repo.[/red]")
            sys.exit(1)

        # Aplatit les chunks triés par priorité
        all_chunks = []
        for analysis in file_analyses:
            all_chunks.extend(analysis.chunks)

        total_chunks = print_chunk_overview(file_analyses)

        if args.max_chunks:
            console.print(f"\n[yellow]⚠ Limite --max-chunks={args.max_chunks} appliquée[/yellow]")
            all_chunks = all_chunks[:args.max_chunks]

        # ── ÉTAPE 3 : Contexte global ────────────────────────────────────────
        console.rule("[bold]Étape 3 : Contexte global")
        anthropic_client = anthropic.Anthropic(api_key=api_key)
        ctx_builder = ContextBuilder(client=anthropic_client)
        global_context = ctx_builder.build_and_analyze(repo_path, args.repo)

        # ── ÉTAPE 4 : Analyse des chunks ─────────────────────────────────────
        console.rule("[bold]Étape 4 : Analyse des chunks via Claude Opus")
        analyzer = OpusAnalyzer(api_key=api_key, max_concurrency=args.concurrency)
        results = analyzer.analyze_chunks_sync(
            chunks=all_chunks,
            global_context=global_context,
            max_chunks=args.max_chunks,
        )

        # ── ÉTAPE 5 : Analyse transversale ───────────────────────────────────
        cross_analysis = {"cross_vulnerabilities": [], "summary": ""}
        if not args.no_cross_analysis:
            console.rule("[bold]Étape 5 : Analyse transversale")
            cross_analysis = analyzer.analyze_cross_features(results, global_context)

        # ── ÉTAPE 6 : Génération du rapport ──────────────────────────────────
        console.rule("[bold]Étape 6 : Génération du rapport")
        reporter = ReportGenerator()
        report_path = reporter.generate(
            results=results,
            cross_analysis=cross_analysis,
            global_context=global_context,
            repo_url=args.repo,
            output_path=output_path,
        )

        # ── Sauvegarde JSON brut ──────────────────────────────────────────────
        json_path = output_path.with_suffix(".json")
        with open(json_path, "w") as f:
            json.dump({
                "repo": args.repo,
                "branch": args.branch,
                "timestamp": timestamp,
                "global_context": global_context,
                "cross_analysis": cross_analysis,
                "results": [
                    {
                        "chunk_id": r.chunk_id,
                        "file_path": r.file_path,
                        "node_name": r.node_name,
                        "security_score": r.security_score,
                        "vulnerabilities": [
                            {
                                "id": v.id,
                                "severity": v.severity,
                                "category": v.category,
                                "cwe": v.cwe,
                                "location": v.location,
                                "line_hint": v.line_hint,
                                "description": v.description,
                                "vulnerable_code": v.vulnerable_code,
                                "attack_scenario": v.attack_scenario,
                                "remediation": v.remediation,
                                "fixed_code": v.fixed_code,
                            }
                            for v in r.vulnerabilities
                        ],
                        "error": r.error,
                    }
                    for r in results
                ],
            }, f, ensure_ascii=False, indent=2)

        # ── Résumé final ──────────────────────────────────────────────────────
        console.print()
        console.print(Panel(
            f"[bold green]✅ Analyse terminée avec succès[/bold green]\n\n"
            f"Rapport HTML : [cyan]{report_path}[/cyan]\n"
            f"Données JSON : [cyan]{json_path}[/cyan]\n\n"
            f"Tokens utilisés : [yellow]{analyzer.total_tokens:,}[/yellow]\n"
            f"Coût estimé    : [yellow]${analyzer.total_cost:.4f}[/yellow]",
            border_style="green"
        ))

        return str(report_path)

    except KeyboardInterrupt:
        console.print("\n[yellow]Analyse interrompue par l'utilisateur.[/yellow]")
        sys.exit(0)
    except ValueError as e:
        console.print(f"\n[red]❌ Erreur : {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]❌ Erreur inattendue : {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)
    finally:
        if downloader:
            downloader.cleanup()


if __name__ == "__main__":
    main()
