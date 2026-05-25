"""
Analyseur asynchrone - envoie les chunks à Claude Opus
avec contrôle de la concurrence et retry automatique
"""

import json
import re
import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
import anthropic
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from scanner.config import (
    ANTHROPIC_MODEL, SECURITY_SYSTEM_PROMPT,
    SECURITY_JSON_SCHEMA, MAX_CONCURRENCY
)
from scanner.ast_chunker import CodeChunk

console = Console()


# ─── Structures de résultats ──────────────────────────────────────────────────

@dataclass
class Vulnerability:
    id:              str
    severity:        str
    category:        str
    cwe:             str
    location:        str
    line_hint:       int
    description:     str
    vulnerable_code: str
    attack_scenario: str
    remediation:     str
    fixed_code:      str
    file_path:       str
    chunk_id:        str


@dataclass
class ChunkResult:
    chunk_id:      str
    file_path:     str
    language:      str
    node_name:     str
    security_score: float
    chunk_summary: str
    vulnerabilities: list[Vulnerability]
    observations:  str
    error:         Optional[str] = None
    tokens_used:   int = 0
    analysis_time: float = 0.0


# ─── Analyseur principal ──────────────────────────────────────────────────────

class OpusAnalyzer:
    """
    Envoie les chunks à Claude Opus de façon asynchrone.
    Contrôle la concurrence pour respecter les rate limits.
    """

    def __init__(self, api_key: Optional[str] = None, max_concurrency: int = MAX_CONCURRENCY):
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.async_client = anthropic.AsyncAnthropic(api_key=api_key) if api_key else anthropic.AsyncAnthropic()
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.total_tokens = 0
        self.total_cost = 0.0

    def analyze_chunks_sync(
        self,
        chunks: list[CodeChunk],
        global_context: dict,
        max_chunks: Optional[int] = None,
    ) -> list[ChunkResult]:
        """Point d'entrée synchrone (wrapper pour asyncio)."""
        if max_chunks:
            chunks = chunks[:max_chunks]

        return asyncio.run(self._analyze_all(chunks, global_context))

    async def _analyze_all(
        self,
        chunks: list[CodeChunk],
        global_context: dict,
    ) -> list[ChunkResult]:
        """Lance toutes les analyses en parallèle avec contrôle de concurrence."""

        context_str = self._format_global_context(global_context)

        console.print(f"\n[bold cyan]→ Analyse de {len(chunks)} chunks via Claude Opus[/bold cyan]")
        console.print(f"  Concurrence max : {MAX_CONCURRENCY} appels simultanés")

        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Analyse en cours...", total=len(chunks))

            async def analyze_with_progress(chunk: CodeChunk, idx: int) -> ChunkResult:
                result = await self._analyze_chunk_with_retry(chunk, context_str)
                progress.update(
                    task,
                    advance=1,
                    description=f"[{idx+1}/{len(chunks)}] {chunk.file_path} :: {chunk.node_name}"
                )
                return result

            tasks = [
                analyze_with_progress(chunk, i)
                for i, chunk in enumerate(chunks)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filtre les exceptions
        clean_results = []
        for r in results:
            if isinstance(r, Exception):
                console.print(f"  [red]Erreur non récupérée: {r}[/red]")
            else:
                clean_results.append(r)

        self._print_summary(clean_results)
        return clean_results

    async def _analyze_chunk_with_retry(
        self,
        chunk: CodeChunk,
        global_context: str,
        max_retries: int = 3,
    ) -> ChunkResult:
        """Analyse un chunk avec retry exponentiel en cas d'erreur."""
        async with self.semaphore:
            for attempt in range(max_retries):
                try:
                    return await self._analyze_chunk(chunk, global_context)
                except anthropic.RateLimitError:
                    wait = 2 ** attempt * 5  # 5s, 10s, 20s
                    console.print(f"  [yellow]Rate limit, attente {wait}s...[/yellow]")
                    await asyncio.sleep(wait)
                except anthropic.APIStatusError as e:
                    if attempt == max_retries - 1:
                        return self._error_result(chunk, f"API error: {e}")
                    await asyncio.sleep(2 ** attempt)
                except Exception as e:
                    if attempt == max_retries - 1:
                        return self._error_result(chunk, str(e))
                    await asyncio.sleep(1)

            return self._error_result(chunk, "Max retries atteint")

    async def _analyze_chunk(self, chunk: CodeChunk, global_context: str) -> ChunkResult:
        """Appel API Anthropic pour un chunk."""
        start_time = time.time()

        prompt = chunk.to_prompt(global_context) + f"\n\n{SECURITY_JSON_SCHEMA}"

        response = await self.async_client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=3000,
            system=SECURITY_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )

        elapsed = time.time() - start_time
        tokens = response.usage.input_tokens + response.usage.output_tokens
        self.total_tokens += tokens

        # Coût estimé (Opus : $15/M input, $75/M output)
        cost = (response.usage.input_tokens * 15 + response.usage.output_tokens * 75) / 1_000_000
        self.total_cost += cost

        raw = response.content[0].text.strip()
        return self._parse_response(raw, chunk, tokens, elapsed)

    def _parse_response(
        self,
        raw: str,
        chunk: CodeChunk,
        tokens: int,
        elapsed: float,
    ) -> ChunkResult:
        """Parse la réponse JSON d'Opus."""
        # Nettoie le markdown si présent
        raw = re.sub(r'^```json\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'\s*```\s*$', '', raw, flags=re.MULTILINE)
        raw = raw.strip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Tentative d'extraction JSON partielle
            json_match = re.search(r'\{.*\}', raw, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                except Exception:
                    return self._error_result(chunk, "JSON invalide dans la réponse", tokens, elapsed)
            else:
                return self._error_result(chunk, "Aucun JSON trouvé dans la réponse", tokens, elapsed)

        # Parse les vulnérabilités
        vulns = []
        for v in data.get("vulnerabilities", []):
            vulns.append(Vulnerability(
                id=v.get("id", "VULN-?"),
                severity=v.get("severity", "MEDIUM"),
                category=v.get("category", "OTHER"),
                cwe=v.get("cwe", ""),
                location=v.get("location", chunk.node_name),
                line_hint=int(v.get("line_hint", 0)),
                description=v.get("description", ""),
                vulnerable_code=v.get("vulnerable_code", ""),
                attack_scenario=v.get("attack_scenario", ""),
                remediation=v.get("remediation", ""),
                fixed_code=v.get("fixed_code", ""),
                file_path=chunk.file_path,
                chunk_id=chunk.chunk_id,
            ))

        return ChunkResult(
            chunk_id=chunk.chunk_id,
            file_path=chunk.file_path,
            language=chunk.language,
            node_name=chunk.node_name,
            security_score=float(data.get("security_score", 5.0)),
            chunk_summary=data.get("chunk_summary", ""),
            vulnerabilities=vulns,
            observations=data.get("observations", ""),
            tokens_used=tokens,
            analysis_time=elapsed,
        )

    def analyze_cross_features(
        self,
        all_results: list[ChunkResult],
        global_context: dict,
    ) -> dict:
        """
        Analyse transversale : détecte les failles qui traversent
        plusieurs features (ex: auth bypass → accès payment).
        """
        console.print("\n[bold cyan]→ Analyse transversale cross-features[/bold cyan]")

        # Résumé de toutes les vulnérabilités par feature
        vulns_by_feature: dict[str, list[str]] = {}
        for result in all_results:
            feature = result.file_path.split("/")[0] if "/" in result.file_path else "root"
            if feature not in vulns_by_feature:
                vulns_by_feature[feature] = []
            for v in result.vulnerabilities:
                vulns_by_feature[feature].append(
                    f"[{v.severity}] {v.category} dans {v.location}: {v.description[:100]}"
                )

        summary_text = "\n".join([
            f"\n=== Feature: {feature} ===\n" + "\n".join(vulns[:10])
            for feature, vulns in vulns_by_feature.items()
            if vulns
        ])

        if not summary_text.strip():
            return {"cross_vulnerabilities": [], "summary": "Aucune vulnérabilité transversale détectée."}

        prompt = f"""
Contexte architectural :
{self._format_global_context(global_context)}

Résultats d'analyse par feature :
{summary_text}

Identifie les VULNÉRABILITÉS TRANSVERSALES (qui impliquent plusieurs couches ou features).
Exemples : bypass auth → accès admin, injection SQL dans un service utilisé par plusieurs controllers.

Réponds en JSON :
{{
  "cross_vulnerabilities": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM",
      "description": "description de la faille transversale",
      "affected_features": ["auth", "payment"],
      "attack_chain": "comment un attaquant enchaîne les failles",
      "remediation": "comment corriger"
    }}
  ],
  "summary": "bilan global de sécurité du projet"
}}
"""
        try:
            response = self.client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=2000,
                system=SECURITY_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            raw = response.content[0].text.strip()
            raw = re.sub(r'^```json\s*', '', raw)
            raw = re.sub(r'\s*```$', '', raw)
            result = json.loads(raw)
            console.print(f"  [green]✓[/green] Analyse transversale terminée")
            return result
        except Exception as e:
            console.print(f"  [yellow]⚠ Erreur analyse transversale: {e}[/yellow]")
            return {"cross_vulnerabilities": [], "summary": "Analyse transversale non disponible."}

    def _format_global_context(self, ctx: dict) -> str:
        """Formate le contexte global pour l'injection dans les prompts."""
        if not ctx:
            return ""
        lines = [
            f"Projet : {ctx.get('repo_name', '?')}",
            f"Stack  : {', '.join(ctx.get('tech_stack', []))}",
            f"Auth   : {ctx.get('auth_mechanism', '?')}",
            f"DB     : {', '.join(ctx.get('db_access_patterns', []))}",
            f"Notes  : {ctx.get('risk_map', {}).get('context_for_analysis', '')}",
        ]
        immediate = ctx.get("immediate_findings", [])
        if immediate:
            lines.append(f"Findings immédiats : {len(immediate)} détectés (voir rapport global)")
        return "\n".join(lines)

    def _error_result(
        self,
        chunk: CodeChunk,
        error: str,
        tokens: int = 0,
        elapsed: float = 0.0,
    ) -> ChunkResult:
        return ChunkResult(
            chunk_id=chunk.chunk_id,
            file_path=chunk.file_path,
            language=chunk.language,
            node_name=chunk.node_name,
            security_score=0.0,
            chunk_summary="",
            vulnerabilities=[],
            observations="",
            error=error,
            tokens_used=tokens,
            analysis_time=elapsed,
        )

    def _print_summary(self, results: list[ChunkResult]):
        """Affiche un résumé de l'analyse."""
        total_vulns = sum(len(r.vulnerabilities) for r in results)
        by_severity = {}
        for r in results:
            for v in r.vulnerabilities:
                by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

        errors = sum(1 for r in results if r.error)

        console.print(f"\n[green]✓ Analyse terminée[/green]")
        console.print(f"  Chunks analysés  : {len(results)}")
        console.print(f"  Total failles    : {total_vulns}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = by_severity.get(sev, 0)
            if count:
                color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green", "INFO": "dim"}.get(sev, "white")
                console.print(f"  [{color}]{sev:10}[/{color}] : {count}")
        if errors:
            console.print(f"  [red]Erreurs        : {errors}[/red]")
        console.print(f"  Tokens utilisés  : {self.total_tokens:,}")
        console.print(f"  Coût estimé      : ${self.total_cost:.4f}")
