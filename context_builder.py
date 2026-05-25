"""
Constructeur du contexte global du projet
Analyse la structure du repo et crée un résumé architectural
envoyé à Opus avant l'analyse des chunks individuels
"""

import os
import re
import json
from pathlib import Path
from typing import Optional
import anthropic
from rich.console import Console

from scanner.config import (
    IGNORED_DIRS, SUPPORTED_EXTENSIONS,
    ANTHROPIC_MODEL, SECURITY_SYSTEM_PROMPT
)

console = Console()


class ContextBuilder:
    """
    Construit et envoie le contexte global du projet à Opus.
    Ce contexte est ensuite injecté dans chaque analyse de chunk.
    """

    def __init__(self, client: anthropic.Anthropic):
        self.client = client

    def build_and_analyze(self, repo_path: Path, repo_url: str) -> dict:
        """
        Construit le contexte global et demande à Opus une
        analyse architecturale initiale.

        Returns:
            dict avec architecture, findings immédiats, risk_map
        """
        console.print("\n[bold cyan]→ Construction du contexte global[/bold cyan]")

        context_prompt = self._build_context_prompt(repo_path, repo_url)

        console.print("  Envoi à Claude Opus pour analyse architecturale...")

        system = SECURITY_SYSTEM_PROMPT + """

Pour cette analyse ARCHITECTURALE (pas encore les fichiers individuels),
réponds UNIQUEMENT en JSON valide sans markdown :
{
  "repo_name": "nom du projet",
  "tech_stack": ["Spring Boot", "JWT", "PostgreSQL", ...],
  "architecture_type": "monolith|microservice|layered|hexagonal",
  "auth_mechanism": "JWT|Session|OAuth2|Basic|None",
  "db_access_patterns": ["JPA", "Native queries", "JDBC", ...],
  "public_endpoints": ["/api/auth/login", ...],
  "admin_endpoints": ["/api/admin/...", ...],
  "immediate_findings": [
    {
      "type": "VULNERABLE_DEPENDENCY|MISCONFIGURATION|EXPOSED_ENDPOINT|HARDCODED_SECRET",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "detail": "description précise"
    }
  ],
  "risk_map": {
    "highest_risk_files": ["fichiers critiques à analyser en priorité"],
    "security_concerns": ["liste des préoccupations de sécurité globales"],
    "context_for_analysis": "instructions importantes pour les analyses suivantes"
  },
  "summary": "résumé de l'architecture en 2-3 phrases"
}
"""
        try:
            response = self.client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=2000,
                system=system,
                messages=[{"role": "user", "content": context_prompt}]
            )

            raw = response.content[0].text.strip()
            # Nettoie les éventuels blocs markdown
            raw = re.sub(r'^```json\s*', '', raw)
            raw = re.sub(r'\s*```$', '', raw)

            result = json.loads(raw)
            console.print(f"  [green]✓[/green] Contexte global analysé")
            console.print(f"  Stack : {', '.join(result.get('tech_stack', []))}")

            immediate = result.get("immediate_findings", [])
            if immediate:
                critical = [f for f in immediate if f.get("severity") == "CRITICAL"]
                console.print(f"  [red]⚠ {len(critical)} finding(s) CRITICAL immédiat(s) détecté(s)[/red]")

            return result

        except json.JSONDecodeError as e:
            console.print(f"  [yellow]⚠ Réponse JSON invalide du contexte global: {e}[/yellow]")
            return self._fallback_context(repo_path)
        except Exception as e:
            console.print(f"  [yellow]⚠ Erreur contexte global: {e}[/yellow]")
            return self._fallback_context(repo_path)

    def _build_context_prompt(self, repo_path: Path, repo_url: str) -> str:
        """Assemble le prompt de contexte global."""
        sections = [
            f"=== REPO À ANALYSER ===\nURL : {repo_url}\n",
            f"=== STRUCTURE DES PACKAGES ===\n{self._get_package_tree(repo_path)}\n",
        ]

        # pom.xml ou build.gradle
        deps = self._extract_dependencies(repo_path)
        if deps:
            sections.append(f"=== DÉPENDANCES ===\n{deps}\n")

        # Spring Security config
        security_cfg = self._find_security_config(repo_path)
        if security_cfg:
            sections.append(f"=== SPRING SECURITY CONFIG ===\n{security_cfg}\n")

        # Endpoints HTTP
        endpoints = self._extract_endpoints(repo_path)
        if endpoints:
            sections.append(f"=== ENDPOINTS HTTP DÉTECTÉS ===\n{endpoints}\n")

        # application.yml/properties
        app_config = self._extract_app_config(repo_path)
        if app_config:
            sections.append(f"=== CONFIGURATION APPLICATIVE ===\n{app_config}\n")

        sections.append(
            "Analyse l'architecture de sécurité de ce projet. "
            "Identifie les risques globaux et les fichiers les plus critiques à auditer."
        )

        return "\n".join(sections)

    def _get_package_tree(self, repo_path: Path, max_lines: int = 150) -> str:
        """Génère un arbre de la structure du projet."""
        tree_lines = []

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = sorted([d for d in dirs if d not in IGNORED_DIRS])
            level = str(root).replace(str(repo_path), "").count(os.sep)
            if level > 6:
                continue
            indent = "  " * level
            folder = Path(root).name
            tree_lines.append(f"{indent}{folder}/")

            sub_indent = "  " * (level + 1)
            for f in sorted(files):
                ext = Path(f).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS or f in [
                    "pom.xml", "build.gradle", "application.yml",
                    "application.properties", "Dockerfile"
                ]:
                    tree_lines.append(f"{sub_indent}{f}")

            if len(tree_lines) > max_lines:
                tree_lines.append("  ... (tronqué)")
                break

        return "\n".join(tree_lines)

    def _extract_dependencies(self, repo_path: Path) -> str:
        """Extrait les dépendances depuis pom.xml ou build.gradle."""
        # Maven
        pom = repo_path / "pom.xml"
        if pom.exists():
            return self._parse_pom(pom)

        # Gradle
        gradle = repo_path / "build.gradle"
        if gradle.exists():
            try:
                content = gradle.read_text(errors="replace")
                # Extrait les lignes de dépendances
                deps = re.findall(r"(implementation|compile|api|runtimeOnly)\s+['\"]([^'\"]+)['\"]", content)
                return "\n".join([f"{scope}: {dep}" for scope, dep in deps[:40]])
            except Exception:
                return ""

        return ""

    def _parse_pom(self, pom_path: Path) -> str:
        """Parse le pom.xml et extrait les dépendances avec versions."""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(pom_path)
            root = tree.getroot()
            ns = ""
            # Détecte le namespace Maven
            if root.tag.startswith("{"):
                ns_uri = root.tag.split("}")[0][1:]
                ns = f"{{{ns_uri}}}"

            deps = []
            for dep in root.iter(f"{ns}dependency"):
                group    = dep.findtext(f"{ns}groupId") or ""
                artifact = dep.findtext(f"{ns}artifactId") or ""
                version  = dep.findtext(f"{ns}version") or "?"
                scope    = dep.findtext(f"{ns}scope") or "compile"
                if scope != "test":  # Ignore les deps de test
                    deps.append(f"{group}:{artifact}:{version}")

            return "\n".join(deps[:50])
        except Exception as e:
            return f"Erreur parsing pom.xml: {e}"

    def _find_security_config(self, repo_path: Path) -> Optional[str]:
        """Trouve et retourne la config Spring Security."""
        patterns = [
            "**/SecurityConfig.java",
            "**/WebSecurityConfig.java",
            "**/SecurityConfiguration.java",
            "**/SecurityConfig.kt",
        ]
        import glob
        for pattern in patterns:
            matches = glob.glob(str(repo_path / pattern), recursive=True)
            if matches:
                try:
                    content = Path(matches[0]).read_text(errors="replace")
                    return content[:8000]  # Max 8k chars
                except Exception:
                    pass
        return None

    def _extract_endpoints(self, repo_path: Path) -> str:
        """Extrait tous les endpoints HTTP via regex."""
        endpoints = []
        patterns = [
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
            r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']',
            r'router\.(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',  # Express.js
            r'@app\.(get|post|put|delete|patch)\s*\(["\']([^"\']+)["\']',   # Flask
        ]

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for f in files:
                if not any(f.endswith(ext) for ext in [".java", ".py", ".js", ".ts"]):
                    continue
                filepath = Path(root) / f
                try:
                    content = filepath.read_text(errors="replace")
                    for pattern in patterns:
                        for match in re.finditer(pattern, content):
                            groups = match.groups()
                            method = groups[0].replace("Mapping", "").upper() if len(groups) > 1 else "?"
                            path = groups[-1]
                            endpoints.append(f"{method:8} {path:50} ({f})")
                except Exception:
                    pass

        return "\n".join(sorted(set(endpoints))[:80])

    def _extract_app_config(self, repo_path: Path) -> str:
        """Extrait application.yml/properties en masquant les secrets."""
        for config_name in ["application.yml", "application.yaml", "application.properties",
                            "application-prod.yml", "application-production.yml"]:
            config_path = repo_path / "src" / "main" / "resources" / config_name
            if not config_path.exists():
                config_path = repo_path / config_name
            if config_path.exists():
                try:
                    content = config_path.read_text(errors="replace")
                    # Masque les valeurs sensibles mais garde les clés
                    masked = re.sub(
                        r'(password|secret|key|token|credential|api[_-]?key)\s*:\s*\S+',
                        r'\1: [VALEUR MASQUÉE]',
                        content,
                        flags=re.IGNORECASE
                    )
                    # Signale les valeurs potentiellement en clair
                    raw_count = len(re.findall(
                        r'(password|secret|key)\s*:\s*(?!\$\{)(?!\[)(?![A-Z_]+\})\S+',
                        content, flags=re.IGNORECASE
                    ))
                    result = masked[:5000]
                    if raw_count > 0:
                        result += f"\n\n⚠️ {raw_count} valeur(s) potentiellement en clair détectée(s)"
                    return result
                except Exception:
                    pass
        return ""

    def _fallback_context(self, repo_path: Path) -> dict:
        """Contexte minimal si l'appel API échoue."""
        return {
            "repo_name": repo_path.name,
            "tech_stack": ["inconnu"],
            "architecture_type": "unknown",
            "auth_mechanism": "unknown",
            "immediate_findings": [],
            "risk_map": {
                "highest_risk_files": [],
                "security_concerns": [],
                "context_for_analysis": "Contexte global non disponible, analyse fichier par fichier."
            },
            "summary": "Contexte global non disponible."
        }
