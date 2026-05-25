"""
Parser AST et Chunker
Découpe le code source en chunks cohérents par unité logique (classe, méthode)
Supporte Java, Python, JavaScript/TypeScript
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
from rich.console import Console

from scanner.config import (
    SUPPORTED_EXTENSIONS, CONFIG_FILES, IGNORED_DIRS,
    AST_NODE_TYPES, MAX_CHUNK_CHARS, FILE_PRIORITY
)

console = Console()


# ─── Initialisation des parsers tree-sitter ───────────────────────────────────

LANGUAGES = {
    "java":       Language(tsjava.language()),
    "python":     Language(tspython.language()),
    "javascript": Language(tsjs.language()),
}

PARSERS = {
    lang: Parser(language)
    for lang, language in LANGUAGES.items()
}


# ─── Structures de données ────────────────────────────────────────────────────

@dataclass
class CodeChunk:
    """
    Un chunk de code prêt à être envoyé à Opus.
    Représente une unité logique cohérente du code source.
    """
    chunk_id:     str            # identifiant unique : "auth/AuthService.java::login"
    file_path:    str            # chemin relatif dans le repo
    language:     str            # java | python | javascript
    node_type:    str            # class | method | function | config | file
    node_name:    str            # nom de la classe/méthode
    content:      str            # code source du chunk
    start_line:   int            # ligne de début dans le fichier original
    end_line:     int            # ligne de fin dans le fichier original
    priority:     int            # 0-10 (plus élevé = analysé en premier)
    parent_class: Optional[str]  # classe parente si c'est une méthode
    feature:      str            # feature détectée (auth, payment, user, etc.)
    char_count:   int = field(init=False)

    def __post_init__(self):
        self.char_count = len(self.content)

    def to_prompt(self, global_context: str = "") -> str:
        """Construit le prompt complet pour Opus."""
        ctx_section = f"\n=== CONTEXTE GLOBAL DU PROJET ===\n{global_context}\n" if global_context else ""
        return f"""{ctx_section}
=== CHUNK À ANALYSER ===
ID         : {self.chunk_id}
Fichier    : {self.file_path}
Langage    : {self.language}
Type       : {self.node_type}
Nom        : {self.node_name}
Lignes     : {self.start_line} → {self.end_line}
Feature    : {self.feature}
{f'Classe parente : {self.parent_class}' if self.parent_class else ''}

=== CODE SOURCE ===
```{self.language}
{self.content}
```
"""


@dataclass
class FileAnalysis:
    """Résultat de l'analyse AST d'un fichier."""
    file_path: str
    language:  str
    priority:  int
    chunks:    list[CodeChunk]
    feature:   str
    raw_size:  int


# ─── Détection de feature ─────────────────────────────────────────────────────

FEATURE_KEYWORDS = {
    "auth":     ["auth", "login", "logout", "jwt", "token", "session", "oauth", "sso", "credential"],
    "payment":  ["payment", "pay", "billing", "invoice", "stripe", "transaction", "checkout"],
    "user":     ["user", "account", "profile", "member", "customer", "person"],
    "admin":    ["admin", "backoffice", "management", "console", "dashboard"],
    "security": ["security", "permission", "role", "acl", "access", "privilege", "firewall"],
    "api":      ["api", "rest", "graphql", "endpoint", "route", "controller", "handler"],
    "database": ["repository", "dao", "query", "sql", "db", "database", "persistence", "jpa"],
    "config":   ["config", "configuration", "properties", "settings", "env", "application"],
    "upload":   ["upload", "file", "storage", "s3", "blob", "media", "attachment"],
    "email":    ["email", "mail", "smtp", "notification", "message"],
    "crypto":   ["crypto", "encrypt", "decrypt", "hash", "cipher", "certificate", "ssl", "tls"],
}

def detect_feature(file_path: str, content: str) -> str:
    """Détecte la feature métier d'un fichier selon son nom et contenu."""
    path_lower = file_path.lower()
    content_lower = content.lower()

    scores = {}
    for feature, keywords in FEATURE_KEYWORDS.items():
        score = 0
        for kw in keywords:
            if kw in path_lower:
                score += 3  # Le nom du fichier pèse plus
            if kw in content_lower:
                score += 1
        scores[feature] = score

    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "general"


# ─── Calcul de priorité ───────────────────────────────────────────────────────

def compute_priority(file_path: str) -> int:
    """Calcule la priorité d'un fichier selon son nom."""
    filename = Path(file_path).stem  # nom sans extension
    max_priority = 1  # priorité minimale par défaut

    for keyword, priority in FILE_PRIORITY.items():
        if keyword.lower() in filename.lower():
            max_priority = max(max_priority, priority)

    return max_priority


# ─── Parser AST principal ─────────────────────────────────────────────────────

class ASTChunker:
    """
    Parse les fichiers source avec tree-sitter et les découpe
    en chunks sémantiques (classe, méthode, fonction).
    """

    def __init__(self, skip_tests: bool = True):
        self.skip_tests = skip_tests

    def process_repo(self, repo_path: Path) -> list[FileAnalysis]:
        """
        Parcourt le repo et parse tous les fichiers supportés.
        Retourne la liste des analyses triées par priorité décroissante.
        """
        console.print(f"\n[bold cyan]→ Parsing AST du repo[/bold cyan]")

        analyses = []
        config_analyses = []
        skipped = 0
        total_chunks = 0

        # ── Fichiers de code source ──
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = sorted([d for d in dirs if d not in IGNORED_DIRS])

            for filename in files:
                filepath = Path(root) / filename
                rel_path = str(filepath.relative_to(repo_path))
                ext = filepath.suffix.lower()

                if ext not in SUPPORTED_EXTENSIONS:
                    continue

                language = SUPPORTED_EXTENSIONS[ext]
                priority = compute_priority(filename)

                # Ignore les tests si demandé
                if self.skip_tests and priority == 0:
                    skipped += 1
                    continue

                try:
                    analysis = self._parse_file(filepath, rel_path, language, priority)
                    if analysis and analysis.chunks:
                        analyses.append(analysis)
                        total_chunks += len(analysis.chunks)
                except Exception as e:
                    console.print(f"  [yellow]⚠ Erreur parsing {rel_path}: {e}[/yellow]")

        # ── Fichiers de configuration ──
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for filename in files:
                if filename in CONFIG_FILES or filename.endswith((".yml", ".yaml", ".properties", ".env")):
                    filepath = Path(root) / filename
                    rel_path = str(filepath.relative_to(repo_path))
                    config_chunk = self._parse_config_file(filepath, rel_path)
                    if config_chunk:
                        config_analyses.append(config_chunk)

        # Trie par priorité décroissante
        analyses.sort(key=lambda a: a.priority, reverse=True)

        console.print(f"  [green]✓[/green] {len(analyses)} fichiers parsés → {total_chunks} chunks")
        console.print(f"  [green]✓[/green] {len(config_analyses)} fichiers de config")
        if skipped:
            console.print(f"  [dim]  {skipped} fichiers de test ignorés[/dim]")

        # Les configs sont analysées après le code (priorité 6)
        # On les insère comme FileAnalysis spéciaux
        for cfg in config_analyses:
            analyses.append(cfg)

        return analyses

    def _parse_file(self, filepath: Path, rel_path: str, language: str, priority: int) -> Optional[FileAnalysis]:
        """Parse un fichier source avec tree-sitter et crée les chunks."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        if not content.strip():
            return None

        raw_size = len(content)
        feature = detect_feature(rel_path, content)
        lines = content.split("\n")

        # Parse AST
        parser = PARSERS[language]
        tree = parser.parse(bytes(content, "utf-8"))
        root = tree.root_node

        # Extrait les nœuds logiques
        target_types = AST_NODE_TYPES[language]
        chunks = []

        self._extract_nodes(
            node=root,
            lines=lines,
            rel_path=rel_path,
            language=language,
            priority=priority,
            feature=feature,
            target_types=target_types,
            chunks=chunks,
            parent_class=None,
            depth=0,
        )

        # Si aucun nœud trouvé (fichier trop simple), chunk entier
        if not chunks:
            chunks.append(self._make_file_chunk(rel_path, content, language, priority, feature))

        return FileAnalysis(
            file_path=rel_path,
            language=language,
            priority=priority,
            chunks=chunks,
            feature=feature,
            raw_size=raw_size,
        )

    def _extract_nodes(
        self, node: Node, lines: list[str], rel_path: str,
        language: str, priority: int, feature: str,
        target_types: list[str], chunks: list[CodeChunk],
        parent_class: Optional[str], depth: int,
    ):
        """
        Parcourt récursivement l'AST et extrait les nœuds cibles.
        Gère les classes imbriquées et les méthodes.
        """
        if depth > 5:  # Limite la récursion
            return

        for child in node.children:
            if child.type in target_types:
                name = self._extract_node_name(child, language)
                start_line = child.start_point[0]
                end_line = child.end_point[0]
                code = "\n".join(lines[start_line:end_line + 1])

                # Si le chunk est trop grand, on le re-découpe
                if len(code) > MAX_CHUNK_CHARS:
                    # Re-découpe par méthodes internes
                    self._extract_nodes(
                        child, lines, rel_path, language, priority,
                        feature, target_types, chunks, name, depth + 1
                    )
                else:
                    node_type = self._classify_node_type(child.type, language)
                    chunk_id = f"{rel_path}::{parent_class + '.' if parent_class else ''}{name}"

                    chunks.append(CodeChunk(
                        chunk_id=chunk_id,
                        file_path=rel_path,
                        language=language,
                        node_type=node_type,
                        node_name=name,
                        content=code,
                        start_line=start_line + 1,
                        end_line=end_line + 1,
                        priority=priority,
                        parent_class=parent_class,
                        feature=feature,
                    ))
            else:
                # Continue la récursion
                self._extract_nodes(
                    child, lines, rel_path, language, priority,
                    feature, target_types, chunks, parent_class, depth + 1
                )

    def _extract_node_name(self, node: Node, language: str) -> str:
        """Extrait le nom d'un nœud AST (classe, méthode, fonction)."""
        for child in node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8")
        return "anonymous"

    def _classify_node_type(self, ast_type: str, language: str) -> str:
        """Convertit le type tree-sitter en type lisible."""
        mapping = {
            "class_declaration":      "class",
            "interface_declaration":  "interface",
            "method_declaration":     "method",
            "constructor_declaration":"constructor",
            "enum_declaration":       "enum",
            "class_definition":       "class",
            "function_definition":    "function",
            "function_declaration":   "function",
            "function_expression":    "function",
            "arrow_function":         "arrow_function",
            "method_definition":      "method",
        }
        return mapping.get(ast_type, ast_type)

    def _make_file_chunk(self, rel_path: str, content: str, language: str, priority: int, feature: str) -> CodeChunk:
        """Crée un chunk pour un fichier entier (pas de structure AST détectée)."""
        lines = content.split("\n")
        truncated = content[:MAX_CHUNK_CHARS] if len(content) > MAX_CHUNK_CHARS else content

        return CodeChunk(
            chunk_id=f"{rel_path}::__file__",
            file_path=rel_path,
            language=language,
            node_type="file",
            node_name=Path(rel_path).name,
            content=truncated,
            start_line=1,
            end_line=len(lines),
            priority=priority,
            parent_class=None,
            feature=feature,
        )

    def _parse_config_file(self, filepath: Path, rel_path: str) -> Optional[FileAnalysis]:
        """Parse un fichier de configuration (YAML, properties, XML)."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        if not content.strip():
            return None

        feature = detect_feature(rel_path, content)

        chunk = CodeChunk(
            chunk_id=f"{rel_path}::__config__",
            file_path=rel_path,
            language="yaml" if rel_path.endswith((".yml", ".yaml")) else "properties",
            node_type="config",
            node_name=Path(rel_path).name,
            content=content[:MAX_CHUNK_CHARS],
            start_line=1,
            end_line=len(content.split("\n")),
            priority=6,
            parent_class=None,
            feature=feature,
        )

        return FileAnalysis(
            file_path=rel_path,
            language="config",
            priority=6,
            chunks=[chunk],
            feature=feature,
            raw_size=len(content),
        )
