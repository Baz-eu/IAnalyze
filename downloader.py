"""
Module de téléchargement de repos GitHub
Supporte : URL HTTPS, repos publics et privés (via token)
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional
import git
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class RepoDownloader:
    """
    Clone un repo GitHub localement pour analyse.
    Gère les repos publics et privés (via GitHub token).
    """

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.temp_dir: Optional[str] = None

    def download(self, repo_url: str, branch: str = "main") -> Path:
        """
        Clone le repo et retourne le chemin local.

        Args:
            repo_url : URL GitHub (ex: https://github.com/org/repo)
            branch   : branche à cloner (défaut: main)

        Returns:
            Path vers le dossier cloné
        """
        # Normalise l'URL
        repo_url = self._normalize_url(repo_url)
        repo_name = self._extract_repo_name(repo_url)

        # Crée un dossier temporaire
        self.temp_dir = tempfile.mkdtemp(prefix=f"scanner_{repo_name}_")
        clone_path = Path(self.temp_dir) / repo_name

        console.print(f"\n[bold cyan]→ Clonage du repo[/bold cyan] {repo_url}")
        console.print(f"  Branche : {branch}")
        console.print(f"  Destination : {clone_path}")

        try:
            # Injection du token dans l'URL si disponible (repos privés)
            auth_url = self._build_auth_url(repo_url)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Clonage en cours...", total=None)

                git.Repo.clone_from(
                    auth_url,
                    clone_path,
                    branch=branch,
                    depth=1,           # Shallow clone : seulement le dernier commit
                    single_branch=True # Seulement la branche demandée
                )

                progress.update(task, description="Clone terminé ✓")

            # Statistiques du repo
            stats = self._compute_stats(clone_path)
            console.print(f"\n[green]✓ Repo cloné avec succès[/green]")
            console.print(f"  Fichiers Java/Python/JS : {stats['code_files']}")
            console.print(f"  Taille totale : {stats['total_size_mb']:.1f} MB")
            console.print(f"  Fichiers de config : {stats['config_files']}")

            return clone_path

        except git.exc.GitCommandError as e:
            error_msg = str(e)
            if "Authentication failed" in error_msg:
                raise ValueError(
                    "Authentification GitHub échouée. "
                    "Vérifiez votre GITHUB_TOKEN pour les repos privés."
                )
            elif "Repository not found" in error_msg or "not found" in error_msg.lower():
                raise ValueError(
                    f"Repo introuvable : {repo_url}\n"
                    "Vérifiez l'URL et vos permissions d'accès."
                )
            elif "Remote branch" in error_msg:
                # Essaie avec 'master' si 'main' n'existe pas
                if branch == "main":
                    console.print(f"  [yellow]Branche 'main' introuvable, essai avec 'master'...[/yellow]")
                    return self.download(repo_url, branch="master")
                raise ValueError(f"Branche '{branch}' introuvable dans ce repo.")
            else:
                raise ValueError(f"Erreur Git : {error_msg}")

    def cleanup(self):
        """Supprime le dossier temporaire après analyse."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            console.print(f"\n[dim]Dossier temporaire supprimé[/dim]")

    def _normalize_url(self, url: str) -> str:
        """Normalise l'URL GitHub (enlève .git, trailing slash, etc.)"""
        url = url.strip().rstrip("/")
        if url.endswith(".git"):
            url = url[:-4]
        # Convertit SSH en HTTPS si nécessaire
        if url.startswith("git@github.com:"):
            url = url.replace("git@github.com:", "https://github.com/")
        return url

    def _extract_repo_name(self, url: str) -> str:
        """Extrait le nom du repo depuis l'URL."""
        return url.rstrip("/").split("/")[-1]

    def _build_auth_url(self, url: str) -> str:
        """Injecte le token GitHub dans l'URL pour les repos privés."""
        if self.github_token and "github.com" in url:
            # Format : https://TOKEN@github.com/org/repo
            return url.replace("https://", f"https://{self.github_token}@")
        return url

    def _compute_stats(self, repo_path: Path) -> dict:
        """Calcule des statistiques sur le repo cloné."""
        from scanner.config import SUPPORTED_EXTENSIONS, CONFIG_FILES, IGNORED_DIRS

        code_files = 0
        config_count = 0
        total_size = 0

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

            for f in files:
                filepath = Path(root) / f
                size = filepath.stat().st_size
                total_size += size

                if filepath.suffix in SUPPORTED_EXTENSIONS:
                    code_files += 1
                if f in CONFIG_FILES:
                    config_count += 1

        return {
            "code_files": code_files,
            "config_files": config_count,
            "total_size_mb": total_size / (1024 * 1024),
        }
