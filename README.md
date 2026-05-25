# 🔐 AST Security Scanner

Analyse de sécurité de code source alimentée par **Claude Opus**.
Parse le code avec tree-sitter (AST), découpe en chunks sémantiques,
et envoie à Opus pour détecter les failles avec remédiations.

## Langages supportés
- **Java** (Spring Boot, Spring Security, JPA/Hibernate)
- **Python** (Flask, Django, FastAPI)
- **JavaScript / TypeScript** (Node.js, Express)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

```bash
# Clé API Anthropic (obligatoire)
export ANTHROPIC_API_KEY="sk-ant-..."

# Token GitHub (optionnel, pour les repos privés)
export GITHUB_TOKEN="ghp_..."
```

## Utilisation

### Repo public
```bash
python main.py --repo https://github.com/org/repo
```

### Repo privé
```bash
python main.py --repo https://github.com/org/private-repo \
               --github-token ghp_votre_token
```

### Options avancées
```bash
python main.py \
  --repo https://github.com/org/repo \
  --branch develop \
  --max-chunks 30 \       # Limite pour tester (sans limite = tout analyser)
  --concurrency 3 \       # Appels API parallèles
  --output ./mon_rapport.html
```

## Architecture du pipeline

```
GitHub Repo
    │
    ▼
1. RepoDownloader     → Clone avec git (shallow, depth=1)
    │
    ▼
2. ASTChunker         → Parse avec tree-sitter
   ├── Détecte le langage
   ├── Extrait classes/méthodes/fonctions
   ├── Calcule la priorité (Auth > Repository > Controller > ...)
   └── Détecte la feature (auth, payment, user, ...)
    │
    ▼
3. ContextBuilder     → 1 appel Opus : architecture globale
   ├── Structure des packages
   ├── Dépendances (pom.xml/build.gradle)
   ├── Spring Security config
   ├── Endpoints HTTP
   └── application.yml (secrets masqués)
    │
    ▼
4. OpusAnalyzer       → N appels parallèles (1 par chunk)
   ├── Injecte le contexte global dans chaque prompt
   ├── Retry automatique (RateLimit, erreurs réseau)
   └── Parse la réponse JSON structurée
    │
    ▼
5. Cross-feature      → 1 appel Opus : failles transversales
    │
    ▼
6. ReportGenerator    → Rapport HTML standalone + JSON brut
```

## Sorties

- **rapport_<repo>_<date>.html** : rapport navigable avec toutes les failles
- **rapport_<repo>_<date>.json** : données brutes pour intégration CI/CD

## Estimation des coûts

| Projet | Fichiers | Coût estimé |
|--------|----------|-------------|
| Petit  | ~30      | ~$1-2       |
| Moyen  | ~100     | ~$4-8       |
| Gros   | ~300+    | ~$15-25     |

*Basé sur les tarifs Claude Opus : $15/M tokens input, $75/M tokens output*

## Intégration CI/CD (GitHub Actions)

```yaml
name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: '3.11' }
      - run: pip install -r requirements.txt
      - run: |
          python main.py \
            --repo ${{ github.server_url }}/${{ github.repository }} \
            --branch ${{ github.ref_name }} \
            --max-chunks 50
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: reports/*.html
```
