"""
Configuration globale du scanner de sécurité AST
"""

# Priorité des fichiers par pattern (plus élevé = analysé en premier)
FILE_PRIORITY = {
    # Couche sécurité / auth — CRITIQUE
    "Security":     10,
    "Auth":         10,
    "Jwt":          10,
    "Token":         9,
    "Filter":        9,
    "Interceptor":   9,

    # Couche accès données — HAUTE
    "Repository":    8,
    "Dao":           8,
    "Query":         8,

    # Couche métier — MOYENNE-HAUTE
    "Controller":    7,
    "Service":       7,
    "Handler":       7,

    # Couche config — MOYENNE
    "Config":        6,
    "Configuration": 6,
    "Properties":    5,

    # Couche modèle — BASSE
    "Entity":        3,
    "Model":         3,
    "Dto":           2,
    "Util":          2,
    "Helper":        2,

    # Tests — ignorés par défaut
    "Test":          0,
    "Spec":          0,
}

# Extensions supportées et leur langage tree-sitter
SUPPORTED_EXTENSIONS = {
    ".java":   "java",
    ".py":     "python",
    ".js":     "javascript",
    ".ts":     "javascript",
    ".jsx":    "javascript",
    ".tsx":    "javascript",
}

# Fichiers de config à analyser séparément (pas d'AST)
CONFIG_FILES = [
    "application.yml",
    "application.yaml",
    "application.properties",
    "application-prod.yml",
    "application-production.yml",
    "pom.xml",
    "build.gradle",
    "Dockerfile",
    "docker-compose.yml",
    ".env",
    ".env.prod",
]

# Dossiers à ignorer totalement
IGNORED_DIRS = {
    ".git", "target", "build", "dist", "node_modules",
    "__pycache__", ".mvn", ".gradle", "out", "bin",
    ".idea", ".vscode", "coverage", "test-results",
}

# Nœuds AST à extraire par langage
AST_NODE_TYPES = {
    "java": [
        "class_declaration",
        "interface_declaration",
        "method_declaration",
        "constructor_declaration",
        "enum_declaration",
    ],
    "python": [
        "class_definition",
        "function_definition",
        "async_function_def",
    ],
    "javascript": [
        "class_declaration",
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "export_statement",
    ],
}

# Taille max d'un chunk en caractères (≈ 30k tokens)
MAX_CHUNK_CHARS = 120_000

# Nombre max d'appels API en parallèle
MAX_CONCURRENCY = 4

# Modèle Anthropic à utiliser
ANTHROPIC_MODEL = "claude-opus-4-5"

# Prompt système de sécurité
SECURITY_SYSTEM_PROMPT = """Tu es un expert en cybersécurité spécialisé dans l'audit de code source d'applications d'entreprise.

Tu analyses du code Java Spring / Python / JavaScript et identifies les vulnérabilités de sécurité.

Catégories à détecter :
- OWASP Top 10 : injection SQL, XSS, CSRF, IDOR, SSRF, XXE, désérialisation non sécurisée
- Secrets hardcodés : API keys, passwords, tokens, credentials
- Mauvaise gestion de l'authentification et des sessions
- Failles de cryptographie : algorithmes faibles, IV statiques, clés en dur
- Contrôle d'accès insuffisant : endpoints non protégés, escalade de privilèges
- Injection de commandes OS
- Path traversal
- Dépendances vulnérables
- Mauvaise configuration Spring Security
- Exposition d'informations sensibles dans les logs ou les erreurs
- Race conditions et problèmes de concurrence
- Failles spécifiques JPA/Hibernate : requêtes natives non paramétrées, lazy loading abusif

Pour CHAQUE vulnérabilité trouvée, fournis :
1. Sa localisation précise (méthode, ligne approximative)
2. Une description claire du risque
3. Un exemple d'exploitation
4. La remédiation avec code corrigé

Réponds UNIQUEMENT en JSON valide, sans markdown, sans commentaires.
"""

SECURITY_JSON_SCHEMA = """
Format de réponse JSON obligatoire :
{
  "file": "chemin du fichier analysé",
  "language": "java|python|javascript",
  "security_score": 7.5,
  "chunk_summary": "description de ce que fait ce chunk de code",
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "SQL_INJECTION|XSS|HARDCODED_SECRET|COMMAND_INJECTION|IDOR|SSRF|WEAK_CRYPTO|MISSING_AUTH|PATH_TRAVERSAL|XXE|INSECURE_DESERIALIZATION|SENSITIVE_LOG|RACE_CONDITION|MISCONFIGURATION|VULNERABLE_DEPENDENCY|OTHER",
      "cwe": "CWE-89",
      "location": "nom de la méthode ou classe",
      "line_hint": 42,
      "description": "Description précise et technique de la faille",
      "vulnerable_code": "extrait du code vulnérable",
      "attack_scenario": "Comment un attaquant exploiterait cette faille",
      "remediation": "Explication de la correction",
      "fixed_code": "Code corrigé"
    }
  ],
  "observations": "Remarques générales sur la qualité sécurité de ce code"
}
"""
