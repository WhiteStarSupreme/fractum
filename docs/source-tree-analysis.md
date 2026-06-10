# Arbre des sources — Fractum

```
fractum/
├── src/                          ← code source principal
│   ├── __init__.py               ← expose cli() comme point d'entrée console_scripts
│   ├── config.py                 ← VERSION, FORMAT_VERSION, REQUIRED_PYTHON_VERSION
│   ├── cli/                      ← couche interface utilisateur (Click)
│   │   ├── core.py               ← groupe Click racine, routing encrypt/decrypt/interactive
│   │   ├── commands.py           ← orchestration encrypt + decrypt (fichier principal)
│   │   └── interactive.py        ← mode interactif guidé par menus
│   ├── crypto/                   ← primitives cryptographiques
│   │   ├── encryption.py         ← FileEncryptor : AES-256-GCM, format .enc
│   │   └── memory.py             ← SecureMemory : effacement clé en bytearray
│   ├── shares/                   ← gestion des parts Shamir
│   │   ├── manager.py            ← ShareManager : génération, reconstruction, I/O
│   │   ├── archiver.py           ← ShareArchiver : ZIP(part + .enc)
│   │   └── metadata.py           ← ShareMetadata : dataclass + validation
│   └── utils/
│       └── integrity.py          ← os.urandom(), hash d'intégrité de l'outil
│
├── tests/                        ← suite de tests (Docker-only recommandé)
│   ├── Dockerfile.test           ← image de test isolée
│   ├── run_tests.py              ← runner de tests (gestion des dep sets)
│   ├── test_cli.py               ← tests des commandes CLI
│   ├── test_core_crypto.py       ← tests unitaires crypto (AES-GCM, Shamir)
│   ├── test_functional.py        ← tests end-to-end encrypt→decrypt
│   ├── test_security.py          ← tests de propriétés de sécurité
│   ├── test_fuzzing.py           ← fuzzing des entrées et artefacts
│   ├── test_compatibility.py     ← rétrocompatibilité format v1/v2
│   ├── test_metadata_integrity.py← intégrité des métadonnées et parts
│   ├── test_performance.py       ← benchmarks
│   └── README.md                 ← instructions d'exécution des tests
│
├── packages/                     ← dépendances bundlées (offline install)
│   ├── CHECKSUMS.sha256          ← hashes SHA-256 des .whl (vérifiés à l'install)
│   ├── click-8.1.8-py3-none-any.whl
│   └── pycryptodome-3.23.0-*.whl (Linux x86_64, macOS, Windows)
│
├── .github/
│   └── workflows/
│       └── release.yml           ← pipeline release : build, sign GPG, publish
│
├── Dockerfile                    ← image de distribution (utilisateur final)
├── setup.py                      ← installation + vérification checksums .whl
├── bootstrap-linux.sh            ← script d'installation Linux (pyenv)
├── bootstrap-macos.sh            ← script d'installation macOS
├── bootstrap-windows.ps1         ← script d'installation Windows
├── README.md                     ← documentation utilisateur principale
├── LICENSE
└── .gitignore
```

## Répertoires critiques

| Répertoire | Rôle |
|-----------|------|
| `src/crypto/` | Primitives cryptographiques — tout changement ici nécessite une revue sécurité |
| `src/shares/` | Logique Shamir et I/O des parts — cœur de la garantie zéro-knowledge |
| `src/cli/commands.py` | Orchestration principale — gère le cycle de vie complet des secrets |
| `tests/` | Suite complète ; à exécuter uniquement via Docker (voir [development-guide.md](./development-guide.md)) |
| `packages/` | Dépendances offline — ne jamais modifier sans mettre à jour `CHECKSUMS.sha256` |

## Points d'entrée

| Point d'entrée | Fichier | Description |
|---------------|---------|-------------|
| `fractum` (CLI) | `src/__init__.py` → `src/cli/core.py` | Commande principale |
| `fractum encrypt` | `src/cli/commands.py:encrypt()` | Chiffrement + génération des parts |
| `fractum decrypt` | `src/cli/commands.py:decrypt()` | Reconstruction + déchiffrement |
| `fractum -i` | `src/cli/interactive.py` | Mode interactif guidé |
| Docker | `Dockerfile` | Image de distribution avec utilisateur non-root |
