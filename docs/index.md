# Documentation Fractum — Index

> Généré le 2026-06-10 par BMAD `bmad-document-project` (scan initial, niveau deep).
> Point d'entrée principal pour les agents IA travaillant sur ce projet.

---

## Vue d'ensemble du projet

- **Type :** Monolithe CLI Python
- **Langage principal :** Python 3.12.11
- **Architecture :** Pipeline en couches (CLI → Crypto + Shares + Utils)
- **Version :** 1.3.0 | Format on-disk : v2
- **Dépendances :** PyCryptodome 3.23.0, Click 8.1.8

**Résumé :** Fractum chiffre un fichier avec AES-256-GCM puis découpe la clé de chiffrement en `n` parts via Shamir's Secret Sharing (`k-parmi-n`). Outil de stockage à froid pour secrets à haute valeur (wallets crypto, clés PKI, credentials d'urgence). Fonctionne entièrement hors ligne.

---

## Documentation générée

- [Vue d'ensemble du projet](./project-overview.md) — résumé exécutif, stack, architecture en couches
- [Architecture](./architecture.md) — flux encrypt/decrypt, format `.enc`, format des parts, décisions de conception
- [Arbre des sources](./source-tree-analysis.md) — structure des répertoires annotée, points d'entrée
- [Guide de développement](./development-guide.md) — installation, tests, conventions, ajout de dépendances
- [Guide de déploiement](./deployment-guide.md) — Docker, CI/CD, scripts bootstrap, air-gap, TEE

---

## Documentation existante

- [README.md](../README.md) — documentation utilisateur officielle (Docker, usage, cas d'usage)
- [tests/README.md](../tests/README.md) — instructions d'exécution des tests
- [Audit sécurité](../../fractum.md) — audit complet 3 passes (passes 1-3, 2026-06-08/09/10)

---

## Démarrage rapide (développeur)

```bash
# Installation locale
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e .

# Tests via Docker (recommandé)
docker build -f tests/Dockerfile.test -t fractum-test .
docker run --rm fractum-test

# Usage CLI
fractum encrypt secret.txt -t 3 -n 5 -l mon_secret
fractum decrypt secret.txt.enc -s ./shares
```

---

## Référence rapide — modules

| Module | Responsabilité |
|--------|---------------|
| `src/cli/core.py` | Point d'entrée Click, routing |
| `src/cli/commands.py` | Orchestration encrypt/decrypt |
| `src/cli/interactive.py` | Mode interactif guidé |
| `src/crypto/encryption.py` | AES-256-GCM, format .enc |
| `src/crypto/memory.py` | Effacement mémoire de la clé |
| `src/shares/manager.py` | Génération/reconstruction Shamir |
| `src/shares/archiver.py` | Création des ZIP de parts |
| `src/shares/metadata.py` | Dataclass + validation des parts |
| `src/utils/integrity.py` | `os.urandom()`, hash d'intégrité outil |
| `src/config.py` | VERSION, FORMAT_VERSION, REQUIRED_PYTHON_VERSION |

---

## Points d'attention pour les agents IA

- **Contrainte Python stricte :** `==3.12.11` — ne pas suggérer de mise à jour de version sans vérifier `src/config.py`
- **Pas de hash plaintext :** GCM garantit l'intégrité — ne jamais rajouter un hash du plaintext dans les métadonnées
- **Clés en `bytearray`** — toujours manipuler les clés en `bytearray` mutable, jamais en `bytes` immuables
- **FORMAT_VERSION** — toute modification du format on-disk doit incrémenter `FORMAT_VERSION`, pas `VERSION`
- **Dépendances offline** — tout ajout de dépendance doit être bundlé dans `packages/` avec son checksum
- **Tests Docker** — les tests s'exécutent en environnement Docker isolé, pas directement sur le host
- **Audit sécurité** — lire `../../fractum.md` avant tout changement dans `src/crypto/` ou `src/shares/`
