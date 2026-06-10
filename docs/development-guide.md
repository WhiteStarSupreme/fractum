# Guide de développement — Fractum

## Prérequis

| Outil | Version requise | Notes |
|-------|----------------|-------|
| Python | **exactement 3.12.11** | Vérifié à l'install par `setup.py` |
| Docker | 20+ | Recommandé pour les tests |
| Git | — | — |

> ⚠️ La version Python est vérifiée en dur (`==3.12.11`). Un autre patch Python fera échouer `setup.py`.

## Installation (développement local)

```bash
# 1. Cloner le dépôt
git clone <repo-url>
cd fractum

# 2. Créer un venv avec Python 3.12.11
python3.12 -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate

# 3. Installer les dépendances (vérifie les checksums des .whl bundlés)
pip install -e .
```

> `setup.py` vérifie automatiquement `packages/CHECKSUMS.sha256` avant d'installer les `.whl`. Ne jamais remplacer un `.whl` sans mettre à jour le fichier de checksums.

## Usage CLI

```bash
# Chiffrer un fichier avec un schéma 3-parmi-5
fractum encrypt secret.txt -t 3 -n 5 -l mon_secret

# Déchiffrer avec les parts dans un répertoire
fractum decrypt secret.txt.enc -s ./shares

# Mode interactif
fractum -i

# Avec métadonnées minimales (OpSec)
fractum encrypt secret.txt -t 3 -n 5 -l mon_secret --minimal-metadata
```

## Tests

### Via Docker (recommandé — isolé, reproductible)

```bash
# Construction de l'image de test
docker build -f tests/Dockerfile.test -t fractum-test .

# Lancer tous les tests
docker run --rm fractum-test

# Lancer un fichier de tests spécifique
docker run --rm fractum-test python -m pytest tests/test_core_crypto.py -v
```

### Localement (pour développement rapide)

```bash
pip install pytest
pytest tests/ -v
```

### Fichiers de tests

| Fichier | Couverture |
|---------|-----------|
| `test_cli.py` | Commandes CLI (encrypt/decrypt, options) |
| `test_core_crypto.py` | AES-256-GCM, Shamir SSS — propriétés unitaires |
| `test_functional.py` | Flux complets encrypt → decrypt |
| `test_security.py` | Propriétés de sécurité (zéro-knowledge, intégrité) |
| `test_fuzzing.py` | Robustesse face à des artefacts corrompus/hostiles |
| `test_compatibility.py` | Rétrocompatibilité format v1/v2 |
| `test_metadata_integrity.py` | Intégrité des métadonnées et des parts |
| `test_performance.py` | Benchmarks |

## Conventions de code

- **Python 3.12.11 strict** — pas de f-strings ou syntax post-3.12 inutiles
- **Pas de dépendances réseau** — tout doit fonctionner hors ligne
- **Primitives cryptographiques** : uniquement `pycryptodome` et `os.urandom()` — jamais de construction maison
- **Clés en `bytearray`** — jamais en `bytes` immuables pour permettre l'effacement
- **Erreurs explicites** — toujours lever avec un message clair plutôt qu'avaler les exceptions

## Ajouter une dépendance

1. Télécharger le `.whl` dans `packages/`
2. Calculer son SHA-256 : `sha256sum mon_paquet.whl`
3. Ajouter la ligne dans `packages/CHECKSUMS.sha256`
4. Tester l'install : `pip install -e .`

## Structure d'un fichier de part (référence)

```json
{
  "version": "1.3.0",
  "label": "mon_secret",
  "threshold": 3,
  "total_shares": 5,
  "share_index": 1,
  "share_key": "<base64>",
  "hash": "<sha256(share_data)>",
  "share_set_id": "<uuid4>"
}
```

## Variables d'environnement

Aucune variable d'environnement n'est requise. Tout fonctionne par flags CLI.

## Modifier le format on-disk

1. Incrémenter `FORMAT_VERSION` dans `src/config.py`
2. Mettre à jour `FileEncryptor.decrypt_file()` pour gérer la rétrocompatibilité
3. Ajouter des tests dans `test_compatibility.py`
4. Documenter le changement dans `CHANGELOG` ou le commit message
