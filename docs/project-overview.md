# Vue d'ensemble — Fractum

## Résumé exécutif

Fractum est un outil CLI Python de **stockage à froid sécurisé** de secrets à haute valeur et longue durée de vie. Il combine deux primitives cryptographiques éprouvées :

1. **AES-256-GCM** — chiffre le fichier secret avec une clé aléatoire de 32 octets.
2. **Shamir's Secret Sharing (SSS)** — découpe cette clé en `n` parts dont `k` suffisent à la reconstruire (`k-parmi-n`).

Chaque porteur reçoit une archive ZIP contenant sa part et le fichier chiffré. La reconstruction du secret est impossible avec moins de `k` parts.

**Cas d'usage typiques :** seed phrases de wallets crypto, clés maîtres PKI, mots de passe admin d'urgence, exports de gestionnaire de mots de passe, documents juridiques/financiers.

## Stack technique

| Catégorie | Technologie | Version |
|-----------|-------------|---------|
| Langage | Python | 3.12.11 (requis exactement) |
| Chiffrement | PyCryptodome | 3.23.0 |
| CLI | Click | 8.1.8 |
| Algorithme crypto | AES-256-GCM + Shamir SSS | — |
| Containerisation | Docker | image `python:3.12.11-slim` |

## Classification du dépôt

- **Type :** Monolithe CLI
- **Langage principal :** Python
- **Format de distribution :** Releases GitHub signées GPG, image Docker
- **Compatibilité :** Linux, macOS, Windows

## Architecture en couches

```
fractum CLI (Click)
    └── src/cli/
           ├── commands.py   ← commandes encrypt / decrypt (orchestration principale)
           ├── interactive.py← mode interactif guidé
           └── core.py       ← point d'entrée Click, routing

    src/crypto/
           ├── encryption.py ← FileEncryptor (AES-256-GCM, format .enc)
           └── memory.py     ← SecureMemory (effacement clé en mémoire)

    src/shares/
           ├── manager.py    ← ShareManager (génération/reconstruction Shamir)
           ├── archiver.py   ← ShareArchiver (création des ZIP de parts)
           └── metadata.py   ← ShareMetadata (modèle de données d'une part)

    src/utils/
           └── integrity.py  ← hash d'intégrité de l'outil, os.urandom()

    src/config.py             ← VERSION, FORMAT_VERSION, REQUIRED_PYTHON_VERSION
```

## Propriétés de sécurité garanties

| Propriété | Mécanisme |
|-----------|-----------|
| Confidentialité du secret | AES-256-GCM (clé 256 bits aléatoire) |
| Intégrité/authenticité du fichier | Tag GCM (128 bits) |
| Zéro-knowledge sous le seuil | Shamir SSS sur GF(2¹²⁸) |
| Authentification des métadonnées | AAD GCM (`cipher.update(metadata_bytes)`) |
| Rétrocompatibilité des formats | `FORMAT_VERSION` découplé de la version applicative |
| Effacement mémoire de la clé | `bytearray` mutable zéroïsé après usage |

## Liens

- README : [../README.md](../README.md)
- Audit sécurité complet : [../../fractum.md](../../fractum.md)
- Documentation officielle : https://fractum.katvio.com/
