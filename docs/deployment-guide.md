# Guide de déploiement — Fractum

## Mode Docker (recommandé)

L'usage Docker est recommandé car le flag `--network=none` garantit qu'aucune exfiltration réseau n'est possible pendant l'opération.

### Build de l'image

```bash
docker build -t fractum .
```

L'image base est épinglée par digest SHA-256 dans le `Dockerfile` :
```dockerfile
FROM python:3.12.11-slim@sha256:<digest>
```

### Chiffrement via Docker

```bash
docker run --rm \
  --network=none \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/shares:/app/shares" \
  fractum encrypt /data/secret.txt -t 3 -n 5 -l mon_secret
```

### Déchiffrement via Docker

```bash
docker run --rm \
  --network=none \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/shares:/app/shares" \
  fractum decrypt /data/secret.txt.enc -s /app/shares
```

### Sécurité de l'image Docker

| Mesure | Détail |
|--------|--------|
| Utilisateur non-root | `fractumuser` (UID non-root) |
| Permissions des répertoires | `chmod 750` sur `/data` et `/app/shares` |
| Image de base épinglée | `python:3.12.11-slim@sha256:...` (digest SHA-256) |
| Réseau isolable | `--network=none` recommandé en production |

## Pipeline CI/CD (GitHub Actions)

Le pipeline `.github/workflows/release.yml` gère les releases :

1. **Build** — package l'outil
2. **Signature GPG** — signe les artefacts avec la clé GPG de release
3. **Checksums SHA-256** — génère les checksums des artefacts
4. **Publication** — publie sur GitHub Releases

Les actions GitHub sont épinglées par digest SHA-256 (H1 corrigé) :
```yaml
uses: actions/checkout@<sha>       # v4.1.1
uses: softprops/action-gh-release@<sha>  # v2.2.2
```

## Scripts d'installation (utilisateurs finaux)

| Script | Plateforme | Méthode |
|--------|-----------|---------|
| `bootstrap-linux.sh` | Linux | pyenv + venv |
| `bootstrap-macos.sh` | macOS | pyenv + venv |
| `bootstrap-windows.ps1` | Windows | pyenv-win + venv |

> Les scripts téléchargent pyenv et vérifient le hash avant exécution (M3 corrigé).

## Vérification d'une release

```bash
# Importer la clé GPG publique de release
gpg --import fractum-public.asc

# Vérifier la signature d'un artefact
gpg --verify fractum-v1.3.0.tar.gz.sig fractum-v1.3.0.tar.gz

# Vérifier les checksums SHA-256
sha256sum -c fractum-v1.3.0.sha256
```

## Déploiement dans un environnement air-gapped

1. Télécharger l'archive de release et sa signature GPG sur une machine connectée
2. Vérifier la signature GPG
3. Transférer l'archive sur la machine air-gappée (USB, CD-ROM...)
4. Installer avec `pip install -e .` (les `.whl` bundlés dans `packages/` éliminent le besoin de réseau)
5. Utiliser avec `--network=none` si Docker est disponible

## Considérations pour usage TEE (Trusted Execution Environment)

Fractum peut être exécuté dans un TEE (ex. Enclaver.io) pour des garanties de sécurité supplémentaires :
- L'image Docker est compatible avec les outils d'enclavement
- Le flag `--network=none` est déjà dans les prérequis recommandés
- Voir : https://github.com/enclaver-io/enclaver
