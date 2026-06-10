# Architecture — Fractum

## Résumé

Fractum est un CLI Python à architecture **pipeline en couches** : la couche CLI orchestre les opérations, délègue le chiffrement à `crypto/`, le partage des secrets à `shares/`, et s'appuie sur `utils/` pour l'aléatoire et l'intégrité. Il n'y a pas de serveur, pas de base de données, pas d'état persistant entre les invocations.

---

## Flux `encrypt`

```
Utilisateur
    │  fractum encrypt <fichier> -t K -n N -l <label>
    ▼
commands.encrypt()
    ├─ valide paramètres Shamir (2 ≤ K ≤ N ≤ 255)
    ├─ génère clé AES-256 via os.urandom(32)          [integrity.py]
    ├─ FileEncryptor(key).encrypt_file(input, output)  [encryption.py]
    │       ├─ construit metadata_bytes (JSON, sans hash plaintext)
    │       ├─ AES.new(key, MODE_GCM)
    │       ├─ cipher.update(metadata_bytes)  ← AAD
    │       ├─ encrypt_and_digest(data) → ciphertext + tag
    │       └─ écrit : [4B len_meta][meta][16B nonce][16B tag][ciphertext]
    ├─ ShareManager(K, N).generate_shares(key, label)  [manager.py]
    │       └─ Shamir.split sur deux moitiés de 16 o (GF(2¹²⁸))
    ├─ écrit share_*.txt dans /tmp sécurisé             [manager.save_share]
    ├─ ShareArchiver.create_share_archive() par porteur [archiver.py]
    │       └─ ZIP(share_i.txt + fichier.enc)
    ├─ SecureMemory.secure_clear(key_bytearray)         [memory.py]
    └─ supprime share_*.txt temporaires
```

## Flux `decrypt`

```
Utilisateur
    │  fractum decrypt <fichier.enc> -s <dossier_parts>
    ▼
commands.decrypt()
    ├─ détecte archives ZIP → extrait dans répertoire temporaire (finally: cleanup)
    ├─ ShareManager.load_shares(fichiers)               [manager.py]
    │       ├─ valide champs JSON (index, threshold, total_shares ranges N6/N7)
    │       ├─ vérifie hash intégrité de chaque part (L5)
    │       └─ retourne [(index, bytes), ...] + ShareMetadata
    ├─ match par share_set_id (chemin principal) ou label (fallback)
    ├─ ShareManager(K, N).combine_shares(parts)
    │       └─ Shamir.combine sur deux moitiés → clé AES-256
    ├─ FileEncryptor(key).decrypt_file(input, output)   [encryption.py]
    │       ├─ lit metadata + valide format_version (M5)
    │       ├─ cipher.update(metadata_bytes) si format_version ≥ 2 (C2)
    │       └─ decrypt_and_verify(ciphertext, tag)
    ├─ SecureMemory.secure_clear(key_bytearray)
    └─ vérifie que le fichier de sortie n'écrase pas un existant (N4)
```

---

## Format du fichier `.enc`

```
Offset    Taille   Contenu
------    ------   -------
0         4 o      Longueur du bloc métadonnées (big-endian, max 64 Kio)
4         N o      Métadonnées JSON en clair (AAD GCM) :
                     { "format_version": "2", "version": "1.3.0",
                       "timestamp": <unix>, "share_set_id": <uuid>, ... }
4+N       16 o     Nonce GCM (aléatoire)
4+N+16    16 o     Tag d'authentification GCM
4+N+32    M o      Ciphertext (= plaintext chiffré)
```

> Les métadonnées sont en clair mais cryptographiquement liées au ciphertext via l'AAD GCM — toute modification invalide le tag.

## Format d'un fichier de part (`share_*.txt`)

```json
{
  "version": "1.3.0",
  "label": "mon_secret",
  "threshold": 3,
  "total_shares": 5,
  "share_index": 2,
  "share_key": "<base64 32 octets>",
  "hash": "<sha256(share_data)>",
  "share_set_id": "<uuid>",
  "tool_integrity": { ... }
}
```

Avec `--minimal-metadata` : le `label` est remplacé par `sha256(label)[:32]` et `tool_integrity`/`python_version` sont omis.

---

## Modules — responsabilités

### `src/config.py`
Constantes globales : `VERSION`, `FORMAT_VERSION` (version du format on-disk, découplée de l'app), `REQUIRED_PYTHON_VERSION`.

### `src/crypto/encryption.py` — `FileEncryptor`
- `encrypt_file(input, output, extra_metadata)` : chiffre avec AES-256-GCM, metadata en AAD.
- `decrypt_file(input, output)` : déchiffre, vérifie le tag GCM, rétrocompat format v1.
- `_read_metadata_raw()` : lecture bornée (max 64 Kio), remonte les erreurs proprement.

### `src/crypto/memory.py` — `SecureMemory`
- `secure_clear(bytearray)` : zéroïse la clé en place dans un `bytearray` mutable.
- Limite documentée : Python ne garantit pas l'absence de copies internes par l'interpréteur.

### `src/shares/manager.py` — `ShareManager`
- `generate_shares(secret, label)` : découpe la clé 32 o en deux instances Shamir de 16 o sur GF(2¹²⁸).
- `combine_shares(parts)` : reconstruit la clé depuis K parts minimum.
- `load_shares(files)` : charge et valide les fichiers de parts (N6/N7/L5).
- `save_share(share, label)` : sérialise une part en JSON.

### `src/shares/archiver.py` — `ShareArchiver`
- `create_share_archive(share_file, enc_file, label, index)` : crée une archive ZIP `label_share_N.zip` contenant le fichier de part et le `.enc`.

### `src/shares/metadata.py` — `ShareMetadata`
- Dataclass de métadonnées d'une part : validation des champs à la construction.

### `src/utils/integrity.py`
- `get_enhanced_random_bytes(n)` : alias de `os.urandom(n)` (mixage maison supprimé — L6).
- `calculate_tool_integrity()` : hash SHA-256 des fichiers sources pour détecter une altération de l'outil.

### `src/cli/core.py`
- Point d'entrée Click (`cli`). Route vers `encrypt`, `decrypt`, ou `interactive_mode`.

### `src/cli/commands.py`
- Implémentation des commandes `encrypt` et `decrypt` : validation des paramètres, orchestration des couches, gestion des erreurs, nettoyage des artefacts temporaires.

### `src/cli/interactive.py`
- Mode interactif guidé (menus) pour les utilisateurs qui ne veulent pas mémoriser les flags CLI.

---

## Décisions de conception notables

| Décision | Justification |
|----------|---------------|
| Shamir sur 2×16 o au lieu de 32 o direct | Limite de GF(2¹²⁸) dans PyCryptodome (max 16 o par instance) |
| Pas de hash du plaintext dans les métadonnées | GCM garantit déjà l'intégrité ; un hash en clair permettrait la confirmation du secret sous le seuil (C1) |
| `FORMAT_VERSION` séparé de `VERSION` | Un upgrade de l'app ne doit pas rendre les vieux fichiers illisibles (M5) |
| `.enc` inclus dans chaque archive de part | Chaque porteur est autonome pour la reconstruction |
| `bytearray` mutable pour la clé | Permet l'effacement en place (M4) |
| `os.urandom()` direct sans mixage | Recommandation OWASP/Latacora : pas de RNG userspace maison (L6) |
