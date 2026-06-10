# Analyse de robustesse cryptographique — Fractum

> Calculé le 2026-06-10. Basé sur le commit `main` post-corrections (toutes les findings C1/C2/M4/M5/L1-L8 corrigées).

---

## 1. AES-256-GCM — marges de sécurité

### Espace des clés

| Paramètre | Valeur |
|-----------|--------|
| Taille de clé | 256 bits |
| Espace des clés | 2²⁵⁶ ≈ 1,16 × 10⁷⁷ |
| Brute-force à 10¹⁸ op/s (ASIC état de l'art) | **2²⁵⁶ / 10¹⁸ ≈ 10⁵⁸ années** |
| Résistance quantique (Grover) | Espace effectif réduit à 2¹²⁸ — toujours infaisable |
| Sécurité post-quantique | AES-256 est considéré résistant aux attaques quantiques connues |

**Conclusion :** aucune menace computationnelle prévisible sur la clé AES dans l'horizon de vie de Fractum.

### Tag d'authentification GCM

| Paramètre | Valeur |
|-----------|--------|
| Taille du tag | 128 bits |
| Probabilité de forge par tentative | ≤ 2⁻¹²⁸ ≈ 3 × 10⁻³⁹ |
| Probabilité de forge après 2³² messages | ≤ 2⁻⁹⁶ ≈ 10⁻²⁹ — toujours négligeable |

> Le tag GCM garantit à la fois l'intégrité et l'authenticité du ciphertext ET des métadonnées (AAD, correction C2). Toute modification d'un seul bit est détectée avec probabilité 1 − 2⁻¹²⁸.

### Espace des nonces (INFO-1 — réutilisation de clé avec `--existing-shares`)

La clé AES est réutilisée sur plusieurs fichiers dans ce mode. PyCryptodome génère un nonce de 128 bits aléatoire par chiffrement.

**Probabilité de collision de nonce après N fichiers (paradoxe des anniversaires) :**

```
P(collision) ≈ N² / 2¹²⁹
```

| N fichiers chiffrés avec la même clé | P(au moins une collision) |
|--------------------------------------|--------------------------|
| 1 000 | 1,5 × 10⁻³³ |
| 1 000 000 | 1,5 × 10⁻²⁷ |
| 1 milliard (10⁹) | 1,5 × 10⁻²¹ |
| 10¹⁵ (1 quadrillion) | 1,5 × 10⁻⁹ |
| **Seuil P = 10⁻⁶** | **N ≈ 8 × 10¹⁶ fichiers** |

**Conclusion INFO-1 :** avec des nonces de 128 bits, un utilisateur devrait chiffrer ~10¹⁷ fichiers distincts avec la même clé pour atteindre une probabilité de collision de 1 sur un million. En pratique, la réutilisation de clé dans `--existing-shares` est **négligeable** pour tout usage réaliste.

**Mitigation recommandée (non bloquante) :** dériver une sous-clé par fichier via HKDF :
```python
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
per_file_key = HKDF(master_key, 32, file_id.encode(), SHA256)
```
Cela éliminerait la contrainte théorique sans impact sur les performances.

---

## 2. Shamir's Secret Sharing — garantie zéro-knowledge

### Paramètres d'implémentation

| Paramètre | Valeur |
|-----------|--------|
| Corps fini | GF(2¹²⁸) (via PyCryptodome) |
| Taille du secret | 32 octets découpés en 2 × 16 o (limite GF(2¹²⁸)) |
| Schéma | k-parmi-n, 2 ≤ k ≤ n ≤ 255 |
| Type de sécurité | **Information-théorétique** (pas seulement computationnelle) |

### Preuve de la garantie zéro-knowledge

Avec k−1 parts, un adversaire détient k−1 points sur un polynôme de degré k−1 sur GF(2¹²⁸). Pour tout candidat de secret s ∈ GF(2¹²⁸), il existe **exactement un** polynôme de degré k−1 passant par ces k−1 points et évaluant à s en x=0. Donc toutes les valeurs de secret sont équiprobables — les k−1 parts ne révèlent **aucun bit** du secret.

```
∀ s ∈ GF(2¹²⁸), P(secret = s | k−1 parts) = 1 / 2¹²⁸
```

Cette garantie est **inconditionnelle** (valable même contre un adversaire avec une puissance de calcul infinie).

### Robustesse post-corrections C1

Avant la correction C1, le SHA-256 du plaintext était stocké en clair → un adversaire avec 1 part pouvait confirmer/invalider des candidats de secret (brute-force oracle). **Post-correction :** sans le hash, la seule façon de tester un candidat est de reconstruire la clé (nécessite k parts) puis de vérifier le tag GCM. Ci-dessous l'espace de brute-force réel par type de secret :

| Type de secret | Espace | Coût brute-force à 10⁶ essais/s |
|---------------|--------|----------------------------------|
| BIP-39 24 mots | 2²⁵⁶ (avec checksum) | **> 10⁶⁸ années** |
| BIP-39 12 mots | 2¹³² ≈ 5,4 × 10³⁹ | **> 10²⁶ années** |
| Passphrase 20 chars ASCII | ~95²⁰ ≈ 2¹³¹ | **> 10²⁵ années** |
| Clé privée EC 256 bits | 2²⁵⁶ | **> 10⁶⁸ années** |

> **Rappel :** ces attaques nécessitent d'abord d'obtenir k parts. La garantie Shamir rend la collecte des parts le seul vecteur d'attaque viable.

---

## 3. Résistance à la corruption des parts

### Détection de corruption (L5 corrigé)

Chaque part stocke `sha256(share_data)`. À la reconstruction :
- Part corrompue (1 bit modifié) : détectée avec probabilité 1 − 2⁻²⁵⁶ ≈ 1
- Part altérée par un attaquant actif : idem (SHA-256 sur 32 octets)
- Fausse part (données aléatoires) : détectée avant la tentative Shamir → erreur claire

Si une part corrompue passe la vérification SHA-256 (probabilité 2⁻²⁵⁶), la reconstruction Shamir produit une clé erronée → le tag GCM rejette la tentative de déchiffrement.

**Double filet de sécurité :** SHA-256 de la part + tag AES-GCM.

### Reconstruction avec parts invalides

| Scénario | Comportement |
|----------|-------------|
| Part corrompue (hash mismatch) | `ValueError: Integrity check failed for share X` (avant Shamir) |
| Part d'un autre set (share_set_id mismatch) | Rejetée au matching |
| Part avec index dupliqué | `ValueError: Duplicate indices detected` |
| Mauvais threshold/total déclarés | `ValueError` à la validation N6 |
| Reconstitution avec k parts fausses | Clé erronée → `ValueError: Incorrect key or tampered data` (GCM) |

---

## 4. Intégrité des métadonnées (C2 corrigé)

Les métadonnées (`format_version`, `version`, `timestamp`, `share_set_id`) sont liées cryptographiquement au ciphertext via l'AAD GCM :

```python
cipher.update(metadata_bytes)  # AAD
ciphertext, tag = cipher.encrypt_and_digest(data)
```

**Conséquence :** toute modification d'un octet des métadonnées (réécriture de `format_version`, altération du `timestamp`) invalide le tag GCM → détection certaine.

---

## 5. Calcul d'entropie de la clé AES

La clé AES est générée par `os.urandom(32)` :

```
H(clé) = 256 bits (entropie maximale — CSPRNG du noyau)
```

Sur Linux : `os.urandom()` utilise `getrandom()` syscall → alimenté par le pool d'entropie du noyau (CSPRNG ChaCha20 sur Linux ≥ 5.17). Aucune source d'entropie « maison » n'intervient (L6 corrigé).

---

## 6. Synthèse — matrice de menaces

| Menace | Faisabilité | Mitigation |
|--------|-------------|-----------|
| Brute-force AES-256 | **Impossible** (2²⁵⁶) | Clé aléatoire 256 bits |
| Forge du tag GCM | **Impossible** (2⁻¹²⁸/tentative) | AES-256-GCM |
| Confirmation du secret < k parts | **Impossible** (C1 corrigé) | Pas de hash plaintext |
| Altération des métadonnées | **Impossible** (C2 corrigé) | AAD GCM |
| Collision de nonce (`--existing-shares`) | **Négligeable** (< 10⁻²⁷ pour < 10⁶ fichiers) | INFO-1 documenté |
| Corruption silencieuse d'une part | **Impossible** (L5 corrigé) | SHA-256 + GCM |
| Attaque quantique (Grover sur AES) | **Infaisable** (2¹²⁸ résiduel) | AES-256 survit à Grover |
| Collecte forcée de k parts | Hors périmètre crypto | OpSec, distribution géographique |

---

## 7. Recommandations ouvertes

| ID | Priorité | Description |
|----|----------|-------------|
| INFO-1 | Faible | Dériver une sous-clé par fichier (HKDF) en mode `--existing-shares` pour éliminer théoriquement la contrainte nonce |
| — | Faible | Documenter la limite de réutilisation de clé dans le README |
| — | Veille | Surveiller NIST Post-Quantum Cryptography pour AES-256 (statut actuel : résistant) |
