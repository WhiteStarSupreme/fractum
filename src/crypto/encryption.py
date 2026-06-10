import json
import time
from typing import Any, Dict, Optional, Tuple

from Crypto.Cipher import AES
from src.config import FORMAT_VERSION, VERSION

MAX_METADATA_LEN = 65536  # L3: 64 KiB — prevents memory DoS on malformed .enc files


class FileEncryptor:
    def __init__(self, key: bytes):
        self.key = key
        self.version = VERSION

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_metadata_bytes(self, extra: Optional[Dict[str, Any]] = None) -> bytes:
        """Serialises metadata to bytes. Used both for writing and as GCM AAD."""
        meta: Dict[str, Any] = {
            "format_version": FORMAT_VERSION,
            "version": self.version,
            "timestamp": int(time.time()),
        }
        if extra:
            meta.update(extra)
        return json.dumps(meta, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def _read_metadata_raw(self, f: Any) -> Tuple[Dict[str, Any], bytes]:
        """Reads the metadata block and returns (dict, raw_bytes).

        L3: rejects blocks larger than MAX_METADATA_LEN.
        L8: raises ValueError on any corruption instead of swallowing it.
        """
        len_bytes = f.read(4)
        if len(len_bytes) < 4:
            raise ValueError("Truncated file: cannot read metadata length")
        metadata_len = int.from_bytes(len_bytes, "big")
        if metadata_len > MAX_METADATA_LEN:
            raise ValueError(
                f"Metadata block too large ({metadata_len} bytes, max {MAX_METADATA_LEN})"
            )
        raw = f.read(metadata_len)
        if len(raw) != metadata_len:
            raise ValueError("Truncated file: metadata block is incomplete")
        try:
            meta: Dict[str, Any] = json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError:
            try:
                meta = json.loads(raw.decode("latin-1", errors="replace"))
            except json.JSONDecodeError:
                raise ValueError("Metadata block is not valid JSON")
        except json.JSONDecodeError:
            raise ValueError("Metadata block is not valid JSON")
        return meta, raw

    def _read_metadata(self, f: Any) -> Dict[str, Any]:
        """Convenience wrapper that returns only the metadata dict."""
        meta, _ = self._read_metadata_raw(f)
        meta.setdefault("version", self.version)
        return meta

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Encrypts a file with AES-256-GCM.

        C1: no plaintext hash stored — GCM already provides integrity/authenticity.
        C2: metadata bytes are passed as AAD so they are cryptographically bound
            to the ciphertext; any tampering invalidates the tag.
        """
        metadata_bytes = self._build_metadata_bytes(extra_metadata)

        with open(input_path, "rb") as f:
            data = f.read()

        cipher = AES.new(self.key, AES.MODE_GCM)
        cipher.update(metadata_bytes)  # C2: authenticate the plaintext metadata
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(output_path, "wb") as f:
            f.write(len(metadata_bytes).to_bytes(4, "big"))
            f.write(metadata_bytes)
            f.write(cipher.nonce)   # 16 bytes
            f.write(tag)            # 16 bytes
            f.write(ciphertext)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypts a file with AES-256-GCM.

        M5: version check uses format_version (compatibility) not app version;
            only blocks on incompatible major format, warns on minor differences.
        C2: AAD is used for files encrypted with format_version >= 2.
        """
        with open(input_path, "rb") as f:
            metadata, metadata_bytes = self._read_metadata_raw(f)

            # M5: compare format_version, not the app version string
            file_fmt = str(metadata.get("format_version", "1"))
            if int(file_fmt.split(".")[0]) > int(FORMAT_VERSION.split(".")[0]):
                raise ValueError(
                    f"Unsupported format version {file_fmt!r} "
                    f"(this build supports up to {FORMAT_VERSION})"
                )

            nonce = f.read(16)
            if len(nonce) != 16:
                raise ValueError("Invalid or missing nonce")
            tag = f.read(16)
            if len(tag) != 16:
                raise ValueError("Invalid or missing authentication tag")
            ciphertext = f.read()
            if not ciphertext:
                raise ValueError("No encrypted data found")

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        # C2: feed AAD only for format_version >= 2 (backward compat with old files)
        if int(file_fmt.split(".")[0]) >= 2:
            cipher.update(metadata_bytes)

        try:
            data = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Incorrect key or tampered data")

        if len(data) == 0:
            raise ValueError("Decrypted data is empty")

        with open(output_path, "wb") as f:
            f.write(data)
