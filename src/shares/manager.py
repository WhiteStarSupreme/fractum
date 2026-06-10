import base64
import hashlib
import json
from typing import List, Tuple

from Crypto.Protocol.SecretSharing import Shamir
from src.config import VERSION
from src.shares.metadata import ShareMetadata


class ShareManager:
    def __init__(self, threshold: int, total_shares: int):
        if not isinstance(threshold, int) or threshold < 2:
            raise ValueError("Threshold must be a positive integer greater than 1")
        if not isinstance(total_shares, int) or total_shares < threshold:
            raise ValueError("Total shares must be greater than or equal to threshold")
        if total_shares > 255:
            raise ValueError("Total shares cannot exceed 255")

        self.threshold = threshold
        self.total_shares = total_shares
        self.version = VERSION

    def _prepare_secret(self, secret: bytes) -> bytes:
        """Pads the secret to exactly 32 bytes with zero bytes.

        L7: the secret passed here is always the randomly-generated AES key
        (32 bytes), so padding is never triggered in practice.  If this API
        were ever used with variable-length secrets the caller would need to
        store the original length separately because trailing zero bytes are
        indistinguishable from padding after reconstruction.
        """
        if len(secret) > 32:
            raise ValueError("Secret cannot exceed 32 bytes")
        if len(secret) == 0:
            raise ValueError("Secret cannot be empty")
        return secret.ljust(32, b"\0")

    def generate_shares(self, secret: bytes, label: str) -> List[Tuple[int, bytes]]:
        if not isinstance(secret, bytes):
            raise ValueError("Secret must be in bytes")
        if not isinstance(label, str) or not label:
            raise ValueError("Label must be a non-empty string")

        prepared_secret = self._prepare_secret(secret)
        secret_part1 = prepared_secret[:16]
        secret_part2 = prepared_secret[16:]

        shares1 = Shamir.split(self.threshold, self.total_shares, secret_part1, ssss=False)
        shares2 = Shamir.split(self.threshold, self.total_shares, secret_part2, ssss=False)

        combined_shares = []
        for i in range(self.total_shares):
            idx1, share1 = shares1[i]
            idx2, share2 = shares2[i]
            if idx1 != idx2:
                raise ValueError("Share index inconsistency")
            combined_shares.append((idx1, share1 + share2))

        return combined_shares

    def combine_shares(self, shares: List[Tuple[int, bytes]]) -> bytes:
        if not isinstance(shares, list):
            raise ValueError("Shares must be provided as a list")
        if len(shares) < self.threshold:
            raise ValueError(
                f"Insufficient number of shares: {len(shares)} < {self.threshold}"
            )

        indices = set(idx for idx, _ in shares)
        if len(indices) != len(shares):
            raise ValueError("Duplicate indices detected")

        try:
            shares1 = [(idx, share[:16]) for idx, share in shares]
            shares2 = [(idx, share[16:]) for idx, share in shares]
            secret_part1 = Shamir.combine(shares1[: self.threshold], ssss=False)
            secret_part2 = Shamir.combine(shares2[: self.threshold], ssss=False)
            return secret_part1 + secret_part2
        except Exception as e:
            raise ValueError(f"Error reconstructing secret: {str(e)}")

    def verify_shares(self, shares: List[Tuple[int, bytes]]) -> bool:
        if not isinstance(shares, list):
            return False
        if len(shares) < self.threshold:
            return False
        try:
            indices = set(idx for idx, _ in shares)
            if len(indices) != len(shares):
                return False
            Shamir.combine(shares[: self.threshold], ssss=False)
            return True
        except Exception:
            return False

    @staticmethod
    def load_shares(
        share_files: List[str],
    ) -> Tuple[List[Tuple[int, bytes]], ShareMetadata]:
        """Loads shares from files.

        N6: validates share_index, threshold, total_shares ranges.
        L5: verifies the per-share integrity hash when present; raises a clear
            error rather than letting a corrupted share produce a wrong key.
        N7: handles missing required fields explicitly instead of relying on
            generic except blocks to silently drop the file.
        """
        shares = []
        metadata = None

        for share_file in share_files:
            with open(share_file, "r") as f:
                share_info = json.load(f)

            # N7: explicit check for required fields
            for required in ("label", "share_index"):
                if required not in share_info:
                    raise ValueError(
                        f"Share file {share_file!r} is missing required field {required!r}"
                    )

            # N6: validate share_index range
            share_index = share_info["share_index"]
            if not isinstance(share_index, int) or not (1 <= share_index <= 255):
                raise ValueError(
                    f"Invalid share_index {share_index!r} in {share_file!r} "
                    "(must be an integer 1–255)"
                )

            # N6: validate threshold / total_shares if present
            threshold = share_info.get("threshold")
            total_shares = share_info.get("total_shares")
            if threshold is not None:
                if not isinstance(threshold, int) or not (2 <= threshold <= 255):
                    raise ValueError(
                        f"Invalid threshold {threshold!r} in {share_file!r}"
                    )
            if total_shares is not None:
                if not isinstance(total_shares, int) or not (1 <= total_shares <= 255):
                    raise ValueError(
                        f"Invalid total_shares {total_shares!r} in {share_file!r}"
                    )

            if metadata is None:
                metadata = ShareMetadata.from_share_info(share_info)
            else:
                current = ShareMetadata.from_share_info(share_info)
                if metadata.version != current.version:
                    raise ValueError(f"Incompatible version in {share_file!r}")
                if metadata.label != current.label:
                    raise ValueError(f"Incompatible label in {share_file!r}")
                if metadata.threshold != current.threshold:
                    raise ValueError(f"Incompatible threshold in {share_file!r}")
                if metadata.total_shares != current.total_shares:
                    raise ValueError(f"Incompatible total_shares in {share_file!r}")

            share_key = share_info.get("share_key", share_info.get("share"))
            if not share_key:
                raise ValueError(f"No share key found in {share_file!r}")

            share_data = base64.b64decode(share_key)

            # L5: verify integrity hash when present — surfaces corruption before
            # a wrong reconstructed key produces a confusing "Incorrect key" error
            stored_hash = share_info.get("hash") or share_info.get("share_integrity_hash")
            if stored_hash:
                computed = hashlib.sha256(share_data).hexdigest()
                if computed != stored_hash:
                    raise ValueError(
                        f"Integrity check failed for share {share_index} in "
                        f"{share_file!r}: share data is corrupted or tampered"
                    )

            shares.append((share_index, share_data))

        if metadata is None:
            raise ValueError("No valid share files found")

        return shares, metadata

    def save_share(self, share: Tuple[int, bytes], label: str) -> str:
        idx, share_data = share
        filename = f"share_{idx}.txt"

        meta = ShareMetadata(
            version=self.version,
            label=label,
            threshold=self.threshold,
            total_shares=self.total_shares,
        )
        meta.validate()

        share_info = {
            **meta.to_dict(),
            "share_index": idx,
            "share_key": base64.b64encode(share_data).decode(),
            "hash": hashlib.sha256(share_data).hexdigest(),
        }

        with open(filename, "w") as f:
            json.dump(share_info, f, indent=2)

        return filename
