# -*- coding: utf-8 -*-

"""
CLI test suite for Fractum.

Covers the command-line interface layer (src/cli/), which was previously
untested:
  - the top-level ``cli`` group (--version, help, interactive dispatch)
  - the ``encrypt`` command (happy path, verbose, error handling, reuse)
  - the ``decrypt`` command (directory-based shares and manual entry)
  - the ``collect_manual_shares`` helper (Base64/Hex parsing, validation)

These are integration-style tests driven through Click's CliRunner so the
real encryption / Shamir / archiving code runs end to end.
"""

import base64
import json
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from src.cli.commands import collect_manual_shares, decrypt, encrypt
from src.cli.core import cli
from src.config import VERSION

SECRET_TEXT = b"The quick brown fox jumps over the lazy dog. 1234567890!"


def _read_share_values(shares_dir: Path):
    """Extract (index, base64_value) pairs from the generated share archives."""
    values = []
    for zip_path in sorted(shares_dir.glob("share_*.zip")):
        with zipfile.ZipFile(zip_path) as zf:
            share_name = next(
                n for n in zf.namelist() if Path(n).name.startswith("share_")
                and n.endswith(".txt")
            )
            info = json.loads(zf.read(share_name))
            values.append((info["share_index"], info["share_key"]))
    return values


class TestCliGroup(unittest.TestCase):
    """Tests for the top-level command group in src/cli/core.py."""

    def setUp(self):
        self.runner = CliRunner()

    def test_version_flag(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(VERSION, result.output)
        self.assertIn("fractum version", result.output)

    def test_no_args_shows_help(self):
        result = self.runner.invoke(cli, [])
        self.assertEqual(result.exit_code, 0)
        # Help text advertises both subcommands.
        self.assertIn("encrypt", result.output)
        self.assertIn("decrypt", result.output)

    def test_interactive_flag_dispatches(self):
        with mock.patch("src.cli.core.interactive_mode") as mocked:
            result = self.runner.invoke(cli, ["--interactive"])
        self.assertEqual(result.exit_code, 0)
        mocked.assert_called_once()

    def test_unknown_command_errors(self):
        result = self.runner.invoke(cli, ["frobnicate"])
        self.assertNotEqual(result.exit_code, 0)


class TestEncryptCommand(unittest.TestCase):
    """Tests for the encrypt command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_encrypt_produces_enc_and_archives(self):
        with self.runner.isolated_filesystem():
            Path("secret.txt").write_bytes(SECRET_TEXT)
            result = self.runner.invoke(
                encrypt, ["secret.txt", "-t", "2", "-n", "3", "-l", "mysecret"]
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertTrue(Path("secret.txt.enc").exists())
            archives = list(Path("shares").glob("share_*.zip"))
            self.assertEqual(len(archives), 3)
            # Temporary plaintext share files must be cleaned up.
            self.assertEqual(list(Path(".").glob("share_*.txt")), [])

    def test_encrypt_verbose_reports_steps(self):
        with self.runner.isolated_filesystem():
            Path("secret.txt").write_bytes(SECRET_TEXT)
            result = self.runner.invoke(
                encrypt,
                ["secret.txt", "-t", "2", "-n", "3", "-l", "my secret", "-v"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            # Spaces in the label are normalised to underscores.
            self.assertIn("my_secret", result.output)
            self.assertIn("Encrypted file", result.output)

    def test_encrypt_threshold_greater_than_shares_fails(self):
        with self.runner.isolated_filesystem():
            Path("secret.txt").write_bytes(SECRET_TEXT)
            result = self.runner.invoke(
                encrypt, ["secret.txt", "-t", "5", "-n", "3", "-l", "x"]
            )
            self.assertEqual(result.exit_code, 1)
            self.assertIn("Error", result.output)

    def test_encrypt_missing_required_option(self):
        with self.runner.isolated_filesystem():
            Path("secret.txt").write_bytes(SECRET_TEXT)
            # No --label provided.
            result = self.runner.invoke(
                encrypt, ["secret.txt", "-t", "2", "-n", "3"]
            )
            self.assertNotEqual(result.exit_code, 0)

    def test_encrypt_nonexistent_input_file(self):
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                encrypt, ["nope.txt", "-t", "2", "-n", "3", "-l", "x"]
            )
            self.assertNotEqual(result.exit_code, 0)

    def test_encrypt_minimal_metadata_hashes_label(self):
        """N10: --minimal-metadata must replace the label with its SHA-256 hash."""
        import hashlib, zipfile as _zf
        with self.runner.isolated_filesystem():
            Path("secret.txt").write_bytes(SECRET_TEXT)
            result = self.runner.invoke(
                encrypt,
                ["secret.txt", "-t", "2", "-n", "3", "-l", "wallet_seed", "-M"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            expected_hash = hashlib.sha256(b"wallet_seed").hexdigest()[:32]
            for zip_path in Path("shares").glob("share_*.zip"):
                with _zf.ZipFile(zip_path) as zf:
                    share_name = next(
                        n for n in zf.namelist()
                        if Path(n).name.startswith("share_") and n.endswith(".txt")
                    )
                    info = json.loads(zf.read(share_name))
                    # Label must be hashed, not plaintext
                    self.assertEqual(
                        info["label"], expected_hash,
                        "Label should be SHA-256 hash in minimal-metadata mode"
                    )
                    # Identifying fields must be absent
                    self.assertNotIn(
                        "tool_integrity", info,
                        "tool_integrity must be omitted in minimal-metadata mode"
                    )
                    self.assertNotIn(
                        "python_version", info,
                        "python_version must be omitted in minimal-metadata mode"
                    )

    def test_encrypt_minimal_metadata_round_trip(self):
        """N10: files encrypted with --minimal-metadata must still decrypt correctly."""
        with self.runner.isolated_filesystem():
            Path("secret.txt").write_bytes(SECRET_TEXT)
            result = self.runner.invoke(
                encrypt,
                ["secret.txt", "-t", "2", "-n", "3", "-l", "mywallet", "-M"],
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)

            Path("secret.txt").unlink()
            result = self.runner.invoke(decrypt, ["secret.txt.enc", "-s", "shares"])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual(Path("secret.txt").read_bytes(), SECRET_TEXT)


class TestDecryptCommand(unittest.TestCase):
    """Tests for the decrypt command (full round trips)."""

    def setUp(self):
        self.runner = CliRunner()

    def _encrypt(self, threshold=2, shares=3, label="round"):
        Path("secret.txt").write_bytes(SECRET_TEXT)
        result = self.runner.invoke(
            encrypt,
            ["secret.txt", "-t", str(threshold), "-n", str(shares), "-l", label],
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)

    def test_round_trip_with_shares_dir(self):
        with self.runner.isolated_filesystem():
            self._encrypt()
            # Remove the original so decryption recreates it.
            Path("secret.txt").unlink()
            result = self.runner.invoke(
                decrypt, ["secret.txt.enc", "-s", "shares"]
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual(Path("secret.txt").read_bytes(), SECRET_TEXT)

    def test_decrypt_requires_a_share_source(self):
        with self.runner.isolated_filesystem():
            self._encrypt()
            result = self.runner.invoke(decrypt, ["secret.txt.enc"])
            self.assertEqual(result.exit_code, 1)
            self.assertIn("Error", result.output)

    def test_round_trip_with_manual_shares(self):
        with self.runner.isolated_filesystem():
            self._encrypt(threshold=2, shares=3)
            values = _read_share_values(Path("shares"))
            self.assertGreaterEqual(len(values), 2)
            Path("secret.txt").unlink()

            (idx1, val1), (idx2, val2) = values[0], values[1]
            # threshold, total, idx1, val1, idx2, val2, confirm proceed
            stdin = "\n".join(
                ["2", "3", str(idx1), val1, str(idx2), val2, "y", ""]
            )
            result = self.runner.invoke(
                decrypt, ["secret.txt.enc", "-m"], input=stdin
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertEqual(Path("secret.txt").read_bytes(), SECRET_TEXT)


class TestCollectManualShares(unittest.TestCase):
    """Direct tests for collect_manual_shares input parsing."""

    def _run(self, stdin):
        """Run collect_manual_shares under a Click context fed by stdin."""
        runner = CliRunner()

        # collect_manual_shares uses click.prompt which reads from stdin; wrap
        # it in a throwaway command so CliRunner can supply the input stream.
        import click

        @click.command()
        def harness():
            shares, metadata = collect_manual_shares()
            click.echo(f"COUNT={len(shares)}")
            click.echo(f"THRESHOLD={metadata['threshold']}")

        return runner.invoke(harness, input=stdin)

    def test_base64_share_accepted(self):
        value = base64.b64encode(b"\x01" * 32).decode()
        stdin = "\n".join(["2", "3", "1", value, "2", value, "y", ""])
        result = self._run(stdin)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("COUNT=2", result.output)
        self.assertIn("THRESHOLD=2", result.output)

    def test_hex_share_accepted(self):
        value = ("ab" * 32)  # 32 bytes in hex
        stdin = "\n".join(["2", "2", "1", value, "2", value, "y", ""])
        result = self._run(stdin)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("COUNT=2", result.output)

    def test_invalid_threshold_rejected(self):
        # threshold 1 is below the minimum of 2.
        stdin = "\n".join(["1", "3"])
        result = self._run(stdin)
        self.assertNotEqual(result.exit_code, 0)

    def test_invalid_share_value_is_retried(self):
        good = base64.b64encode(b"\x02" * 32).decode()
        # First value is garbage -> re-prompted; index reused afterwards.
        stdin = "\n".join(
            ["2", "2", "1", "not-valid!!", "1", good, "2", good, "y", ""]
        )
        result = self._run(stdin)
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Invalid share key value", result.output)
        self.assertIn("COUNT=2", result.output)


if __name__ == "__main__":
    unittest.main()
