import base64
import binascii
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import click

from src.crypto.encryption import FileEncryptor
from src.crypto.memory import SecureMemory
from src.shares.archiver import ShareArchiver
from src.shares.manager import ShareManager
from src.utils.integrity import calculate_tool_integrity, get_enhanced_random_bytes

# L4: reject ZIP archives whose total uncompressed size exceeds this limit
MAX_ZIP_UNCOMPRESSED = 100 * 1024 * 1024  # 100 MiB


@click.command()
@click.argument(
    "input_file", type=click.Path(exists=True, dir_okay=False, file_okay=True)
)
@click.option("--threshold", "-t", required=True, type=int, help="Minimum number of shares needed")
@click.option("--shares", "-n", required=True, type=int, help="Total number of shares to generate")
@click.option("--label", "-l", required=True, help="Label to identify shares")
@click.option(
    "--existing-shares",
    "-e",
    type=click.Path(exists=True, dir_okay=True, file_okay=False),
    help="Directory containing existing shares",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode")
@click.option(
    "--minimal-metadata",
    "-M",
    is_flag=True,
    help=(
        "N10: reduce identifying information in share files. "
        "The label is replaced by its SHA-256 hash and non-essential fields "
        "(tool_integrity, python_version) are omitted."
    ),
)
def encrypt(
    input_file: str,
    threshold: int,
    shares: int,
    label: str,
    existing_shares: str,
    verbose: bool,
    minimal_metadata: bool,
) -> None:
    """Encrypts a file and generates shares."""
    try:
        label = label.replace(" ", "_")
        if verbose:
            click.echo(f"Using label: {label}")

        if sys.version_info < (3, 8):
            raise ValueError("Python 3.8 or higher is required")

        shares_dir = Path("shares")
        if not shares_dir.exists():
            shares_dir.mkdir()
            if verbose:
                click.echo("Created shares directory")

        tool_integrity = calculate_tool_integrity()

        if existing_shares:
            existing_shares_path = Path(existing_shares).absolute()
            if verbose:
                click.echo(f"Looking for existing shares in: {existing_shares_path}")

            share_files: List[Path] = []
            for file_path in existing_shares_path.glob("*.*"):
                if not file_path.is_file():
                    continue
                try:
                    with open(file_path, "r") as f:
                        share_info = json.load(f)
                    if all(
                        key in share_info
                        for key in [
                            "share_index",
                            "share_key" if "share_key" in share_info else "share",
                            "label",
                            "threshold",
                            "total_shares",
                        ]
                    ):
                        share_files.append(file_path)
                except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                    continue

            if not share_files:
                if verbose:
                    click.echo("Searching for share files in alternative formats...")
                for file_pattern in ["share_*.txt", "*.share", "*.json"]:
                    for file_path in existing_shares_path.glob(file_pattern):
                        try:
                            with open(file_path, "r") as f:
                                share_info = json.load(f)
                            if all(
                                key in share_info
                                for key in [
                                    "share_index",
                                    "share_key" if "share_key" in share_info else "share",
                                    "label",
                                ]
                            ):
                                share_files.append(file_path)
                        except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                            continue

                if not share_files:
                    raise ValueError(
                        f"No valid share files found in: {existing_shares}"
                    )

            if verbose:
                click.echo(f"Found {len(share_files)} valid share files")

            # N7: use .get() instead of direct indexing
            with open(share_files[0], "r") as f:
                share_info = json.load(f)
            existing_label = share_info.get("label")
            if not existing_label:
                raise ValueError(f"Share file {share_files[0]} is missing 'label' field")

            click.echo(f"\nExisting shares found with label: {existing_label}")
            label = existing_label
            click.echo(f"Label used: {label}")

            threshold = share_info.get("threshold", 3)
            total_shares_val = share_info.get("total_shares", 5)
            click.echo(f"Existing shares parameters: threshold={threshold}, total_shares={total_shares_val}")

            share_files_str = [str(f) for f in share_files]
            shares_data, metadata = ShareManager.load_shares(share_files_str)

            if metadata.label != label:
                raise ValueError(
                    f"Share label mismatch: expected {label}, found {metadata.label}"
                )

            threshold = metadata.threshold
            shares = metadata.total_shares

            if verbose:
                click.echo(f"Using parameters: threshold={threshold}, total_shares={shares}")

            share_manager = ShareManager(threshold, shares)
            # M4: wrap in bytearray so SecureMemory.secure_clear can actually zero it
            key = bytearray(share_manager.combine_shares(shares_data))

            with open(share_files[0], "r") as f:
                share_info = json.load(f)
            share_set_id = share_info.get("share_set_id", None)

        else:
            # M4: generate key as bytearray from the start
            key = bytearray(get_enhanced_random_bytes(32))

            random_component = get_enhanced_random_bytes(16).hex()
            input_filename = Path(input_file).stem
            timestamp = str(time.time())
            share_set_id = hashlib.sha256(
                (label + input_filename + timestamp + random_component).encode()
            ).hexdigest()[:16]

            if verbose:
                click.echo(f"Generated share set ID: {share_set_id}")

            share_manager = ShareManager(threshold, shares)
            share_data = share_manager.generate_shares(bytes(key), label)

            archiver = ShareArchiver()

            # INFO-2: write temporary share files to a restricted-permission temp
            # directory instead of the CWD to reduce exposure via sync/backup tools
            share_temp_dir = tempfile.mkdtemp()
            os.chmod(share_temp_dir, 0o700)
            new_share_files: List[str] = []
            try:
                # N10: in minimal-metadata mode, hash the label and drop fields that
                # reveal the nature or scheme of the secret to a single share holder.
                stored_label = (
                    hashlib.sha256(label.encode()).hexdigest()[:32]
                    if minimal_metadata
                    else label
                )
                if minimal_metadata and verbose:
                    click.echo("Minimal-metadata mode: label hashed, tool_integrity omitted")

                for idx, share in share_data:
                    share_file_path = os.path.join(share_temp_dir, f"share_{idx}.txt")
                    share_entry: Dict[str, Any] = {
                        "share_index": idx,
                        "share_key": base64.b64encode(share).decode(),
                        "label": stored_label,
                        # L5: store hash so load_shares() can verify integrity
                        "hash": hashlib.sha256(share).hexdigest(),
                        "threshold": threshold,
                        "total_shares": shares,
                        "share_set_id": share_set_id,
                    }
                    if not minimal_metadata:
                        share_entry["tool_integrity"] = tool_integrity
                        share_entry["python_version"] = (
                            f"{sys.version_info.major}."
                            f"{sys.version_info.minor}."
                            f"{sys.version_info.micro}"
                        )
                    with open(share_file_path, "w") as f:
                        json.dump(share_entry, f, indent=2)
                    os.chmod(share_file_path, 0o600)
                    new_share_files.append(share_file_path)

                if verbose:
                    click.echo(f"Generated {shares} shares")

                # N3: route through FileEncryptor.encrypt_file() — single crypto path
                # N9: file is read once inside encrypt_file(), not twice
                # C1: no plaintext hash passed — removed from metadata
                output_file = f"{input_file}.enc"
                encryptor = FileEncryptor(bytes(key))
                encryptor.encrypt_file(
                    input_file,
                    output_file,
                    extra_metadata={"share_set_id": share_set_id},
                )

                if verbose:
                    click.echo(f"Encrypted file: {output_file}")

                for idx, share_file_path in enumerate(new_share_files, 1):
                    archive_path = archiver.create_share_archive(
                        share_file_path, output_file, idx, label
                    )
                    if verbose:
                        click.echo(f"Created archive: {Path(archive_path).absolute()}")
            finally:
                shutil.rmtree(share_temp_dir, ignore_errors=True)

            SecureMemory.secure_clear(key)
            return

        # existing-shares path: encrypt only (no new archives)
        output_file = f"{input_file}.enc"
        encryptor = FileEncryptor(bytes(key))
        encryptor.encrypt_file(
            input_file,
            output_file,
            extra_metadata={"share_set_id": share_set_id},
        )

        if verbose:
            click.echo(f"Encrypted file: {output_file}")

        SecureMemory.secure_clear(key)

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@click.command()
@click.argument(
    "input_file", type=click.Path(exists=True, dir_okay=False, file_okay=True)
)
@click.option(
    "--shares-dir",
    "-s",
    type=click.Path(exists=True, dir_okay=True, file_okay=False),
    help="Path to directory containing shares or ZIP archives",
)
@click.option(
    "--manual-shares",
    "-m",
    is_flag=True,
    help="Manually enter share values instead of using files",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose mode")
def decrypt(
    input_file: str, shares_dir: str, manual_shares: bool, verbose: bool
) -> None:
    """Decrypts a file using shares."""
    try:
        if manual_shares:
            if verbose:
                click.echo("Manual share entry mode activated")
            shares_data, metadata = collect_manual_shares()

            if not shares_data or len(shares_data) < 2:
                raise ValueError("Not enough valid shares provided (minimum 2).")

            share_manager = ShareManager(metadata["threshold"], metadata["total_shares"])
            # M4: bytearray so secure_clear actually zeros key material
            key = bytearray(share_manager.combine_shares(shares_data))

            # N4: never silently overwrite an existing file
            output_file = (
                input_file[:-4] if input_file.endswith(".enc") else input_file + ".dec"
            )
            if Path(output_file).exists():
                raise ValueError(
                    f"Output file already exists: {output_file}. "
                    "Remove it first or rename it."
                )

            encryptor = FileEncryptor(bytes(key))
            encryptor.decrypt_file(input_file, output_file)
            click.echo(f"File successfully decrypted: {Path(output_file).absolute()}")
            SecureMemory.secure_clear(key)
            return

        if not shares_dir:
            raise ValueError("Either --shares-dir or --manual-shares must be provided")

        shares_path = Path(shares_dir).absolute()
        if verbose:
            click.echo(f"Looking for shares in: {shares_path}")

        # Extract share_set_id from file metadata
        extracted_share_set_id = None
        with open(input_file, "rb") as f:
            _tmp_encryptor = FileEncryptor(SecureMemory.secure_bytes(32))
            file_metadata = _tmp_encryptor._read_metadata(f)
            extracted_share_set_id = file_metadata.get("share_set_id")
            if verbose:
                if extracted_share_set_id:
                    click.echo(f"Found share_set_id in file metadata")
                else:
                    click.echo("No share_set_id found in file metadata")

        shares_by_set_id: Dict[str, Dict[str, Any]] = {}
        shares_by_label: Dict[str, Dict[str, Any]] = {}

        share_files = []
        zip_files = list(shares_path.glob("*.zip"))
        if zip_files:
            share_files.extend(zip_files)
            if verbose:
                click.echo(f"Found {len(zip_files)} ZIP archives")

        for file_path in shares_path.glob("*.*"):
            if file_path.is_file() and file_path.suffix != ".zip":
                try:
                    with open(file_path, "r") as f:
                        share_info = json.load(f)
                    if all(
                        k in share_info
                        for k in [
                            "share_index",
                            "share_key" if "share_key" in share_info else "share",
                            "label",
                        ]
                    ):
                        share_files.append(file_path)
                except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                    continue

        if not share_files:
            all_files = [f for f in shares_path.glob("*") if f.is_file()]
            if not all_files:
                raise ValueError(f"No files found in directory {shares_path}")
            click.echo("No files match the expected share format in the directory.")
            return

        if verbose:
            click.echo(f"Processing {len(share_files)} share files/archives")

        # Process share files; track temp dirs separately so N2 cleanup is correct
        for share_file in share_files:
            temp_dir: Path | None = None

            if str(share_file).endswith(".zip"):
                temp_dir = Path(tempfile.mkdtemp(prefix="fractum_share_"))
                try:
                    # L4: guard against decompression bombs
                    with zipfile.ZipFile(share_file, "r") as zipf:
                        total_uncompressed = sum(
                            info.file_size for info in zipf.infolist()
                        )
                        if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
                            raise ValueError(
                                f"ZIP archive too large "
                                f"({total_uncompressed} bytes uncompressed, "
                                f"max {MAX_ZIP_UNCOMPRESSED})"
                            )
                        zipf.extractall(temp_dir)

                    share_files_in_zip = list(temp_dir.glob("share_*.txt"))
                    if not share_files_in_zip:
                        if verbose:
                            click.echo(f"No share file found in archive {share_file.name}")
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        continue
                    share_file = share_files_in_zip[0]
                except Exception as e:
                    # N2: always clean up temp_dir on failure
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    if verbose:
                        click.echo(f"Error extracting {share_file.name}: {str(e)}")
                    continue

            try:
                with open(share_file, "r") as f:
                    share_info = json.load(f)

                # N7: explicit field check instead of bare KeyError
                label = share_info.get("label")
                if not label:
                    if verbose:
                        click.echo(f"Share file {share_file.name} missing 'label' field, skipping")
                    continue

                share_set_id = share_info.get("share_set_id")

                def _resolve_version(si: Dict[str, Any]) -> str:
                    from src.config import VERSION as _V
                    if "tool_integrity" in si and "shares_tool_version" in si["tool_integrity"]:
                        return si["tool_integrity"]["shares_tool_version"]
                    return si.get("shares_tool_version") or si.get("version") or _V

                def _get_entry(store: Dict, key: str, si: Dict[str, Any]) -> Dict[str, Any]:
                    if key not in store:
                        store[key] = {
                            "shares": [],
                            "metadata": {
                                "version": _resolve_version(si),
                                "label": label,
                                # N6: validated below; defaults kept for compatibility
                                "threshold": si.get("threshold", 3),
                                "total_shares": si.get("total_shares", 5),
                            },
                        }
                    return store[key]

                share_key = share_info.get("share_key") or share_info.get("share")
                if not share_key:
                    if verbose:
                        click.echo(f"No share key in {share_file.name}, skipping")
                    continue

                decoded_share = base64.b64decode(share_key)

                if share_set_id:
                    entry = _get_entry(shares_by_set_id, share_set_id, share_info)
                    entry["shares"].append(
                        (share_info["share_index"], decoded_share)
                    )

                entry = _get_entry(shares_by_label, label, share_info)
                entry["shares"].append(
                    (share_info["share_index"], decoded_share)
                )

            except Exception as e:
                if verbose:
                    click.echo(f"Error processing {share_file.name}: {str(e)}")
            finally:
                # N2: always clean up temp_dir, regardless of share_file reassignment
                if temp_dir is not None:
                    shutil.rmtree(temp_dir, ignore_errors=True)

        if verbose:
            click.echo(f"Found shares for {len(shares_by_label)} different labels")
            for lbl in shares_by_label:
                cnt = len(shares_by_label[lbl]["shares"])
                thr = shares_by_label[lbl]["metadata"]["threshold"]
                click.echo(f"  - {lbl}: {cnt} shares (threshold: {thr})")

        # Resolution: prefer share_set_id match, fall back to label matching
        if extracted_share_set_id and extracted_share_set_id in shares_by_set_id:
            if verbose:
                click.echo("Matched shares by share_set_id")
            share_data = shares_by_set_id[extracted_share_set_id]["shares"]
            metadata = shares_by_set_id[extracted_share_set_id]["metadata"]
        else:
            # Try label matching against the input filename
            input_label = None
            for lbl in shares_by_label:
                if lbl in input_file:
                    input_label = lbl
                    break

            if input_label is not None:
                share_data = shares_by_label[input_label]["shares"]
                metadata = shares_by_label[input_label]["metadata"]
            elif shares_by_label:
                # N1: fallback — try each label with a real full decryption
                # The previous code tried to verify the key against 32 bytes of
                # ciphertext, which always fails for files > 32 bytes because
                # GCM authenticates the *entire* ciphertext.
                found = False
                for lbl in shares_by_label:
                    try:
                        if verbose:
                            click.echo(f"Trying shares with label: {lbl}")

                        candidate_meta = shares_by_label[lbl]["metadata"]
                        candidate_shares = shares_by_label[lbl]["shares"]
                        candidate_manager = ShareManager(
                            candidate_meta["threshold"], candidate_meta["total_shares"]
                        )
                        candidate_key = bytearray(
                            candidate_manager.combine_shares(candidate_shares)
                        )

                        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".dec.tmp")
                        os.close(tmp_fd)
                        try:
                            FileEncryptor(bytes(candidate_key)).decrypt_file(
                                input_file, tmp_path
                            )
                            # Full decryption succeeded — this is the right label
                            if verbose:
                                click.echo(f"Key verified for label: {lbl}")
                            share_data = candidate_shares
                            metadata = candidate_meta
                            SecureMemory.secure_clear(candidate_key)
                            found = True
                            break
                        except ValueError:
                            if verbose:
                                click.echo(f"Key verification failed for label: {lbl}")
                            SecureMemory.secure_clear(candidate_key)
                            continue
                        finally:
                            try:
                                os.unlink(tmp_path)
                            except OSError:
                                pass
                    except Exception as e:
                        if verbose:
                            click.echo(f"Error trying label {lbl}: {str(e)}")
                        continue

                if not found:
                    raise ValueError(
                        "No compatible shares found. "
                        "None of the available shares could decrypt the file."
                    )
            else:
                raise ValueError("No compatible shares found")

        if verbose:
            click.echo(f"\nUsing shares for label: {metadata.get('label', '?')}")
            click.echo(
                f"Found {len(share_data)} shares (need {metadata['threshold']})"
            )

        threshold = metadata["threshold"]
        total_shares = metadata["total_shares"]
        share_manager = ShareManager(threshold, total_shares)
        # M4: bytearray for effective zeroing
        key = bytearray(share_manager.combine_shares(share_data))

        # N4: refuse to silently overwrite an existing file
        output_file = (
            input_file[:-4] if input_file.endswith(".enc") else input_file + ".dec"
        )
        if Path(output_file).exists():
            raise ValueError(
                f"Output file already exists: {output_file}. "
                "Remove it first or rename it."
            )

        encryptor = FileEncryptor(bytes(key))
        encryptor.decrypt_file(input_file, output_file)
        click.echo(f"File successfully decrypted: {Path(output_file).absolute()}")
        SecureMemory.secure_clear(key)

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


def collect_manual_shares() -> Tuple[List[Tuple[int, bytes]], Dict[str, Any]]:
    """Collects shares manually from user input."""
    click.echo("\n=== Manual Share Entry ===")

    threshold = click.prompt("Threshold (minimum number of shares needed)", type=int)
    total_shares = click.prompt("Total shares", type=int)

    if threshold < 2 or threshold > total_shares or total_shares > 255:
        raise ValueError(
            "Invalid parameters. Threshold must be >= 2, "
            "total_shares must be >= threshold and <= 255."
        )

    from src.config import VERSION

    metadata: Dict[str, Any] = {
        "version": VERSION,
        "threshold": threshold,
        "total_shares": total_shares,
    }

    click.echo("\nEnter share details when prompted. Enter 'done' when finished.")
    shares: List[Tuple[int, bytes]] = []

    while True:
        share_index_input = click.prompt("Share index (or 'done' to finish)", type=str)
        if share_index_input.lower() == "done":
            break

        try:
            share_index = int(share_index_input)
            if share_index < 1 or share_index > 255:
                click.echo("Invalid share index. Must be between 1 and 255.")
                continue
        except ValueError:
            click.echo("Invalid share index. Please enter a number.")
            continue

        share_value = click.prompt("Share key value (Base64 or Hex encoded)", type=str)

        try:
            try:
                share_bytes = base64.b64decode(share_value)
                if len(share_bytes) != 32:
                    raise ValueError("Decoded length is not 32 bytes")
            except (ValueError, binascii.Error):
                hex_value = share_value.replace(":", "").replace(" ", "")
                if all(c in "0123456789abcdefABCDEF" for c in hex_value):
                    share_bytes = bytes.fromhex(hex_value)
                    if len(share_bytes) != 32:
                        raise ValueError(
                            f"Expected 32 bytes, got {len(share_bytes)}"
                        )
                else:
                    raise ValueError("Must be valid Base64 or Hex")
        except Exception as e:
            click.echo(f"Invalid share key value: {str(e)}. Please try again.")
            continue

        shares.append((share_index, share_bytes))
        click.echo(f"Share {share_index} added. Total: {len(shares)}")

        if len(shares) >= metadata["threshold"]:
            if click.confirm(
                "You have enough shares. Proceed with decryption?", default=None
            ):
                break

    if len(shares) < 2:
        click.echo("Warning: Not enough shares provided (minimum 2 required).")

    return shares, metadata
