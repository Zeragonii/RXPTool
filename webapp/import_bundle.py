"""Lossless RXPTool archival bundles for an existing, matching-key import.

The bundle saves the *original* import text, the plaintext and each chunk's
unmodified decompressed bytes. Restoring never generates a new key-bound import:
it returns the recorded import unchanged after thorough consistency checks.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from typing import Callable

from rxp_decrypt import CHUNK_RE, decode_chunk, derive_base, extract_chunks, initial_permutation

BUNDLE_SCHEMA = "rxptool-import-archive"
BUNDLE_VERSION = 1
MAX_ARCHIVE_UNCOMPRESSED = 192 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RECORDED_SEPARATORS = 50_000


class BundleError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def account_fingerprint(account_id: str) -> str:
    # No cleartext account ID is stored; fingerprint of the exact derived key.
    return digest(derive_base(account_id))


def _metadata_from_import(payload: str) -> tuple[int | None, int | None]:
    # Lua importer strips leading non-digit prefix and trailing non-digits.
    prepared = re.sub(r"^\D+", "", payload)
    prepared = re.sub(r"\D+$", "", prepared)
    match_count = re.match(r"^(\d+)\|", prepared)
    match_version = re.search(r"\|(\d+)$", prepared)
    return (int(match_count.group(1)) if match_count else None,
            int(match_version.group(1)) if match_version else None)


def nul_offsets(data: bytes) -> list[int]:
    """Return exact zero-based offsets of every NUL byte, including repeats."""
    positions = [m.start() for m in re.finditer(b"\x00", data)]
    if len(positions) > MAX_RECORDED_SEPARATORS:
        raise BundleError("Too many NUL separators to record in a manifest")
    return positions


def original_framing(payload: str) -> dict:
    """Preserve literal text *outside* the encrypted chunks, not inferred framing.

    The original complete import uses `count|` ahead of the first chunk and
    `|version` after the last. Bare Base64/chunk inputs have no outer framing.
    Character positions refer to the original Unicode input string; payload
    byte lengths elsewhere use UTF-8. All genuine payload framing is ASCII.
    """
    matches = list(CHUNK_RE.finditer(payload))
    if not matches:
        return {
            "input_kind": "standalone-chunk-or-base64",
            "header": {"raw": None, "declared_guide_count": None},
            "footer": {"raw": None, "addon_version": None},
            "inter_chunk_text": [],
        }
    raw_header = payload[:matches[0].start()]
    raw_footer = payload[matches[-1].end():]
    between = [payload[a.end():b.start()] for a, b in zip(matches, matches[1:])]
    if max([len(raw_header), len(raw_footer), *(len(x) for x in between)] or [0]) > 256 * 1024:
        raise BundleError("Import framing is too large for the metadata manifest")
    count_match = re.search(r"(\d+)\|$", raw_header)
    footer_match = re.match(r"^\|(\d+)", raw_footer)
    return {
        "input_kind": "framed-import" if count_match and footer_match else "chunk-data",
        "header": {"raw": raw_header if raw_header else None, "declared_guide_count": int(count_match.group(1)) if count_match else None},
        "footer": {"raw": raw_footer if raw_footer else None, "addon_version": int(footer_match.group(1)) if footer_match else None},
        "inter_chunk_text": between,
    }


def make_import_manifest(payload: str, account_id: str, guides: list[bytes],
                         *, max_output_bytes: int, max_chunks: int) -> tuple[dict, list[bytes], bytes]:
    """Inspect successfully decrypted bytes without normalising their separators."""
    chunks = extract_chunks(payload, None)
    if len(chunks) > max_chunks:
        raise BundleError("Too many encrypted chunks")
    original = payload.encode("utf-8")
    permutation = initial_permutation(derive_base(account_id))
    matches = list(CHUNK_RE.finditer(payload))
    raw_chunks: list[bytes] = []
    manifest_chunks: list[dict] = []
    stream_nuls: list[int] = []
    stream_offset = 0
    restored_guides: list[bytes] = []
    for index, chunk in enumerate(chunks, 1):
        raw = decode_chunk(chunk, permutation, max_output_bytes - stream_offset)
        chunk_nuls = nul_offsets(raw)
        stream_nuls.extend(stream_offset + pos for pos in chunk_nuls)
        if len(stream_nuls) > MAX_RECORDED_SEPARATORS:
            raise BundleError("Too many total NUL separators to record")
        chunk_guides = [g for g in raw.split(b"\x00") if g]
        restored_guides.extend(chunk_guides)
        raw_chunks.append(raw)
        chunk_metadata = {
            "index": index,
            "mode": ":" if chunk.checksum is not None else "raw-base64",
            "checksum": chunk.checksum,
            "base64_length": len(chunk.b64),
            "plaintext_bytes": len(raw),
            "plaintext_sha256": digest(raw),
            "guides": len(chunk_guides),
            "raw_stream_start_byte_0_based": stream_offset,
            "raw_stream_end_byte_exclusive": stream_offset + len(raw),
            "nul_byte_offsets_0_based": chunk_nuls,
        }
        if len(matches) == len(chunks):
            match = matches[index - 1]
            chunk_metadata["source_char_start_0_based"] = match.start()
            chunk_metadata["source_char_end_exclusive"] = match.end()
            chunk_metadata["source_prefix_raw"] = payload[match.start():match.start(3)]
            chunk_metadata["source_terminator_raw"] = payload[match.end(3):match.end()]
        manifest_chunks.append(chunk_metadata)
        stream_offset += len(raw)
    if restored_guides != guides:
        raise BundleError("Decoded guide content changed during export")
    combined = b"\x00".join(guides)
    framing = original_framing(payload)
    declared_count, import_version = _metadata_from_import(payload)
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "schema_version": BUNDLE_VERSION,
        "description": "Read-only source inspection and lossless archive; original import restoration requires original ID",
        "offsets": {
            "unit": "bytes", "base": 0, "nul_byte_value_hex": "00",
            "note": "Raw offsets include every original NUL, including repeated/leading/trailing separators; combined TXT normalises to one NUL between nonempty guides.",
            "raw_chunks_concatenated_bytes": stream_offset,
            "raw_chunks_concatenated_nul_byte_offsets_0_based": stream_nuls,
            "normalized_combined_nul_byte_offsets_0_based": nul_offsets(combined),
        },
        "source": {
            "payload_sha256": digest(original),
            "payload_bytes": len(original),
            "declared_guide_count": declared_count,
            "import_version": import_version,
            "framing": framing,
            "account_key_fingerprint": account_fingerprint(account_id),
        },
        "guides": {"count": len(guides), "combined_bytes": len(combined), "combined_sha256": digest(combined)},
        "chunks": manifest_chunks,
    }
    return manifest, raw_chunks, combined


def manifest_json(manifest: dict) -> bytes:
    output = (json.dumps(manifest, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    if len(output) > MAX_MANIFEST_BYTES:
        raise BundleError("Manifest exceeds the 4 MiB export limit")
    return output


def build_import_manifest(payload: str, account_id: str, guides: list[bytes],
                          *, max_output_bytes: int, max_chunks: int) -> bytes:
    """Return a small, editable-layout JSON without archival file hashes.

    v1.1.5 uses only metadata necessary to retain framing, empty guide slots,
    and original account context. The full archival ZIP keeps its original
    detailed manifest, so old archives and archive recovery remain compatible.
    """
    archived, _raw_chunks, _combined = make_import_manifest(
        payload, account_id, guides, max_output_bytes=max_output_bytes, max_chunks=max_chunks
    )
    framing = archived['source']['framing']
    layout = {
        'schema': 'rxptool-edit-layout',
        'schema_version': 1,
        'description': 'Editable guide layout; no original encrypted bytes or source-file hashes',
        'account_key_fingerprint': archived['source']['account_key_fingerprint'],
        'header': framing['header']['raw'],
        'footer': framing['footer']['raw'],
        'inter_chunk_text': framing['inter_chunk_text'],
        'guide_count': len(guides),
        'chunks': [{
            'index': c['index'],
            'mode': c['mode'],
            'plaintext_bytes': c['plaintext_bytes'],
            'guides': c['guides'],
            'nul_byte_offsets_0_based': c['nul_byte_offsets_0_based'],
        } for c in archived['chunks']],
    }
    return manifest_json(layout)


def build_import_bundle(payload: str, account_id: str, guides: list[bytes],
                        *, max_output_bytes: int, max_chunks: int) -> bytes:
    """Make a portable archive containing an identical manifest plus original data."""
    manifest, raw_chunks, combined = make_import_manifest(
        payload, account_id, guides, max_output_bytes=max_output_bytes, max_chunks=max_chunks
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("manifest.json", manifest_json(manifest))
        zf.writestr("original_payload.txt", payload.encode("utf-8"))
        zf.writestr("decrypted_guides.txt", combined)
        for index, raw in enumerate(raw_chunks, 1):
            zf.writestr(f"chunks/chunk_{index:03d}.bin", raw)
    return output.getvalue()


def is_import_bundle(data: bytes) -> bool:
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return "manifest.json" in zf.namelist() and "original_payload.txt" in zf.namelist()
    except (OSError, zipfile.BadZipFile):
        return False


def restore_original_import(data: bytes, account_id: str,
                            decode_payload: Callable[[str, str], tuple[list[bytes], int]],
                            *, max_output_bytes: int = MAX_ARCHIVE_UNCOMPRESSED) -> tuple[bytes, int]:
    """Return the exact original payload, rejecting altered/incorrect-key bundles."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            files = zf.infolist()
            if len(files) > 520 or len(files) != len({x.filename for x in files}):
                raise BundleError("Archive contains duplicate or excessive entries")
            if any(x.file_size > max_output_bytes for x in files):
                raise BundleError("Archive contains an oversized file")
            if sum(x.file_size for x in files) > max_output_bytes:
                raise BundleError("Archive uncompressed size exceeds limit")
            if not {"manifest.json", "original_payload.txt", "decrypted_guides.txt"} <= set(zf.namelist()):
                raise BundleError("Archive is missing required source or plaintext data")
            raw_manifest = zf.read("manifest.json")
            if len(raw_manifest) > MAX_MANIFEST_BYTES:
                raise BundleError("Manifest too large")
            manifest = json.loads(raw_manifest)
            if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_SCHEMA or manifest.get("schema_version") != BUNDLE_VERSION:
                raise BundleError("Unsupported import archive version")
            if not isinstance(manifest.get("source"), dict) or not isinstance(manifest.get("guides"), dict) or not isinstance(manifest.get("chunks"), list):
                raise BundleError("Invalid manifest")
            required_names = {"manifest.json", "original_payload.txt", "decrypted_guides.txt"}
            chunks = manifest["chunks"]
            if not 1 <= len(chunks) <= 512:
                raise BundleError("Invalid chunk count")
            required_names.update(f"chunks/chunk_{idx:03d}.bin" for idx in range(1, len(chunks) + 1))
            if set(zf.namelist()) != required_names:
                raise BundleError("Unexpected or missing archive entries")
            original = zf.read("original_payload.txt")
            combined = zf.read("decrypted_guides.txt")
            if digest(original) != manifest["source"].get("payload_sha256"):
                raise BundleError("Original encrypted payload has been modified")
            if len(original) != manifest["source"].get("payload_bytes"):
                raise BundleError("Original payload length mismatch")
            if digest(combined) != manifest["guides"].get("combined_sha256"):
                raise BundleError("Decrypted guide data has been modified; exact restoration is unavailable")
            if len(combined) != manifest["guides"].get("combined_bytes"):
                raise BundleError("Guide data length mismatch")
            if account_fingerprint(account_id) != manifest["source"].get("account_key_fingerprint"):
                raise BundleError("Use the original ID associated with this import archive")
            payload = original.decode("utf-8")
            recovered, chunk_count = decode_payload(account_id, payload)
            if chunk_count != len(chunks) or b"\0".join(recovered) != combined:
                raise BundleError("Archived encrypted and plaintext data do not match")
            if len(recovered) != manifest["guides"].get("count"):
                raise BundleError("Archived guide count does not match")
            raw_chunks = extract_chunks(payload, None)
            permutation = initial_permutation(derive_base(account_id))
            if len(raw_chunks) != len(chunks):
                raise BundleError("Import chunk count mismatch")
            count = 0
            cumulative_offset = 0
            source_matches = list(CHUNK_RE.finditer(payload))
            for idx, (chunk, metadata) in enumerate(zip(raw_chunks, chunks), 1):
                raw = decode_chunk(chunk, permutation, max_output_bytes)
                if not isinstance(metadata, dict) or metadata.get("index") != idx:
                    raise BundleError("Chunk ordering mismatch")
                if (digest(raw) != metadata.get("plaintext_sha256") or
                    raw != zf.read(f"chunks/chunk_{idx:03d}.bin") or
                    metadata.get("checksum") != chunk.checksum or
                    metadata.get("base64_length") != len(chunk.b64) or
                    metadata.get("plaintext_bytes") != len(raw)):
                    raise BundleError("Archived chunk was modified")
                if "nul_byte_offsets_0_based" in metadata and metadata["nul_byte_offsets_0_based"] != nul_offsets(raw):
                    raise BundleError("Archived NUL separator metadata was modified")
                if "raw_stream_start_byte_0_based" in metadata and (
                    metadata["raw_stream_start_byte_0_based"] != cumulative_offset or
                    metadata.get("raw_stream_end_byte_exclusive") != cumulative_offset + len(raw)
                ):
                    raise BundleError("Archived raw chunk positions were modified")
                if "source_char_start_0_based" in metadata:
                    if len(source_matches) != len(chunks):
                        raise BundleError("Archived source chunk positions were modified")
                    match = source_matches[idx - 1]
                    expected_fields = {
                        "source_char_start_0_based": match.start(),
                        "source_char_end_exclusive": match.end(),
                        "source_prefix_raw": payload[match.start():match.start(3)],
                        "source_terminator_raw": payload[match.end(3):match.end()],
                    }
                    if any(metadata.get(field) != expected for field, expected in expected_fields.items()):
                        raise BundleError("Archived source chunk framing was modified")
                cumulative_offset += len(raw)
                count += len([g for g in raw.split(b"\0") if g])
            if count != len(recovered):
                raise BundleError("Chunk guide count mismatch")
            guide_count, version = _metadata_from_import(payload)
            if (manifest["source"].get("declared_guide_count") != guide_count or
                manifest["source"].get("import_version") != version):
                raise BundleError("Import header/footer metadata was altered")
            if "offsets" in manifest:
                recorded = manifest["offsets"]
                if not isinstance(recorded, dict):
                    raise BundleError("Invalid NUL separator metadata")
                total_raw = b"".join(zf.read(f"chunks/chunk_{idx:03d}.bin") for idx in range(1, len(chunks) + 1))
                if recorded.get("raw_chunks_concatenated_bytes") != len(total_raw):
                    raise BundleError("Archived raw stream length was modified")
                if recorded.get("raw_chunks_concatenated_nul_byte_offsets_0_based") != nul_offsets(total_raw):
                    raise BundleError("Archived raw separator offsets were modified")
                if recorded.get("normalized_combined_nul_byte_offsets_0_based") != nul_offsets(combined):
                    raise BundleError("Archived combined separator offsets were modified")
            if "framing" in manifest["source"] and manifest["source"]["framing"] != original_framing(payload):
                raise BundleError("Archived header/footer metadata was modified")
            return original, len(recovered)
    except (zipfile.BadZipFile, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, OverflowError) as exc:
        raise BundleError("Invalid or damaged import archive") from exc
