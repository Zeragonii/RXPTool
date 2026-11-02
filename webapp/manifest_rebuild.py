"""Rebuild an edited, *same-account* native-format guide import without stored ciphertext.

The v1.1.3 standalone manifest records original framing, per-chunk NUL
positions, and SHA-256 fingerprints of the source key. Reconstruct the
original guide slots from that structure, substituting a new plaintext guide
for each nonempty slot, then independently recompress/encrypt every chunk.

This only accepts the original key fingerprint. It is NOT an account-rebinding
feature. Third-party game/addon loading remains a separate test.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import zlib

from rxp_decrypt import CHUNK_RE, derive_base, initial_permutation, xor_stream

SCHEMA = "rxptool-import-archive"
MAX_GUIDES = 1000
MAX_CHUNKS = 512
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 24 * 1024 * 1024


class RebuildError(ValueError):
    pass


def rebuild_from_manifest(manifest_bytes: bytes, plaintext: bytes, account_id: str):
    """Return (native-format import text, count, chunk_count, edited).

    `plaintext` is the normalised combined TXT, with a single NUL delimiter
    between each nonempty guide. Original empty slots are reconstructed from
    the manifest; guide ordering/count must stay unchanged.
    """
    if not 0 < len(manifest_bytes) <= MAX_MANIFEST_BYTES:
        raise RebuildError("Manifest must be a JSON file up to 4 MiB")
    if not 0 < len(plaintext) <= MAX_PLAINTEXT_BYTES:
        raise RebuildError("Plaintext must be 1 byte to 16 MiB")
    try:
        m = json.loads(manifest_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RebuildError("Manifest is not valid JSON") from exc
    if not isinstance(m, dict) or m.get("schema") != SCHEMA or m.get("schema_version") != 1:
        raise RebuildError("Expected a v1.1.3 RXPTool import manifest")
    source = m.get("source")
    chunks = m.get("chunks")
    guide_info = m.get("guides")
    if not isinstance(source, dict) or not isinstance(guide_info, dict) or not isinstance(chunks, list):
        raise RebuildError("Manifest is missing source, guides or chunks")
    if not 1 <= len(chunks) <= MAX_CHUNKS:
        raise RebuildError("Manifest has no chunks or too many chunks")
    fingerprint = hashlib.sha256(derive_base(account_id)).hexdigest()
    framing = source.get("framing")
    if not isinstance(framing, dict) or framing.get("input_kind") != "framed-import":
        raise RebuildError("A full import header and footer are required; standalone chunks cannot be rebuilt as a native import")
    header = framing.get("header")
    footer = framing.get("footer")
    between = framing.get("inter_chunk_text")
    if not all(isinstance(x, dict) for x in (header, footer)) or not isinstance(between, list):
        raise RebuildError("Invalid import framing")
    head, foot = header.get("raw"), footer.get("raw")
    if not isinstance(head, str) or not isinstance(foot, str) or len(between) != len(chunks) - 1:
        raise RebuildError("Missing or inconsistent import framing")
    if any(not isinstance(x, str) for x in between) or sum(map(len, [head, foot, *between])) > 256 * 1024:
        raise RebuildError("Import framing is too large or invalid")
    # Matches Lua's leading non-digit and trailing non-digit trimming.
    if not re.fullmatch(r"\D*\d+\|", head) or not re.fullmatch(r"\|\d+\D*", foot):
        raise RebuildError("Import header or footer does not have the expected syntax")
    declared = int(re.search(r"(\d+)\|$", head).group(1))
    version = int(re.match(r"\|(\d+)", foot).group(1))
    if (header.get("declared_guide_count") != declared or
        footer.get("addon_version") != version or
        source.get("declared_guide_count") != declared or
        source.get("import_version") != version):
        raise RebuildError("Manifest guide count or version framing disagrees with source fields")

    guides = plaintext.split(b"\x00")
    if not guides or len(guides) > MAX_GUIDES or any(not g for g in guides):
        raise RebuildError("Upload a combined TXT with exactly one NUL byte between nonempty guides")
    if len(guides) != guide_info.get("count") or declared != len(guides):
        raise RebuildError("Edited guide count must match the original import and manifest")
    permutation = initial_permutation(derive_base(account_id))
    guide_idx = 0
    encoded = []
    edited = (hashlib.sha256(plaintext).hexdigest() != guide_info.get("combined_sha256"))
    for i, chunk in enumerate(chunks, 1):
        if not isinstance(chunk, dict) or chunk.get("index") != i or chunk.get("mode") != ":":
            raise RebuildError(f"Invalid metadata for chunk {i}")
        old_size, offsets, count = (chunk.get("plaintext_bytes"), chunk.get("nul_byte_offsets_0_based"), chunk.get("guides"))
        if not isinstance(old_size, int) or not 0 <= old_size <= MAX_PLAINTEXT_BYTES or not isinstance(offsets, list) or not isinstance(count, int):
            raise RebuildError(f"Malformed NUL metadata for chunk {i}")
        if len(offsets) > 50000 or any(not isinstance(pos, int) or pos < 0 or pos >= old_size for pos in offsets):
            raise RebuildError(f"Invalid NUL offset in chunk {i}")
        if offsets != sorted(set(offsets)):
            raise RebuildError(f"Unsorted or repeated NUL offsets in chunk {i}")
        bounds = [-1, *offsets, old_size]
        slot_sizes = [b - a - 1 for a, b in zip(bounds, bounds[1:])]
        if any(n < 0 for n in slot_sizes) or sum(n > 0 for n in slot_sizes) != count:
            raise RebuildError(f"Chunk {i} guide-slot metadata is inconsistent")
        new_slots = []
        for slot_size in slot_sizes:
            if slot_size:
                if guide_idx >= len(guides):
                    raise RebuildError("Not enough guides for the declared chunk layout")
                new_slots.append(guides[guide_idx])
                guide_idx += 1
            else:
                new_slots.append(b"")
        raw = b"\x00".join(new_slots)
        if len(raw) > MAX_PLAINTEXT_BYTES:
            raise RebuildError(f"Edited chunk {i} exceeds 16 MiB")
        check = zlib.adler32(raw) & 0xFFFFFFFF
        encrypted = xor_stream(zlib.compress(raw, level=6), permutation)
        encoded.append(f'{check}:{base64.b64encode(encrypted).decode("ascii")}%')
    if guide_idx != len(guides):
        raise RebuildError("More guides were supplied than fit the original layout")
    result = head + encoded[0] + "".join(middle + part for middle, part in zip(between, encoded[1:])) + foot
    if len(result.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise RebuildError("Output import is too large")
    if len(CHUNK_RE.findall(result)) != len(chunks):
        raise RebuildError("Generated import has invalid or ambiguous chunk framing")
    return result, len(guides), len(chunks), edited
