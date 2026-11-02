#!/usr/bin/env python3
"""Offline decoder for GuideLoader.lua's account-keyed import format.

Uses only Python's standard library. Supply the same account ID text the addon
receives from its WoW API call. This tool cannot recover an unknown ID/key.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import re
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path


# Mirrors Lua: (%-?%d+)(%D)([A-Za-z0-9%+%/%=]+)%%
CHUNK_RE = re.compile(r"(-?\d+)(\D)([A-Za-z0-9+/=]+)%")
SINGLE_RE = re.compile(r"(-?\d+):([A-Za-z0-9+/=]+)%?")
B64_RE = re.compile(r"[A-Za-z0-9+/=]+")


class DecodeError(Exception):
    pass


@dataclass(frozen=True)
class Chunk:
    b64: str
    checksum: int | None


def derive_base(id_string: str) -> bytes:
    """Translate ReadCacheData()'s 16-entry in-place byte transformation."""
    # Lua's `:lower()`, `#base` and `:sub()` operate on bytes, not Unicode chars.
    src = id_string.encode("utf-8").lower()[-16:]
    k = 16 - len(src)

    base = [src[(i - k) & 15] if ((i - k) & 15) < len(src) else 0
            for i in range(16)]

    for i in range(16):
        base[(-i) & 15] = (
            base[(15 - i) & 15]
            ^ base[(13 - i) & 15]
            ^ base[(12 - i) & 15]
            ^ base[(10 - i) & 15]
        )

    return bytes(base)


def initial_permutation(base: bytes) -> list[int]:
    """Translate ReadCacheData('buffer') exactly (RC4-style KSA)."""
    if len(base) != 16:
        raise ValueError("The derived key must be 16 bytes")

    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + base[i & 15]) & 0xff
        state[i], state[j] = state[j], state[i]
    return state


def xor_stream(payload: bytes, initial_state: list[int]) -> bytes:
    """Translate CheckDataIntegrity's byte loop (RC4-style PRGA)."""
    state = initial_state.copy()
    i = j = 0
    result = bytearray(len(payload))

    for offset, value in enumerate(payload):
        i = (i + 1) & 0xff
        j = (j + state[i]) & 0xff
        state[i], state[j] = state[j], state[i]
        result[offset] = value ^ state[(state[i] + state[j]) & 0xff]

    return bytes(result)


def extract_chunks(text: str, manual_checksum: int | None) -> list[Chunk]:
    """Accept full addon exports, 'checksum:base64%' chunks, or raw Base64."""
    matches = list(CHUNK_RE.finditer(text))
    if matches:
        chunks = []
        for match in matches:
            mode = match.group(2)
            if mode != ":":
                raise DecodeError(f"Unsupported payload mode {mode!r}; Lua only supports ':'")
            chunks.append(Chunk(match.group(3), int(match.group(1))))
        return chunks

    compact = "".join(text.split())
    single = SINGLE_RE.fullmatch(compact)
    if single:
        checksum = int(single.group(1))
        if manual_checksum is not None and checksum != manual_checksum:
            raise DecodeError("The supplied --checksum conflicts with the chunk header")
        return [Chunk(single.group(2), checksum)]

    if B64_RE.fullmatch(compact):
        return [Chunk(compact, manual_checksum)]

    raise DecodeError(
        "No valid encrypted chunk found. Provide the full import string, "
        "a 'checksum:base64%' chunk, or a raw Base64 payload."
    )


def decode_chunk(chunk: Chunk, initial_state: list[int], max_output_bytes: int) -> bytes:
    encoded = chunk.b64
    try:
        # WoW's built-in and fallback Base64 decoders expect standard Base64.
        encrypted = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DecodeError(f"Invalid Base64 payload: {exc}") from exc

    compressed = xor_stream(encrypted, initial_state)

    if len(compressed) < 8:
        raise DecodeError("Decoded payload is too short to contain a valid zlib stream")

    cmf, flg = compressed[:2]
    trailer = int.from_bytes(compressed[-4:], "big")
    if (
        (cmf & 0x0f) != 8
        or cmf > 0x78
        or (flg & 0x20) != 0
        or ((cmf << 8) | flg) % 31 != 0
    ):
        raise DecodeError("Invalid zlib header: incorrect ID or corrupted payload")

    expected = None if chunk.checksum is None else chunk.checksum & 0xffffffff
    if expected is not None and trailer != expected:
        raise DecodeError(
            f"Checksum in zlib trailer ({trailer:#010x}) does not match "
            f"payload header ({expected:#010x}); incorrect ID or corrupted data"
        )

    try:
        decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS)
        plain = decompressor.decompress(compressed, max_output_bytes + 1)
        if len(plain) > max_output_bytes or decompressor.unconsumed_tail:
            raise DecodeError("Decompressed data exceeds configured safety limit")
        plain += decompressor.flush(max_output_bytes + 1 - len(plain))
        if len(plain) > max_output_bytes:
            raise DecodeError("Decompressed data exceeds configured safety limit")
        if not decompressor.eof:
            raise DecodeError("Truncated zlib stream")
        if decompressor.unused_data:
            raise DecodeError("Unexpected bytes after the zlib stream")
    except zlib.error as exc:
        raise DecodeError(f"Zlib decompression failed: {exc}") from exc

    actual = zlib.adler32(plain) & 0xffffffff
    if expected is not None and actual != expected:
        raise DecodeError(
            f"Plaintext Adler-32 {actual:#010x} does not match "
            f"payload header {expected:#010x}"
        )
    if actual != trailer:
        raise DecodeError("Plaintext checksum differs from the zlib trailer")

    return plain


def guide_label(guide: bytes, number: int) -> str:
    """Show a short, safe display label for each guide in the UI preview."""
    group = name = None
    header = guide.decode("utf-8", errors="replace")
    for line in header.splitlines():
        line = line.strip()
        if re.match(r"^step(?:\s|$)", line, re.IGNORECASE):
            break
        match = re.match(r"^#(group|name)\s+(.+?)\s*$", line, re.IGNORECASE)
        if match:
            value = re.split(r"\s+<<", match.group(2), maxsplit=1)[0].strip()
            if match.group(1).lower() == "group" and not group:
                group = value
            elif match.group(1).lower() == "name" and not name:
                name = value
        if group and name:
            break

    def safe(text: str) -> str:
        text = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text)
        text = re.sub(r"\s+", " ", text).strip(" ._")
        return text[:64].rstrip(" ._")

    labels = [safe(value) for value in (group, name) if value]
    labels = [label for label in labels if label]
    suffix = " - ".join(labels) if labels else "Guide"
    return f"{number:03d} · {suffix}"



def main() -> int:
    """Optional CLI entry point: export one editable TXT, same as the WebUI."""
    parser = argparse.ArgumentParser(description='Decrypt a full native RXP import to Editable guide TXT.')
    parser.add_argument('--payload-file', required=True, type=Path, help='Original encrypted import text file')
    parser.add_argument('--id', dest='account_id', help='Original account ID (prompted if omitted)')
    parser.add_argument('--output', type=Path, default=Path('editable_guides.txt'),
                        help='Path for the self-contained editable TXT')
    args = parser.parse_args()
    try:
        from webapp.editable_document import make_editable_document
        account = args.account_id or getpass.getpass('Account ID (not echoed): ')
        if not account:
            raise DecodeError('An account ID is required')
        payload = args.payload_file.read_text(encoding='utf-8-sig')
        editable, count, chunks = make_editable_document(payload, account)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(editable)
        print(f'Saved {count} guides from {chunks} chunk(s) to {args.output}', file=sys.stderr)
        return 0
    except (DecodeError, ValueError, OSError, UnicodeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
