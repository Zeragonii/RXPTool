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


def guide_filename(guide: bytes, number: int) -> str:
    """Make a Windows-safe filename from pre-step #group/#name headers.

    Filename formatting never alters the bytes written to the actual file.
    """
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
    # Numeric prefix avoids collisions even if different guides have identical names.
    suffix = " - ".join(labels) if labels else "Guide"
    return f"guide_{number:03d} - {suffix}.txt"


def write_guides(guides: list[bytes], directory: Path) -> list[Path]:
    """Create separate files without deleting unrelated/previous user files."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for number, guide in enumerate(guides, start=1):
        path = directory / guide_filename(guide, number)
        path.write_bytes(guide)
        paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode a GuideLoader.lua account-keyed encrypted import."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--payload", help="Full import string, single chunk, or Base64")
    source.add_argument("--payload-file", type=Path, help="Read encoded payload from a text file")
    parser.add_argument("--id", dest="account_id", help="Exact account ID/BattleTag returned by WoW")
    parser.add_argument("--checksum", type=int, help="Decimal Adler-32 checksum for raw Base64 input")
    parser.add_argument("--output", type=Path,
                        help="Save a single guide to this file; multiple guides are automatically split")
    parser.add_argument("--split-dir", type=Path,
                        help="Custom directory for separate guides (also writes a single guide there)")
    parser.add_argument("--max-output-mib", type=int, default=128,
                        help="Maximum decompressed bytes per chunk in MiB (default: 128)")
    args = parser.parse_args()

    try:
        if args.max_output_mib <= 0:
            raise DecodeError("--max-output-mib must be greater than zero")
        account_id = args.account_id
        if account_id is None:
            account_id = getpass.getpass("Account ID (not echoed): ")
        if not account_id:
            raise DecodeError("An account ID is required")

        text = (args.payload_file.read_text(encoding="utf-8-sig")
                if args.payload_file is not None else args.payload)
        chunks = extract_chunks(text, args.checksum)
        initial_state = initial_permutation(derive_base(account_id))

        decoded = []
        for number, chunk in enumerate(chunks, start=1):
            try:
                decoded.append(decode_chunk(chunk, initial_state,
                                            args.max_output_mib * 1024 * 1024))
            except DecodeError as exc:
                raise DecodeError(f"Chunk {number}/{len(chunks)}: {exc}") from exc

        # Lua loads all nonempty spans separated by NUL as distinct guides.
        guides = [guide for item in decoded for guide in item.split(b"\x00") if guide]
        if not guides:
            raise DecodeError("Decryption produced no guide data")

        if len(guides) > 1:
            # Match the addon's behaviour: every nonempty NUL-separated span is
            # an independent guide, even when it came from another chunk.
            split_dir = args.split_dir or (
                (args.output.parent if args.output else Path.cwd()) / "decrypted_guides"
            )
            paths = write_guides(guides, split_dir)
            print(f"Detected {len(guides)} guides; wrote separate files to {split_dir}:",
                  file=sys.stderr)
            for path in paths:
                print(f"  {path.name}", file=sys.stderr)
            if args.output and args.output.exists():
                print(f"Note: existing combined/previous file {args.output} was not modified.",
                      file=sys.stderr)
        else:
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_bytes(guides[0])
                print(f"Saved single guide to {args.output}", file=sys.stderr)
            if args.split_dir:
                paths = write_guides(guides, args.split_dir)
                print(f"Saved single guide to {paths[0]}", file=sys.stderr)
            if not args.output and not args.split_dir:
                sys.stdout.buffer.write(guides[0])
                if not guides[0].endswith(b"\n"):
                    sys.stdout.buffer.write(b"\n")

        print(f"Success: {len(chunks)} encrypted chunk(s), {len(guides)} guide(s)",
              file=sys.stderr)
        return 0
    except (DecodeError, OSError, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
