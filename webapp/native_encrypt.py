"""Account-ID keyed guide payload encoder compatible with RXPTool's decoder.

This encodes the same zlib / Adler-32 / XOR / Base64 chunk structure that
rxp_decrypt.extract_chunks() and rxp_decrypt.decode_chunk() accept. It does not
make any assertion about third-party addon authorisation or full import framing.
"""
from __future__ import annotations

import base64
import io
import zipfile
import zlib

from rxp_decrypt import derive_base, initial_permutation, xor_stream

MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024
MAX_GUIDES = 1000


class EncryptError(ValueError):
    pass


def prepare_guides(source: bytes, filename: str) -> tuple[bytes, int]:
    """Accept NUL-delimited plaintext or a ZIP of standalone .txt guide files.

    Output is canonical guide plaintext: nonempty spans joined by one NUL.
    Guide bytes themselves are never decoded as text or rewritten.
    """
    if not source or len(source) > MAX_PLAINTEXT_BYTES:
        raise EncryptError('Choose a nonempty file of at most 16 MiB')
    guides: list[bytes] = []
    if filename.lower().endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(source), 'r') as archive:
                total = 0
                for entry in archive.infolist():
                    if entry.is_dir():
                        continue
                    if not entry.filename.lower().endswith('.txt'):
                        raise EncryptError('ZIP must contain only individual .txt guide files')
                    if entry.flag_bits & 1:
                        raise EncryptError('Password-protected ZIP files are not supported')
                    total += entry.file_size
                    if total > MAX_PLAINTEXT_BYTES:
                        raise EncryptError('Extracted guide data exceeds 16 MiB')
                    if len(guides) >= MAX_GUIDES:
                        raise EncryptError('Too many guides (maximum 1000)')
                    blob = archive.read(entry)
                    if b'\x00' in blob:
                        raise EncryptError('A ZIP guide contains NUL separators; upload it as combined TXT instead')
                    if blob:
                        guides.append(blob)
        except (zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError) as exc:
            raise EncryptError('Invalid or unsupported ZIP archive') from exc
    else:
        guides = [item for item in source.split(b'\x00') if item]

    if not guides:
        raise EncryptError('No nonempty guide data found')
    if len(guides) > MAX_GUIDES:
        raise EncryptError('Too many guides (maximum 1000)')
    return b'\x00'.join(guides), len(guides)


def encrypt_payload(plaintext: bytes, account_id: str) -> str:
    """Invert the existing RXPTool decoder on a single complete chunk.

    The header is the decimal Adler-32 checksum followed by ':'; the payload
    is Base64 of XOR-encrypted zlib data and terminates with '%'.
    """
    if not account_id or not account_id.strip():
        raise EncryptError('Enter the ID used for encryption')
    if not plaintext or len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise EncryptError('Plaintext must be between 1 byte and 16 MiB')
    check = zlib.adler32(plaintext) & 0xFFFFFFFF
    compressed = zlib.compress(plaintext, level=6)
    encrypted = xor_stream(compressed, initial_permutation(derive_base(account_id.strip())))
    return f'{check}:{base64.b64encode(encrypted).decode("ascii")}%'
