"""RXPTool's own authenticated package format. NOT RestedXP's import format.

Wire: 8-byte versioned magic | 16-byte salt | 12-byte AES-GCM nonce |
      ciphertext with 16-byte authentication tag.

Encrypted plaintext: zlib(2-byte UTF-8 filename length | filename | exact file bytes).
The Battle.net ID is key material, not a secret; use the resulting package only
for convenience/compatibility, not protection from someone who knows the ID.
"""
from __future__ import annotations

import os
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"RXPTENC\x01"
SALT_BYTES = 16
NONCE_BYTES = 12
ITERATIONS = 240_000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_WIRE_BYTES = MAX_FILE_BYTES + 128 * 1024


class PackageError(ValueError):
    pass


def _key(battle_id: str, salt: bytes) -> bytes:
    if not battle_id or len(battle_id.encode("utf-8")) > 256:
        raise PackageError("Provide a valid account ID")
    # Identifier normalisation is deliberately specified by our own format.
    # This format is not designed for, or accepted by, the RestedXP importer.
    normalised = battle_id.strip().lower().encode("utf-8")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITERATIONS).derive(normalised)


def _safe_name(name: str) -> str:
    name = name.replace("\\", "/").split("/")[-1].strip()
    if not name or name in (".", ".."):
        name = "guide.txt"
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise PackageError("Filename contains invalid characters")
    if len(name.encode("utf-8")) > 180:
        raise PackageError("Filename is too long (180 UTF-8 bytes maximum)")
    return name


def encrypt_package(file_data: bytes, battle_id: str, filename: str = "guide.txt") -> bytes:
    if not isinstance(file_data, bytes) or not 0 < len(file_data) <= MAX_FILE_BYTES:
        raise PackageError("File must contain data and be no larger than 16 MiB")
    name = _safe_name(filename).encode("utf-8")
    payload = len(name).to_bytes(2, "big") + name + file_data
    compressed = zlib.compress(payload, level=6)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(_key(battle_id, salt)).encrypt(nonce, compressed, MAGIC)
    return MAGIC + salt + nonce + ciphertext


def decrypt_package(package: bytes, battle_id: str) -> tuple[bytes, str]:
    minimum = len(MAGIC) + SALT_BYTES + NONCE_BYTES + 16
    if not isinstance(package, bytes) or not minimum <= len(package) <= MAX_WIRE_BYTES:
        raise PackageError("Invalid or oversized RXPTool package")
    if not package.startswith(MAGIC):
        raise PackageError("Not an RXPTool package (.rxptool); RestedXP exports are not supported here")
    position = len(MAGIC)
    salt = package[position:position + SALT_BYTES]
    position += SALT_BYTES
    nonce = package[position:position + NONCE_BYTES]
    position += NONCE_BYTES
    try:
        compressed = AESGCM(_key(battle_id, salt)).decrypt(nonce, package[position:], MAGIC)
    except InvalidTag:
        raise PackageError("Incorrect ID or corrupted package (authentication failed)") from None
    try:
        inflater = zlib.decompressobj()
        plain = inflater.decompress(compressed, MAX_FILE_BYTES + 512)
        if not inflater.eof or inflater.unconsumed_tail or inflater.unused_data:
            raise PackageError("Invalid or oversized package contents")
    except zlib.error:
        raise PackageError("Invalid compressed package contents") from None
    if len(plain) < 3:
        raise PackageError("Invalid package contents")
    length = int.from_bytes(plain[:2], "big")
    if length == 0 or len(plain) <= 2 + length:
        raise PackageError("Invalid package filename or missing file data")
    try:
        filename = _safe_name(plain[2:2 + length].decode("utf-8"))
    except UnicodeError:
        raise PackageError("Invalid package filename") from None
    file_data = plain[2 + length:]
    if len(file_data) > MAX_FILE_BYTES:
        raise PackageError("Package file exceeds 16 MiB")
    return file_data, filename
