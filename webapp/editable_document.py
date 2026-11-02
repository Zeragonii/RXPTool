"""Self-contained, editable guide documents. No byte offsets or saved ciphertext.

A document holds the original account *key fingerprint*, visible framing and
literal guide slots; empty slots replace original NUL separators. Changing the
length of any guide doesn't affect parsing or separator reconstruction.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import zlib

from rxp_decrypt import CHUNK_RE, decode_chunk, derive_base, extract_chunks, initial_permutation, xor_stream
from webapp.import_bundle import original_framing

MAGIC = b'#!RXPTOOL/1\n'


def is_editable_document(data: bytes) -> bool:
    # Editors that add a UTF-8 BOM are accepted without changing guide data.
    clean = data[3:] if data.startswith(b'\xef\xbb\xbf') else data
    return clean.startswith(MAGIC) or clean.startswith(b'#!RXPTOOL/1\r\n')
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_CHUNKS = 512
MAX_GUIDES = 1000
MAX_FRAMING = 256 * 1024
MAX_OUTPUT_BYTES = 24 * 1024 * 1024


class DocumentError(ValueError):
    pass


def _line(data: bytes, offset: int) -> tuple[bytes, int]:
    end = data.find(b'\n', offset)
    if end < 0:
        raise DocumentError('Document is truncated or lacks a final newline')
    line = data[offset:end]
    if line.endswith(b'\r'):
        line = line[:-1]
    if len(line) > MAX_FRAMING:
        raise DocumentError('An editable document directive is too long')
    return line, end + 1


def _json_line(label: bytes, value: object) -> bytes:
    return label + json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n'


def make_editable_document(payload: str, account_id: str, max_plaintext_bytes: int = MAX_DOCUMENT_BYTES) -> tuple[bytes, int, int]:
    """Decode every *raw* chunk, preserving leading, trailing & repeated NUL slots."""
    framing = original_framing(payload)
    if framing['input_kind'] != 'framed-import':
        raise DocumentError('Editable TXT requires an import with its original header and footer')
    head, foot = framing['header']['raw'], framing['footer']['raw']
    between = framing['inter_chunk_text']
    if not isinstance(head, str) or not isinstance(foot, str) or not isinstance(between, list):
        raise DocumentError('Invalid native import framing')
    chunks = extract_chunks(payload, None)
    if not 1 <= len(chunks) <= MAX_CHUNKS or len(between) != len(chunks) - 1:
        raise DocumentError('Unsupported import chunk layout')
    perm = initial_permutation(derive_base(account_id))
    out = [MAGIC,
           _json_line(b'#!header=', head),
           _json_line(b'#!footer=', foot),
           _json_line(b'#!account_key_fingerprint=', hashlib.sha256(derive_base(account_id)).hexdigest())]
    total = 0
    count = 0
    for idx, chunk in enumerate(chunks):
        if chunk.checksum is None:
            raise DocumentError('Only native checksum-prefixed chunks are supported in editable TXT')
        raw = decode_chunk(chunk, perm, max_plaintext_bytes - total)
        total += len(raw)
        if total > max_plaintext_bytes:
            raise DocumentError('Decoded guide document exceeds 16 MiB')
        if idx:
            out.append(_json_line(b'#!between=', between[idx - 1]))
        out.append(b'#!chunk\n')
        for item in raw.split(b'\x00'):
            if not item:
                out.append(b'#!empty\n')
                continue
            count += 1
            if count > MAX_GUIDES:
                raise DocumentError('Too many guides for an editable document')
            # A marker on its own line is deliberately reserved. Guard against
            # ambiguous source text rather than silently corrupting a guide.
            if re.search(rb'(?m)^#!endguide\r?$', item):
                raise DocumentError('A guide contains a reserved #!endguide line')
            trailing = item.endswith(b'\n')
            out.append(b'#!guide trailing_lf=' + (b'1' if trailing else b'0') + b'\n')
            out.append(item)
            if not trailing:
                out.append(b'\n')  # delimiter for a guide with no final LF
            out.append(b'#!endguide\n')
        out.append(b'#!endchunk\n')
    out.append(b'#!end\n')
    data = b''.join(out)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise DocumentError('Editable document exceeds 16 MiB')
    return data, count, len(chunks)


def rebuild_from_editable_document(document: bytes, account_id: str) -> tuple[str, int, int, list[bytes]]:
    """Parse a user-edited TXT and freshly encrypt raw chunks for the SAME ID.

    Returns (framed import, guide count, chunk count, original guide contents).
    The header guide count is recalculated. Each #!empty marks an empty NUL
    slot; no byte offsets are used. The exact original encrypted data isn't read.
    """
    if not is_editable_document(document) or len(document) > MAX_DOCUMENT_BYTES:
        raise DocumentError('Expected a #!RXPTOOL/1 editable TXT (16 MiB maximum)')
    if b'\x00' in document:
        raise DocumentError('Editable TXT must use #!guide and #!empty markers instead of raw NUL bytes')
    _, pos = _line(document, 3 if document.startswith(b'\xef\xbb\xbf') else 0)
    def read_setting(key: bytes) -> object:
        nonlocal pos
        line, pos = _line(document, pos)
        if not line.startswith(key):
            raise DocumentError('Expected document field ' + key.decode('ascii'))
        try:
            return json.loads(line[len(key):].decode('ascii'))
        except (ValueError, UnicodeError) as exc:
            raise DocumentError('Invalid JSON for ' + key.decode('ascii')) from exc

    header = read_setting(b'#!header=')
    footer = read_setting(b'#!footer=')
    fingerprint = read_setting(b'#!account_key_fingerprint=')
    if not isinstance(fingerprint, str) or fingerprint != hashlib.sha256(derive_base(account_id)).hexdigest():
        raise DocumentError('ID does not match the original document account; same-account reconstruction only')
    if not isinstance(header, str) or not re.fullmatch(r'\D*\d+\|', header) or not isinstance(footer, str) or not re.fullmatch(r'\|\d+\D*', footer):
        raise DocumentError('The stored import header/footer is not valid')
    between = []
    raw_chunks = []
    guide_count = 0
    while True:
        line, next_pos = _line(document, pos)
        if line == b'#!end':
            if next_pos != len(document):
                raise DocumentError('Unexpected content following #!end')
            pos = next_pos
            break
        if raw_chunks:
            if not line.startswith(b'#!between='):
                raise DocumentError('Expected #!between metadata between chunks')
            try:
                middle = json.loads(line[len(b'#!between='):].decode('ascii'))
            except (ValueError, UnicodeError) as exc:
                raise DocumentError('Invalid #!between JSON') from exc
            if not isinstance(middle, str):
                raise DocumentError('Invalid #!between value')
            between.append(middle)
            pos = next_pos
            line, next_pos = _line(document, pos)
        if line != b'#!chunk':
            raise DocumentError('Expected #!chunk or #!end')
        pos = next_pos
        slots: list[bytes] = []
        while True:
            line, next_pos = _line(document, pos)
            if line == b'#!endchunk':
                pos = next_pos
                break
            if line == b'#!empty':
                slots.append(b'')
                pos = next_pos
            elif line in (b'#!guide trailing_lf=0', b'#!guide trailing_lf=1'):
                trailing = line.endswith(b'1')
                body_start = next_pos
                # The only control sequence inside a guide is a dedicated
                # marker line. The rest stays byte-for-byte editable text.
                marker = re.search(rb'(?m)^#!endguide\r?\n', document[body_start:])
                if not marker:
                    raise DocumentError('Unterminated #!guide block')
                body_end = body_start + marker.start()
                body = document[body_start:body_end]
                if re.search(rb'(?m)^#!(?:guide(?:\s|$)|empty\r?$|chunk\r?$|endchunk\r?$|end\r?$)', body):
                    raise DocumentError('Unterminated #!guide block or nested control directive')
                if not body.endswith(b'\n'):
                    raise DocumentError('The #!endguide marker must be on a separate line')
                if not trailing:
                    body = body[:-1]
                    if body.endswith(b'\r'):
                        body = body[:-1]
                if not body:
                    raise DocumentError('An empty guide should use #!empty instead')
                slots.append(body)
                guide_count += 1
                if guide_count > MAX_GUIDES:
                    raise DocumentError('Too many guides (maximum 1000)')
                pos = body_start + marker.end()
            else:
                raise DocumentError('Unexpected directive in a chunk: ' + line[:80].decode('ascii', 'replace'))
            if len(slots) > MAX_GUIDES + 1000:
                raise DocumentError('Too many guide/empty slots in one chunk')
        if not slots:
            raise DocumentError('Empty #!chunk is not allowed')
        raw = b'\x00'.join(slots)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise DocumentError('A chunk exceeds 16 MiB')
        raw_chunks.append(raw)
        if len(raw_chunks) > MAX_CHUNKS:
            raise DocumentError('Too many chunks')
    if not raw_chunks or not guide_count:
        raise DocumentError('Document contains no nonempty guides')
    if sum(len(x) for x in raw_chunks) > MAX_DOCUMENT_BYTES:
        raise DocumentError('Guide data exceeds 16 MiB')
    if len(header) + len(footer) + sum(len(s) for s in between) > MAX_FRAMING:
        raise DocumentError('Import framing is too large')
    # Keep the header syntax but calculate the count from live guide markers.
    head = re.sub(r'\d+\|$', str(guide_count) + '|', header)
    perm = initial_permutation(derive_base(account_id))
    chunks = []
    for raw in raw_chunks:
        checksum = zlib.adler32(raw) & 0xffffffff
        encoded = xor_stream(zlib.compress(raw, 6), perm)
        chunks.append(f'{checksum}:{base64.b64encode(encoded).decode("ascii")}%')
    result = head + chunks[0] + ''.join(middle + token for middle, token in zip(between, chunks[1:])) + footer
    if len(result.encode('utf-8')) > MAX_OUTPUT_BYTES or len(CHUNK_RE.findall(result)) != len(chunks):
        raise DocumentError('Rebuilt native import exceeds limits or has ambiguous framing')
    return result, guide_count, len(chunks), raw_chunks
