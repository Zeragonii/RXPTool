"""v1.1.6: editable text should not depend on stored plaintext offsets."""
import base64
import json
import re
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rxp_decrypt import decode_chunk, derive_base, extract_chunks, initial_permutation, xor_stream
from webapp.main import app, decode_payload
from webapp.editable_document import (
    DocumentError, is_editable_document, make_editable_document, rebuild_from_editable_document
)

client = TestClient(app)
ID = 'OriginalTest#1234'


def make_chunk(raw):
    check = zlib.adler32(raw) & 0xFFFFFFFF
    encrypted = xor_stream(zlib.compress(raw), initial_permutation(derive_base(ID)))
    return f'{check}:{base64.b64encode(encrypted).decode()}%'


def get_sample():
    guides = [
        b'#forever\n#group Custom\n#name First\nstep\n+One\n',
        b'#forever\n#group Custom\n#name Second\nstep\n+Two',
        b'#forever\n#group Custom\n#name Third\nstep\n+Three\n\n',
    ]
    raws = [b'\0' + guides[0] + b'\0\0' + guides[1] + b'\0',
            b'\0' + guides[2] + b'\0\0']
    source = 'Banner\n3|' + make_chunk(raws[0]) + '\n' + make_chunk(raws[1]) + '|40000\n'
    return source, guides, raws


def encrypt_file(data, account=ID):
    return client.post('/api/encrypt', json={
        'battle_id': account,
        'filename': 'editable_guides.txt',
        'content_base64': base64.b64encode(data).decode('ascii'),
    })


def raw_from_import(value, id=ID):
    perm = initial_permutation(derive_base(id))
    return [decode_chunk(c, perm, 16 * 1024 * 1024) for c in extract_chunks(value, None)]


def test_no_changes_are_byte_exact_and_original_header_footer_restored():
    source, guides, raws = get_sample()
    editable, count, chunk_count = make_editable_document(source, ID)
    assert is_editable_document(editable)
    assert b'#!header="Banner\\n3|"\n' in editable
    assert b'#!footer="|40000\\n"\n' in editable
    assert b'#!between="\\n"\n' in editable
    assert b'#!empty\n' in editable
    assert b'#!endguide\n' in editable
    assert b'\0' not in editable
    assert count == 3 and chunk_count == 2
    built, count2, chunk_count2, raws2 = rebuild_from_editable_document(editable, ID)
    assert count2 == count and chunk_count2 == chunk_count
    assert raws2 == raws == raw_from_import(built)
    assert built.startswith('Banner\n3|') and built.endswith('|40000\n')
    assert decode_payload(ID, built)[0] == guides


def test_editing_guide_grows_nul_locations_and_exact_guide_contents():
    source, guides, raws = get_sample()
    editable, _, _ = make_editable_document(source, ID)
    # Add a new, considerably longer step to the first guide.
    added = b'\nstep\n+This new step is a hundred characters long ' + b'X'*100
    edited = editable.replace(b'+One\n#!endguide', b'+One' + added + b'\n#!endguide', 1)
    rebuilt = encrypt_file(edited)
    assert rebuilt.status_code == 200, rebuilt.text
    assert rebuilt.headers['x-import-rebuilt'] == 'true'
    assert rebuilt.headers['x-guide-count'] == '3'
    newer_raw = raw_from_import(rebuilt.text)
    assert newer_raw[0].count(b'\0') == raws[0].count(b'\0')
    assert newer_raw[0].index(b'\0', 1) == raws[0].index(b'\0', 1) + len(added)
    assert newer_raw[1] == raws[1]
    actual = decode_payload(ID, rebuilt.text)[0]
    assert actual[0] == guides[0].replace(b'+One', b'+One' + added)
    assert actual[1:] == guides[1:]


def test_markers_allow_adding_and_deleting_whole_guides_and_recount():
    source, guides, raws = get_sample()
    editable, _, _ = make_editable_document(source, ID)
    extra = b'#!guide trailing_lf=1\n#forever\n#group Custom\n#name Fourth\nstep\n+Four\n#!endguide\n'
    edited = editable.replace(b'#!endchunk\n', extra + b'#!endchunk\n', 1)
    built, count, chunks, restored = rebuild_from_editable_document(edited, ID)
    assert count == 4 and chunks == 2
    assert built.startswith('Banner\n4|')
    assert len(decode_payload(ID, built)[0]) == 4
    removed = re.sub(rb'#!guide trailing_lf=0\n.*?#!endguide\n', b'', editable, count=1, flags=re.S)
    built, count, chunks, _ = rebuild_from_editable_document(removed, ID)
    assert count == 2 and built.startswith('Banner\n2|')


def test_wrong_id_and_bad_controls_are_rejected():
    source, _, _ = get_sample()
    editable, _, _ = make_editable_document(source, ID)
    wrong = encrypt_file(editable, 'WrongId#2222')
    assert wrong.status_code == 422
    assert 'same-account' in wrong.json()['error']
    bad = encrypt_file(editable.replace(b'#!endguide', b'#!garbage', 1))
    assert bad.status_code == 422
    assert 'Unterminated' in bad.json()['error']
    extra_nul = encrypt_file(editable + b'\0')
    assert extra_nul.status_code == 422
    assert 'NUL' in extra_nul.json()['error']


def test_windows_crlf_and_no_trailing_lf_are_accepted():
    source, guides, _ = get_sample()
    editable, _, _ = make_editable_document(source, ID)
    windows = editable.replace(b'\n', b'\r\n')
    built, count, chunk_count, raws = rebuild_from_editable_document(windows, ID)
    assert count == 3 and chunk_count == 2
    assert b'#!endguide' not in b''.join(raws)
    # The original no-final-LF guide remains a no-final-LF guide.
    assert b'#name Second\r\nstep\r\n+Two\0' in raws[0]


def test_actual_191_guide_import_roundtrip_when_available():
    matches = list(Path('/mnt/data').glob('Forever Leveling Guide - Both Factions!*'))
    original = matches[0] if matches else None
    if original is None or not original.is_file():
        pytest.skip('Real import sample not attached in this environment')
    payload = original.read_text('utf-8')
    original_id = original.name.split('!', 1)[1]
    resp = client.post('/api/decrypt', json={'battle_id': original_id, 'payload': payload, 'format': 'editable'})
    assert resp.status_code == 200, resp.text[:200]
    assert resp.headers['x-output-format'] == 'editable'
    assert int(resp.headers['x-guide-count']) == 191
    edit = resp.content
    assert b'#!guide ' in edit and b'#!empty' in edit
    result = encrypt_file(edit, original_id)
    assert result.status_code == 200, result.text[:200]
    assert result.headers['x-guide-count'] == '191'
    assert raw_from_import(result.text, original_id) == raw_from_import(payload, original_id)
    # A single, arbitrarily long additional step shifts raw NUL locations,
    # without a manifest and without corrupting any subsequent guide.
    tweak = edit.replace(b'#!endguide\n', b'step\n    +Added an extra custom step\n#!endguide\n', 1)
    changed = encrypt_file(tweak, original_id)
    assert changed.status_code == 200, changed.text[:200]
    new_guides, _ = decode_payload(original_id, changed.text)
    original_guides, _ = decode_payload(original_id, payload)
    assert len(new_guides) == len(original_guides) == 191
    assert new_guides[0] != original_guides[0]
    assert new_guides[1:] == original_guides[1:]


def test_ui_assets_and_api_format_exist():
    assert 'id="downloadEditable"' in client.get('/').text
    assert client.get('/assets/app-v1.1.6.js').status_code == 200
    assert client.get('/assets/encrypt-v1.1.6.js').status_code == 200
    assert 'Editable guide TXT' in client.get('/encrypt').text
