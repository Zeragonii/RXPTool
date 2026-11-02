"""v2 only supports self-contained editable TXT, with no legacy API paths."""
from __future__ import annotations

import base64
import json
import re
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rxp_decrypt import derive_base, initial_permutation, xor_stream
from webapp import main

client = TestClient(main.app)
ACCOUNT = 'UnitTest#2026'


def encrypted_sample() -> str:
    raw = b'\0#retail\n#group Demo\n#name Welcome\nstep\n+Hello\n\0'
    crc = zlib.adler32(raw) & 0xffffffff
    compressed = zlib.compress(raw)
    cipher = xor_stream(compressed, initial_permutation(derive_base(ACCOUNT)))
    return f'1|{crc}:{base64.b64encode(cipher).decode()}%|40000'


def decrypted() -> bytes:
    response = client.post('/api/decrypt', json={'battle_id': ACCOUNT, 'payload': encrypted_sample()})
    assert response.status_code == 200, response.text
    assert response.headers['x-output-format'] == 'editable'
    return response.content


def encrypt_doc(doc: bytes, account: str = ACCOUNT):
    return client.post('/api/encrypt', json={'battle_id': account,
        'content_base64': base64.b64encode(doc).decode()})


def test_v2_screens_have_one_export_no_legacy_controls():
    home = client.get('/')
    encrypt = client.get('/encrypt')
    assert home.status_code == encrypt.status_code == 200
    assert 'id="downloadEditable"' in home.text
    assert 'id="downloadCombined"' not in home.text
    assert 'id="downloadSplit"' not in home.text
    assert 'id="downloadManifest"' not in home.text
    assert 'id="downloadBundle"' not in home.text
    assert 'id="encryptManifest"' not in encrypt.text
    assert 'id="recoveryForm"' not in encrypt.text
    assert 'id="recoverSubmit"' not in encrypt.text
    assert 'v2.0.0' in home.text and 'v2.0.0' in encrypt.text
    assert 'RXP <strong>Tool</strong>' in home.text
    assert 'RXP <strong>Tool</strong>' in encrypt.text
    assert '{{RXP_HEADLINE}}' not in home.text
    assert '{{RXP_HEADLINE}}' not in encrypt.text
    assert 'Guides, unlocked into plaintext.' in home.text
    assert 'Guides, unlocked into plaintext.' in encrypt.text


def test_headline_plaintext_html_escape_and_empty_fallback(monkeypatch):
    monkeypatch.setattr(main, 'HEADLINE', '<script>alert("bad")</script>')
    response = client.get('/')
    assert '<script>' not in response.text
    assert '&lt;script&gt;' in response.text
    assert 'alert(&quot;bad&quot;)' in response.text
    response = client.get('/encrypt')
    assert '&lt;script&gt;' in response.text


def test_only_v2_asset_names_exist():
    for name in ['app-v2.0.0.js', 'app-v2.0.0.css', 'encrypt-v2.0.0.js']:
        assert client.get('/assets/' + name).status_code == 200
    for name in ['app-v1.1.6.js', 'app-v1.1.6.css', 'encrypt-v1.1.6.js', 'app.js']:
        assert client.get('/assets/' + name).status_code == 404
    assert 'default-src' in client.get('/').headers['content-security-policy']
    assert client.get('/health').json() == {'status': 'ok', 'version': '2.0.0'}


def test_removed_endpoints_not_exposed():
    for endpoint in ['/api/rebuild', '/api/open-package']:
        assert client.post(endpoint, json={}).status_code == 404
    for format in ['combined', 'split', 'manifest', 'bundle', 'auto']:
        r = client.post('/api/decrypt', json={'battle_id': ACCOUNT, 'payload': encrypted_sample(), 'format': format})
        assert r.status_code == 400
        assert 'Only Editable guide TXT' in r.text


def test_editable_is_the_only_accepted_input_and_round_trip():
    original = encrypted_sample()
    response = client.post('/api/decrypt', json={'battle_id':ACCOUNT,'payload':original})
    assert response.status_code == 200, response.text
    assert response.headers['content-disposition'].endswith('"editable_guides.txt"')
    assert response.headers['x-guide-count'] == '1'
    doc = response.content
    assert doc.startswith(b'#!RXPTOOL/1\n')
    assert b'#!guide ' in doc
    invalid = encrypt_doc(b'#group Demo\n#name Demo\nstep\n+Hi\n')
    assert invalid.status_code == 400
    output = encrypt_doc(doc)
    assert output.status_code == 200, output.text
    assert output.headers['x-guide-count'] == '1'
    assert output.headers['x-package-verified'] == 'true'
    assert output.headers['content-disposition'].endswith('"rebuilt_import.txt"')
    resp = client.post('/api/decrypt', json={'battle_id':ACCOUNT,'payload':output.text})
    assert resp.status_code == 200
    assert resp.content == doc


def test_edit_reencrypt_and_recount():
    doc = decrypted()
    changed = doc.replace(b'+Hello\n#!endguide\n', b'+Hello\nstep\n+New step\n#!endguide\n')
    assert changed != doc
    result = encrypt_doc(changed)
    assert result.status_code == 200, result.text
    second = client.post('/api/decrypt', json={'battle_id':ACCOUNT,'payload':result.text})
    assert second.status_code == 200
    assert b'+New step' in second.content
    assert second.headers['x-guide-count'] == '1'


def test_wrong_account_rejected():
    doc = decrypted()
    response = encrypt_doc(doc, account='Wrong#2026')
    assert response.status_code == 422
    assert 'same-account' in response.text or 'original document account' in response.text


def test_invalid_malformed_and_oversized_requests():
    assert client.post('/api/decrypt', content='abc',headers={'content-type':'text/plain'}).status_code == 415
    assert client.post('/api/encrypt', json={'battle_id':ACCOUNT,'content_base64':'???'}).status_code == 400
    assert client.post('/api/decrypt', json={'battle_id':ACCOUNT,'payload':'garbage'}).status_code == 422
    assert client.post('/api/encrypt',json={'battle_id':ACCOUNT,'content_base64':base64.b64encode(b'PK\x03\x04ZIP').decode()}).status_code == 400


def test_removed_modules_not_shipped():
    root = Path(__file__).resolve().parents[1]
    for name in ['import_bundle','manifest_rebuild','package_crypto','native_encrypt']:
        assert not (root / 'webapp' / (name + '.py')).exists()
    assert (root / 'VERSION').read_text().strip() == '2.0.0'
