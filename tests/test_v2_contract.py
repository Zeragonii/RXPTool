"""v2 only supports self-contained editable TXT, with no legacy API paths."""
from __future__ import annotations

import base64
import zlib
from pathlib import Path
import re

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
    assert 'v2.0.3' in home.text and 'v2.0.3' in encrypt.text
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
    for name in ['app-v2.0.3.js', 'app-v2.0.3.css', 'encrypt-v2.0.3.js']:
        assert client.get('/assets/' + name).status_code == 200
    for name in ['app-v1.1.6.js', 'app-v1.1.6.css', 'encrypt-v1.1.6.js', 'app.js']:
        assert client.get('/assets/' + name).status_code == 404
    assert 'default-src' in client.get('/').headers['content-security-policy']
    assert client.get('/health').json() == {'status': 'ok', 'version': '2.0.3'}


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
    assert output.headers['content-disposition'].startswith('attachment; filename="editable_guides!UnitTest#2026_')
    assert output.headers['content-disposition'].endswith('.txt"')
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


def test_account_key_fingerprint_is_not_enforced_as_in_uploaded_project():
    doc = decrypted()
    response = encrypt_doc(doc, account='Wrong#2026')
    assert response.status_code == 200, response.text
    assert response.headers['x-package-verified'] == 'true'
    second = client.post('/api/decrypt', json={'battle_id': 'Wrong#2026', 'payload': response.text})
    assert second.status_code == 200, second.text
    assert b'#name Welcome' in second.content
    # Retain the original metadata without enforcing it on the output key.
    assert b'#!account_key_fingerprint=' in doc


def test_legacy_fingerprint_is_informational_not_an_encryption_gate():
    # Existing editable files may contain a fingerprint from another ID or
    # an arbitrarily edited fingerprint. Encryption uses the ID entered now.
    doc = decrypted()
    lines = doc.splitlines(keepends=True)
    doc_with_edited_fingerprint = b''.join(
        b'#!account_key_fingerprint="metadata-not-verified"\n'
        if line.startswith(b'#!account_key_fingerprint=') else line
        for line in lines
    )
    assert doc_with_edited_fingerprint != doc
    target_id = 'DifferentOutput#2607'
    response = encrypt_doc(doc_with_edited_fingerprint, account=target_id)
    assert response.status_code == 200, response.text
    recovered = client.post('/api/decrypt', json={
        'battle_id': target_id, 'payload': response.text,
    })
    assert recovered.status_code == 200, recovered.text
    assert b'#name Welcome' in recovered.content


def test_invalid_malformed_and_oversized_requests():
    assert client.post('/api/decrypt', content='abc',headers={'content-type':'text/plain'}).status_code == 415
    assert client.post('/api/encrypt', json={'battle_id':ACCOUNT,'content_base64':'???'}).status_code == 400
    assert client.post('/api/decrypt', json={'battle_id':ACCOUNT,'payload':'garbage'}).status_code == 422
    assert client.post('/api/encrypt',json={'battle_id':ACCOUNT,'content_base64':base64.b64encode(b'PK\x03\x04ZIP').decode()}).status_code == 400


def test_removed_modules_not_shipped():
    root = Path(__file__).resolve().parents[1]
    for name in ['import_bundle','manifest_rebuild','package_crypto','native_encrypt']:
        assert not (root / 'webapp' / (name + '.py')).exists()
    assert (root / 'VERSION').read_text().strip() == '2.1.0'


def test_decrypt_preserves_uploaded_stem_and_encrypt_names_import():
    title = 'Forever Leveling Guide - Both Factions'
    filename = title + '!Original#12345.txt'
    response = client.post('/api/decrypt', json={
        'battle_id': ACCOUNT, 'payload': encrypted_sample(),
        'source_filename': filename,
    })
    assert response.status_code == 200, response.text
    assert response.headers['content-disposition'] == f'attachment; filename="{title}.txt"'
    assert b'#!source_name="Forever Leveling Guide - Both Factions"\n' in response.content
    second_id = 'DifferentUser#2607'
    encrypted = client.post('/api/encrypt', json={
        'battle_id': second_id, 'filename': 'renamed-editable-file.txt',
        'download_timestamp': '2026-11-04_15-07',
        'content_base64': base64.b64encode(response.content).decode(),
    })
    assert encrypted.status_code == 200, encrypted.text
    assert encrypted.headers['content-disposition'] == (
        f'attachment; filename="{title}!{second_id}_2026-11-04_15-07.txt"'
    )
    assert encrypted.headers['x-package-verified'] == 'true'
    red = client.post('/api/decrypt', json={
        'battle_id': second_id, 'payload': encrypted.text,
        'source_filename': f'{title}!{second_id}_2026-11-04_15-07.txt',
    })
    assert red.status_code == 200, red.text
    assert red.headers['content-disposition'] == f'attachment; filename="{title}.txt"'
    assert b'#name Welcome' in red.content


def test_legacy_editable_document_uses_uploaded_filename():
    legacy = decrypted()  # no source title field
    assert b'#!source_name=' not in legacy
    encrypted = client.post('/api/encrypt', json={
        'battle_id': ACCOUNT,
        'filename': 'Old Guides!.txt',
        'download_timestamp': '2026-11-04_15-08',
        'content_base64': base64.b64encode(legacy).decode(),
    })
    assert encrypted.status_code == 200, encrypted.text
    assert encrypted.headers['content-disposition'] == (
        'attachment; filename="Old Guides!UnitTest#2026_2026-11-04_15-08.txt"'
    )


def test_pasted_payload_uses_generic_fallback_without_broken_name():
    pasted = client.post('/api/decrypt', json={
        'battle_id': ACCOUNT, 'payload': encrypted_sample()})
    assert pasted.status_code == 200
    assert pasted.headers['content-disposition'] == 'attachment; filename="editable_guides.txt"'
    assert b'#!source_name=' not in pasted.content


def test_windows_unfriendly_characters_removed_and_unicode_supported():
    doc = client.post('/api/decrypt', json={
        'battle_id': ACCOUNT, 'payload': encrypted_sample(),
        'source_filename': 'C:\\uploads\\CON:Guide?🔥!Old#123',
    })
    assert doc.status_code == 200, doc.text
    content_disposition = doc.headers['content-disposition']
    assert 'filename*=UTF-8' in content_disposition
    assert 'CON_Guide_%F0%9F%94%A5.txt' in content_disposition
    assert b'#!source_name=' in doc.content
    rebuilt = client.post('/api/encrypt', json={
        'battle_id': 'Name:With*Invalid\\Characters#001',
        'download_timestamp': '2026-11-04_15-09',
        'filename': 'whatever.txt',
        'content_base64': base64.b64encode(doc.content).decode(),
    })
    assert rebuilt.status_code == 200, rebuilt.text
    name = rebuilt.headers['content-disposition']
    assert 'filename*=UTF-8' in name
    assert 'Name_With_Invalid_Characters#001' in name
    assert '2026-11-04_15-09' in name
    assert not re.search(r'[<>:"\\|?*]', name.split('filename*=')[-1])


def test_windows_reserved_names_and_length_limit():
    from webapp.download_names import source_stem, encrypted_filename, safe_timestamp
    assert source_stem('CON!Someone#123') == '_CON'
    assert source_stem('HELLO.txt') == 'HELLO'
    assert source_stem('D:/a/b/HELLO!old#tag.txt') == 'HELLO'
    assert source_stem('HELLO!old#tag_2026-11-04_15-07.txt') == 'HELLO'
    name = encrypted_filename('A'*500, 'X'*500, '2026-11-04_15-07')
    assert len(name.encode()) < 240
    assert name.endswith('_2026-11-04_15-07.txt')
    assert safe_timestamp('2026-02-31_15-07') != '2026-02-31_15-07'


def test_invalid_source_metadata_is_rejected_not_silently_ignored():
    doc = client.post('/api/decrypt', json={
        'battle_id': ACCOUNT, 'payload': encrypted_sample(),
        'source_filename': 'Real Name!Account#123'
    }).content
    broken = doc.replace(b'#!source_name="Real Name"', b'#!source_name=123')
    out = encrypt_doc(broken)
    assert out.status_code == 422, out.text
    assert 'Invalid #!source_name' in out.text


def test_optional_editor_to_publisher_navigation_is_explicit_and_safe(monkeypatch):
    monkeypatch.delenv("RXP_PORTAL_ADMIN_URL", raising=False)
    for route in ("/", "/encrypt"):
        response = client.get(route)
        assert response.status_code == 200
        assert "{{RXP_PUBLISHER_LINK}}" not in response.text
        assert ">Publishing</a>" not in response.text

    destination = "http://192.168.1.20:8788/admin/publish"
    monkeypatch.setenv("RXP_PORTAL_ADMIN_URL", destination)
    for route in ("/", "/encrypt"):
        response = client.get(route)
        assert response.status_code == 200
        assert f'href="{destination}"' in response.text
        assert 'rel="noopener noreferrer"' in response.text
        assert ">Publishing</a>" in response.text

    for unsafe in ("javascript:alert(1)", "https://evil.example/?next=javascript:alert(1)",
                   "https://example.com@evil.example/secret", "https://example.com/#secret",
                   "https://admin.example/extra", "not-a-url"):
        monkeypatch.setenv("RXP_PORTAL_ADMIN_URL", unsafe)
        assert ">Publishing</a>" not in client.get("/").text
        assert ">Publishing</a>" not in client.get("/encrypt").text
