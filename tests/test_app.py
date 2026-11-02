"""Synthetic round-trip/API tests; no genuine paid guide payload is required."""
import base64
import io
import json
import zlib
import zipfile

from fastapi.testclient import TestClient

from rxp_decrypt import derive_base, guide_filename, initial_permutation, xor_stream
from webapp.main import app, MAX_REQUEST_BYTES

client = TestClient(app)


def encrypted(plain: bytes, account_id: str = "Tester#12345") -> str:
    compressed = zlib.compress(plain)
    encrypted_bytes = xor_stream(compressed, initial_permutation(derive_base(account_id)))
    checksum = zlib.adler32(plain) & 0xFFFFFFFF
    return f"{checksum}:{base64.b64encode(encrypted_bytes).decode()}%"


def test_health_and_ui():
    assert client.get('/health').json() == {'status': 'ok'}
    resp = client.get('/')
    assert resp.status_code == 200
    assert b'Decrypt payload' in resp.content
    assert client.get('/assets/app.css').status_code == 200
    assert client.get('/assets/app.js').status_code == 200
    assert client.get('/assets/../../etc/passwd').status_code != 200


def test_single_guide_is_exact_bytes():
    guide = b'#forever\n#group Test\n#name One\nstep\n.goto Stormwind\n'
    r = client.post('/api/decrypt', json={'battle_id': 'Tester#12345', 'payload': encrypted(guide)})
    assert r.status_code == 200, r.text
    assert r.content == guide
    assert r.headers['x-guide-count'] == '1'
    assert r.headers['x-chunk-count'] == '1'
    assert 'guide_001' in r.headers['content-disposition']


def test_two_chunks_three_guides_zip_bytes():
    guides = [
        b'#group Test\n#name Alpha\nstep\n+Alpha\n',
        b'#group Test\n#name Beta\nstep\n+Beta\n',
        b'#group Test\n#name Gamma\nstep\n+Gamma\n',
    ]
    payload = ('3|15:ABC\n' + encrypted(guides[0] + b'\x00' + guides[1]) + '\n' + encrypted(guides[2]))
    r = client.post('/api/decrypt', json={'battle_id': 'Tester#12345', 'payload': payload})
    assert r.status_code == 200, r.text
    assert r.headers['x-guide-count'] == '3'
    assert r.headers['x-chunk-count'] == '2'
    assert r.headers['content-type'] == 'application/zip'
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        assert len(z.namelist()) == 3
        assert [z.read(name) for name in z.namelist()] == guides
        assert z.namelist() == [guide_filename(g, n) for n, g in enumerate(guides, 1)]
    b64 = r.headers['x-guide-preview']
    assert len(json.loads(base64.urlsafe_b64decode(b64))) == 3


def test_wrong_id_rejected_without_plaintext():
    payload = encrypted(b'#group Test\n#name My Guide\nstep\n+abc\n')
    r = client.post('/api/decrypt', json={'battle_id': 'Wrong#12345', 'payload': payload})
    assert r.status_code == 422
    assert 'guide-count' not in r.headers
    assert 'error' in r.json()


def test_bad_input():
    assert client.post('/api/decrypt', json={'battle_id': '', 'payload': 'abc'}).status_code == 400
    assert client.post('/api/decrypt', json={'battle_id': '123', 'payload': ''}).status_code == 400
    assert client.post('/api/decrypt', content='abc', headers={'content-type':'text/plain'}).status_code == 415
    assert client.post('/api/decrypt', json={'battle_id':'x', 'payload':'not a payload'}).status_code == 422


def test_bounded_body_header():
    response = client.post('/api/decrypt', content=b'{}', headers={'content-type':'application/json', 'content-length':str(MAX_REQUEST_BYTES + 1)})
    assert response.status_code == 413


def test_payload_checksum_check():
    payload = encrypted(b'#group Test\n#name Check\nstep\n+ok\n')
    bad = '123:' + payload.split(':', 1)[1]
    response = client.post('/api/decrypt', json={'battle_id':'Tester#12345', 'payload': bad})
    assert response.status_code == 422
    assert 'checksum' in response.json()['error'].lower()


def test_explicit_combined_export_preserves_nul_guide_boundaries():
    guides = [
        b'#group Test\n#name Alpha\nstep\n+Alpha\n',
        b'#group Test\n#name Beta\nstep\n+Beta\n',
        b'#group Test\n#name Gamma\nstep\n+Gamma\n',
    ]
    payload = encrypted(guides[0] + b'\0' + guides[1]) + '\n' + encrypted(guides[2])
    response = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': payload, 'format': 'combined'
    })
    assert response.status_code == 200, response.text
    assert response.content == b'\0'.join(guides)
    assert response.headers['x-output-format'] == 'combined'
    assert response.headers['x-guide-count'] == '3'
    assert response.headers['x-chunk-count'] == '2'
    assert 'decrypted_guides.txt' in response.headers['content-disposition']
    assert response.headers['content-type'] == 'application/octet-stream'


def test_explicit_split_export_on_single_guide():
    guide = b'#group Demo\n#name First guide\nstep\n+Hello\n'
    response = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': encrypted(guide), 'format': 'split'
    })
    assert response.status_code == 200, response.text
    assert response.headers['x-guide-count'] == '1'
    assert response.headers['x-output-format'] == 'split'
    assert response.headers['content-type'] == 'application/zip'
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = archive.namelist()
        assert names == [guide_filename(guide, 1)]
        assert archive.read(names[0]) == guide


def test_format_validation():
    sample = encrypted(b'#group A\n#name B\nstep\n+hello\n')
    for value in ('unknown', '', None, 123, ['split'], {'format': 'split'}):
        response = client.post('/api/decrypt', json={
            'battle_id': 'Tester#12345', 'payload': sample, 'format': value
        })
        assert response.status_code == 400
        assert 'format' in response.json()['error'].lower()


def test_auto_format_is_backward_compatible():
    one = b'#group T\n#name One\nstep\n+Hello\n'
    two = b'#group T\n#name Two\nstep\n+Hello\n'
    single = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': encrypted(one), 'format': 'auto'
    })
    assert single.status_code == 200
    assert single.headers['x-output-format'] == 'combined'
    assert single.content == one
    multi = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': encrypted(one+b'\0'+two), 'format': 'auto'
    })
    assert multi.status_code == 200
    assert multi.headers['x-output-format'] == 'split'
    assert multi.headers['content-type'] == 'application/zip'


def test_export_selection_buttons_in_ui():
    html = client.get('/').text
    assert 'id="downloadCombined"' in html
    assert 'id="downloadSplit"' in html
    assert 'Combined plaintext' in html
    assert 'Separate guides' in html


def test_favicon_assets_reuse_header_icon():
    from xml.etree import ElementTree as ET

    homepage = client.get('/')
    assert homepage.status_code == 200
    assert b'href="/assets/favicon.svg"' in homepage.content
    assert b'src="/assets/favicon.svg"' in homepage.content
    for route, media in (
        ('/favicon.ico', 'image/x-icon'),
        ('/assets/favicon.svg', 'image/svg+xml'),
        ('/assets/favicon-32.png', 'image/png'),
        ('/assets/apple-touch-icon.png', 'image/png'),
    ):
        response = client.get(route)
        assert response.status_code == 200
        assert response.headers['content-type'].startswith(media)
        assert response.content
    root = ET.fromstring(client.get('/assets/favicon.svg').content)
    assert root.tag.endswith('svg')
    # Ensure that the original icon paths are reused, not approximated.
    path_data = {node.attrib['d'] for node in root.iter() if node.tag.endswith('path')}
    assert 'M20 3L35.5 11.5V28.5L20 37L4.5 28.5V11.5L20 3Z' in path_data
    assert 'M13 14H26L18 22H27' in path_data
    assert 'M12 27H24' in path_data
    assert client.get('/assets/unknown.png').status_code == 404


def test_versioned_asset_urls_and_strict_csp():
    """Prevent the old-JS/new-HTML mismatch observed through proxy caches."""
    import re

    page = client.get('/')
    assert page.status_code == 200
    assert 'src="/assets/app-v1.1.6.js"' in page.text
    assert 'href="/assets/app-v1.1.6.css"' in page.text
    assert 'v1.1.6' in page.text
    assert not re.search(r'<script(?![^>]*\bsrc=)', page.text, flags=re.I)
    assert "script-src 'self'" in page.headers['content-security-policy']
    assert "'unsafe-inline'" not in page.headers['content-security-policy']
    for asset, media in [('app-v1.1.6.js', 'application/javascript'), ('app-v1.1.6.css', 'text/css')]:
        response = client.get('/assets/' + asset)
        assert response.status_code == 200
        assert response.headers['content-type'].startswith(media)
        assert response.headers['cache-control'] == 'no-store'
        assert response.content == client.get('/assets/' + asset.replace('-v1.1.4', '')).content
    assert 'downloadCombined' in client.get('/assets/app-v1.1.6.js').text
    assert "missingIds" in client.get('/assets/app-v1.1.6.js').text
    assert client.get('/assets/app-v1.0.3.js').status_code == 404


def test_encrypt_page_has_separate_route_and_navigation():
    homepage = client.get('/')
    assert 'href="/encrypt"' in homepage.text
    page = client.get('/encrypt')
    assert page.status_code == 200
    assert 'id="encryptForm"' in page.text
    assert 'id="recoveryForm"' in page.text  # old .rxptool recovery is retained
    assert 'Compatible with the Decrypt page' in page.text
    assert 'src="/assets/encrypt-v1.1.6.js"' in page.text
    assert '<script>' not in page.text
    assert client.get('/assets/encrypt-v1.1.6.js').status_code == 200
    assert 'encryptGuideCount' in client.get('/assets/encrypt-v1.1.6.js').text


def _encrypt_via_api(data: bytes, filename: str = 'guides.txt', account_id: str = 'Example#1234'):
    return client.post('/api/encrypt', json={
        'battle_id': account_id, 'filename': filename,
        'content_base64': base64.b64encode(data).decode('ascii')
    })


def test_encrypt_is_reverse_of_main_decrypt_for_combined_txt():
    guides = [
        b'#group Alpha\n#name First\nstep\n+Hi\n',
        b'#group Alpha\n#name Second\nstep\n+Bye\n',
    ]
    original = b'\0'.join(guides)
    r = _encrypt_via_api(original)
    assert r.status_code == 200, r.text
    assert r.headers['x-package-verified'] == 'true'
    assert r.headers['x-guide-count'] == '2'
    assert 'encrypted_guides.txt' in r.headers['content-disposition']
    payload = r.content.decode('ascii')
    assert payload.count(':') == 1 and payload.endswith('%')
    assert not payload.startswith('RXPTENC')
    decrypted = client.post('/api/decrypt', json={
        'battle_id': 'example#1234', 'payload': payload, 'format': 'combined'
    })
    assert decrypted.status_code == 200, decrypted.text
    assert decrypted.content == original
    split = client.post('/api/decrypt', json={
        'battle_id': 'Example#1234', 'payload': payload, 'format': 'split'
    })
    assert split.status_code == 200
    with zipfile.ZipFile(io.BytesIO(split.content)) as result:
        assert [result.read(x) for x in result.namelist()] == guides


def test_encrypt_reverses_main_decrypt_for_split_zip():
    originals = [b'#group Test\n#name A\nstep\n+First\n', b'#group Test\n#name B\nstep\n+Second\n']
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        for i, data in enumerate(originals, 1):
            archive.writestr(f'guide_{i:03}.txt', data)
    result = _encrypt_via_api(buf.getvalue(), 'split-guides.zip')
    assert result.status_code == 200, result.text
    assert result.headers['x-guide-count'] == '2'
    dec = client.post('/api/decrypt', json={
        'battle_id': 'Example#1234', 'payload': result.content.decode(), 'format': 'combined'
    })
    assert dec.status_code == 200
    assert dec.content == b'\0'.join(originals)


def test_native_encoder_rejects_wrong_id_and_tampering():
    enc = _encrypt_via_api(b'#group Demo\n#name One\nstep\n+Hi\n')
    assert enc.status_code == 200
    wrong = client.post('/api/decrypt', json={
        'battle_id': 'Wrong#1234', 'payload': enc.text, 'format': 'combined'
    })
    assert wrong.status_code == 422
    damaged = enc.text.replace(':', ':AAAA', 1)
    fail = client.post('/api/decrypt', json={
        'battle_id': 'Example#1234', 'payload': damaged
    })
    assert fail.status_code == 422


def test_encrypt_normalises_nul_boundaries_and_preserves_guides():
    data = b'\0\0#group A\n#name B\nstep\n+one\n\0\0#group A\n#name C\nstep\n+two\n\0'
    enc = _encrypt_via_api(data)
    assert enc.status_code == 200
    dec = client.post('/api/decrypt', json={'battle_id': 'Example#1234', 'payload': enc.text, 'format': 'combined'})
    assert dec.content == b'#group A\n#name B\nstep\n+one\n\0#group A\n#name C\nstep\n+two\n'


def test_encrypt_rejects_invalid_input_zip_bombs_and_oversized_content():
    assert client.post('/api/encrypt', json={'battle_id':'', 'content_base64':base64.b64encode(b'abc').decode()}).status_code == 400
    assert client.post('/api/encrypt', json={'battle_id':'abc', 'content_base64':'!!'}).status_code == 400
    assert client.post('/api/encrypt', content='data', headers={'content-type':'text/plain'}).status_code == 415
    assert _encrypt_via_api(b'bad zip data', 'some.zip').status_code == 422
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('guide_001.txt', b'X' * (16 * 1024 * 1024 + 1))
    assert _encrypt_via_api(buf.getvalue(), 'bomb.zip').status_code == 422
    assert _encrypt_via_api(b'\0\0').status_code == 422


def test_legacy_package_recovery_remains_available():
    from webapp.package_crypto import encrypt_package
    original = b'legacy old-style encrypted content'
    package = encrypt_package(original, 'Example#1234', 'old.txt')
    dec = client.post('/api/open-package', json={
        'battle_id': 'Example#1234', 'filename': 'guide.rxptool',
        'content_base64': base64.b64encode(package).decode()
    })
    assert dec.status_code == 200
    assert dec.content == original
    assert 'old.txt' in dec.headers['content-disposition']


def test_native_cipher_inverse_with_randomized_synthetic_data():
    from webapp.native_encrypt import encrypt_payload
    from rxp_decrypt import extract_chunks, decode_chunk
    import os
    for size in (1, 127, 4097, 65536):
        # Byte samples are structurally opaque, while the Decrypt page exposes nonempty NUL chunks.
        plaintext = os.urandom(size).replace(b'\x00', b'A')
        encoded = encrypt_payload(plaintext, 'Demo#789')
        chunk = extract_chunks(encoded, None)[0]
        decoded = decode_chunk(chunk, initial_permutation(derive_base('Demo#789')), 17 * 1024 * 1024)
        assert decoded == plaintext


def test_package_crypto_legacy_unit_rejects_truncated_and_wrong_format():
    from webapp.package_crypto import encrypt_package, decrypt_package, PackageError
    import pytest
    content = b'a' * 500000
    package = encrypt_package(content, 'example#1', 'a.txt')
    assert decrypt_package(package, 'example#1') == (content, 'a.txt')
    for invalid in (package[:12], b'not a package' * 8):
        with pytest.raises(PackageError):
            decrypt_package(invalid, 'example#1')
    with pytest.raises(PackageError):
        encrypt_package(b'a' * (16 * 1024 * 1024 + 1), 'example#1', 'a.txt')


def _bundle_for(payload: str, identifier: str = 'Tester#12345'):
    return client.post('/api/decrypt', json={
        'battle_id': identifier, 'payload': payload, 'format': 'bundle'
    })


def _restore_bundle(archive: bytes, identifier: str = 'Tester#12345'):
    return client.post('/api/encrypt', json={
        'battle_id': identifier, 'filename': 'rxptool_import_bundle.zip',
        'content_base64': base64.b64encode(archive).decode('ascii')
    })


def _rewrite_zip(data: bytes, filename: str, replacement: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            zout.writestr(name, replacement if name == filename else zin.read(name))
    return output.getvalue()


def test_lossless_bundle_recovers_identical_multi_chunk_original_import():
    guides = [
        b'#group A\n#name One\nstep\n+one\n',
        b'#group A\n#name Two\nstep\n+two\n',
        b'#group A\n#name Three\nstep\n+three\n',
    ]
    # Header, footer, arbitrary line breaks and chunk boundaries are preserved.
    payload = '\n3|' + encrypted(guides[0] + b'\0\0' + guides[1] + b'\0') + '\n' + encrypted(guides[2]) + '|40000\n'
    bundle = _bundle_for(payload)
    assert bundle.status_code == 200, bundle.text
    assert bundle.headers['x-output-format'] == 'bundle'
    assert bundle.headers['x-chunk-count'] == '2'
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
        manifest = json.loads(archive.read('manifest.json'))
        assert manifest['schema_version'] == 1
        assert manifest['source']['import_version'] == 40000
        assert manifest['source']['declared_guide_count'] == 3
        assert manifest['guides']['count'] == 3
        assert len(manifest['chunks']) == 2
        assert archive.read('decrypted_guides.txt') == b'\0'.join(guides)
        assert archive.read('chunks/chunk_001.bin') == guides[0] + b'\0\0' + guides[1] + b'\0'
        assert archive.read('original_payload.txt') == payload.encode()
        assert b'Tester#12345' not in archive.read('manifest.json')
    restored = _restore_bundle(bundle.content)
    assert restored.status_code == 200, restored.text
    assert restored.headers['x-payload-restored'] == 'exact'
    assert restored.content == payload.encode()
    # The normal decoder can still recover it with no modifications.
    dec = client.post('/api/decrypt', json={'battle_id': 'Tester#12345', 'payload': restored.text, 'format': 'combined'})
    assert dec.status_code == 200
    assert dec.content == b'\0'.join(guides)


def test_lossless_bundle_rejects_wrong_id_and_tampered_plaintext():
    payload = encrypted(b'#group Demo\n#name One\nstep\n+test\n')
    original = _bundle_for(payload)
    assert original.status_code == 200
    wrong = _restore_bundle(original.content, 'Wrong#55555')
    assert wrong.status_code == 422
    assert 'original id' in wrong.json()['error'].lower()
    altered = _rewrite_zip(original.content, 'decrypted_guides.txt', b'not the original content')
    failed = _restore_bundle(altered)
    assert failed.status_code == 422
    assert 'modified' in failed.json()['error'].lower()


def test_lossless_bundle_rejects_modified_original_ciphertext():
    payload = encrypted(b'#group Demo\n#name One\nstep\n+test\n')
    original = _bundle_for(payload)
    assert original.status_code == 200
    altered = _rewrite_zip(original.content, 'original_payload.txt', b'invalid')
    failed = _restore_bundle(altered)
    assert failed.status_code == 422
    assert 'modified' in failed.json()['error'].lower()


def test_lossless_bundle_does_not_change_existing_download_modes():
    guide = b'#group Demo\n#name One\nstep\n+test\n'
    payload = encrypted(guide)
    combined = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': payload, 'format': 'combined'
    })
    assert combined.status_code == 200
    assert combined.content == guide
    separate = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': payload, 'format': 'split'
    })
    assert separate.status_code == 200
    assert separate.headers['x-output-format'] == 'split'
    assert b'downloadBundle' in client.get('/assets/app-v1.1.6.js').content
    assert 'id="downloadBundle"' in client.get('/').text
    assert 'metadata archive' in client.get('/encrypt').text


def test_standalone_manifest_preserves_header_footer_and_all_nuls():
    raw_one = b"\0#group A\n#name First\nstep\n+first\n\0\0#group A\n#name Second\nstep\n+second\n\0"
    raw_two = b"#group A\n#name Third\nstep\n+third\n\0\0"
    payload = "\n3|" + encrypted(raw_one) + " \n" + encrypted(raw_two) + "|40000\n"
    result = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': payload, 'format': 'manifest'
    })
    assert result.status_code == 200, result.text
    assert 'layout.json' in result.headers['content-disposition']
    metadata = result.json()
    assert metadata['schema'] == 'rxptool-edit-layout'
    assert metadata['header'] == '\n3|'
    assert metadata['footer'] == '|40000\n'
    assert metadata['inter_chunk_text'] == [' \n']
    assert metadata['guide_count'] == 3
    assert metadata['chunks'][0]['nul_byte_offsets_0_based'] == [i for i, b in enumerate(raw_one) if b == 0]
    assert metadata['chunks'][1]['nul_byte_offsets_0_based'] == [i for i, b in enumerate(raw_two) if b == 0]
    assert 'payload_sha256' not in metadata
    assert 'combined_sha256' not in metadata
    assert 'plaintext_sha256' not in str(metadata)
    assert b'Tester#12345' not in result.content
    archive = _bundle_for(payload)
    assert archive.status_code == 200, archive.text
    with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
        # Legacy archival manifest deliberately retains its original structure.
        archive_manifest = json.loads(zf.read('manifest.json'))
        assert archive_manifest['schema'] == 'rxptool-import-archive'
    restored = _restore_bundle(archive.content)
    assert restored.status_code == 200, restored.text
    assert restored.content.decode() == payload


def test_raw_chunk_manifest_does_not_invent_header_footer():
    data = b'#group Test\n#name Solo\nstep\n+hello\n'
    result = client.post('/api/decrypt', json={
        'battle_id': 'Tester#12345', 'payload': encrypted(data), 'format': 'manifest'
    })
    assert result.status_code == 200
    meta = result.json()
    assert meta['header'] is None
    assert meta['footer'] is None
    assert meta['guide_count'] == 1
    assert meta['chunks'][0]['nul_byte_offsets_0_based'] == []


def test_manifest_ui_and_asset_route():
    home = client.get('/').text
    assert 'id="downloadManifest"' in home
    assert 'Headers, footer' in home
    app_js = client.get('/assets/app-v1.1.6.js')
    assert app_js.status_code == 200
    assert 'downloadFormat(\'manifest\')' in app_js.text


def test_archive_detects_altered_offsets_and_literal_framing():
    raw = b'\0#group A\n#name B\nstep\n+hi\n\0\0'
    payload = '1|' + encrypted(raw) + '|40000'
    orig = _bundle_for(payload)
    assert orig.status_code == 200
    with zipfile.ZipFile(io.BytesIO(orig.content)) as zf:
        manifest = json.loads(zf.read('manifest.json'))
    manifest['chunks'][0]['nul_byte_offsets_0_based'] = [1,2]
    tampered = _rewrite_zip(orig.content, 'manifest.json', json.dumps(manifest).encode())
    response = _restore_bundle(tampered)
    assert response.status_code == 422
    assert 'nul separator' in response.json()['error'].lower()
    manifest['chunks'][0]['nul_byte_offsets_0_based'] = [i for i, b in enumerate(raw) if b == 0]
    manifest['source']['framing']['header']['raw'] = '2|'
    response = _restore_bundle(_rewrite_zip(orig.content, 'manifest.json', json.dumps(manifest).encode()))
    assert response.status_code == 422
    assert 'header/footer' in response.json()['error'].lower()
