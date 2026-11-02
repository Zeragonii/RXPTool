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
    assert 'src="/assets/app-v1.1.0.js"' in page.text
    assert 'href="/assets/app-v1.1.0.css"' in page.text
    assert 'v1.1.0' in page.text
    assert not re.search(r'<script(?![^>]*\bsrc=)', page.text, flags=re.I)
    assert "script-src 'self'" in page.headers['content-security-policy']
    assert "'unsafe-inline'" not in page.headers['content-security-policy']
    for asset, media in [('app-v1.1.0.js', 'application/javascript'), ('app-v1.1.0.css', 'text/css')]:
        response = client.get('/assets/' + asset)
        assert response.status_code == 200
        assert response.headers['content-type'].startswith(media)
        assert response.headers['cache-control'] == 'no-store'
        assert response.content == client.get('/assets/' + asset.replace('-v1.1.0', '')).content
    assert 'downloadCombined' in client.get('/assets/app-v1.1.0.js').text
    assert "missingIds" in client.get('/assets/app-v1.1.0.js').text
    assert client.get('/assets/app-v1.0.3.js').status_code == 404


def test_encrypt_page_has_separate_route_and_navigation():
    homepage = client.get('/')
    assert 'href="/encrypt"' in homepage.text
    encrypt_page = client.get('/encrypt')
    assert encrypt_page.status_code == 200
    assert 'id="encryptForm"' in encrypt_page.text
    assert 'id="recoveryForm"' in encrypt_page.text
    assert '.rxptool' in encrypt_page.text
    assert 'not</strong> RestedXP import strings' in encrypt_page.text
    assert 'src="/assets/encrypt-v1.1.0.js"' in encrypt_page.text
    assert '<script>' not in encrypt_page.text
    assert client.get('/assets/encrypt-v1.1.0.js').status_code == 200
    assert 'encryptForm' in client.get('/assets/encrypt-v1.1.0.js').text


def test_new_format_roundtrip_preserves_combined_guides_and_filename():
    """Encrypted RXPTool format is intentionally NOT a native RXP import string."""
    original = (b'#group Alpha\n#name First\nstep\n+Hi\n\0'
                b'#group Alpha\n#name Second\nstep\n+Bye\n\0\0')
    encoded = base64.b64encode(original).decode('ascii')
    encrypt_response = client.post('/api/encrypt', json={
        'battle_id': 'Example#1234', 'filename': 'my guides.txt', 'content_base64': encoded
    })
    assert encrypt_response.status_code == 200, encrypt_response.text
    assert encrypt_response.content.startswith(b'RXPTENC\x01')
    assert encrypt_response.content != original
    assert encrypt_response.headers['x-package-verified'] == 'true'
    assert 'encrypted_guide.rxptool' in encrypt_response.headers['content-disposition']
    assert b'#group Alpha' not in encrypt_response.content
    reopen = client.post('/api/open-package', json={
        'battle_id': 'Example#1234', 'filename': 'encrypted_guide.rxptool',
        'content_base64': base64.b64encode(encrypt_response.content).decode('ascii')
    })
    assert reopen.status_code == 200, reopen.text
    assert reopen.content == original
    assert 'my guides.txt' in reopen.headers['content-disposition']


def test_new_format_zip_roundtrip_without_modifying_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('first.txt', b'hello')
        archive.writestr('second.txt', b'\0quoted')
    original = buf.getvalue()
    enc = client.post('/api/encrypt', json={
        'battle_id': 'Person#987', 'filename': 'separate-guides.zip',
        'content_base64': base64.b64encode(original).decode()
    })
    assert enc.status_code == 200, enc.text
    dec = client.post('/api/open-package', json={
        'battle_id': 'person#987', 'filename': 'encrypted_guide.rxptool',
        'content_base64': base64.b64encode(enc.content).decode()
    })
    assert dec.status_code == 200, dec.text
    assert dec.content == original
    assert 'separate-guides.zip' in dec.headers['content-disposition']


def test_encryption_randomized_wrong_id_and_tamper_fail():
    request = {
        'battle_id': 'Owner#31415', 'filename': 'new.txt',
        'content_base64': base64.b64encode(b'Not a commercial guide\0hello').decode()
    }
    first = client.post('/api/encrypt', json=request)
    second = client.post('/api/encrypt', json=request)
    assert first.status_code == second.status_code == 200
    assert first.content != second.content  # unique salt and nonce
    bad_id = client.post('/api/open-package', json={
        'battle_id': 'Other#31415', 'filename': 'a.rxptool',
        'content_base64': base64.b64encode(first.content).decode()
    })
    assert bad_id.status_code == 422
    assert 'authentication failed' in bad_id.json()['error']
    tampered = bytearray(first.content)
    tampered[-1] ^= 0x1
    bad_tag = client.post('/api/open-package', json={
        'battle_id': request['battle_id'], 'filename': 'a.rxptool',
        'content_base64': base64.b64encode(tampered).decode()
    })
    assert bad_tag.status_code == 422
    assert 'authentication failed' in bad_tag.json()['error']


def test_package_api_rejects_invalid_inputs_and_native_format():
    good = base64.b64encode(b'abc').decode()
    assert client.post('/api/encrypt', json={'battle_id':'', 'content_base64':good}).status_code == 400
    assert client.post('/api/encrypt', json={'battle_id':'abc', 'content_base64':'!!'}).status_code == 400
    assert client.post('/api/encrypt', json={'battle_id':'abc', 'content_base64':''}).status_code == 400
    assert client.post('/api/encrypt', content='data', headers={'content-type':'text/plain'}).status_code == 415
    assert client.post('/api/open-package', json={
        'battle_id': 'abc', 'content_base64': base64.b64encode(b'not an RXPTool encrypted package').decode()
    }).status_code == 422
    assert client.post('/api/encrypt', json={
        'battle_id':'abc', 'filename':'../../bad.txt', 'content_base64':good
    }).status_code == 200  # filename sanitized, never used for filesystem IO


def test_package_crypto_unit_rejects_truncated_bomb_and_wrong_format():
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
