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
