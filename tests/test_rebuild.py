"""Rebuild full import from standalone manifest + edited TXT, no saved ciphertext."""
import base64
import json
import zlib

from fastapi.testclient import TestClient

from rxp_decrypt import derive_base, extract_chunks, decode_chunk, initial_permutation, xor_stream
from webapp.main import app, decode_payload
from webapp.import_bundle import build_import_manifest

client = TestClient(app)
ID = 'OwnedTest#1234'


def encrypt_chunk(raw):
    checksum = zlib.adler32(raw) & 0xffffffff
    encrypted = xor_stream(zlib.compress(raw), initial_permutation(derive_base(ID)))
    return f'{checksum}:{base64.b64encode(encrypted).decode("ascii")}%'


def fixture():
    guides = [b'#forever\n#group T\n#name One\nstep\n+Hello\n',
              b'#forever\n#group T\n#name Two\nstep\n+Hi\n',
              b'#forever\n#group T\n#name Three\nstep\n+Bye\n']
    raw1 = b'\x00' + guides[0] + b'\x00\x00' + guides[1] + b'\x00'
    raw2 = b'\x00' + guides[2] + b'\x00\x00'
    source = 'RXP\n3|' + encrypt_chunk(raw1) + '\n' + encrypt_chunk(raw2) + '|40000\n'
    decoded, chunks = decode_payload(ID, source)
    assert decoded == guides and chunks == 2
    manifest = build_import_manifest(source, ID, decoded, max_output_bytes=16 * 1024 * 1024, max_chunks=512)
    return source, guides, raw1, raw2, manifest


def call(manifest, plain, account_id=ID):
    return client.post('/api/rebuild', json={
        'battle_id': account_id,
        'manifest_base64': base64.b64encode(manifest).decode(),
        'content_base64': base64.b64encode(plain).decode(),
    })


def test_changed_guides_rebuilt_from_framing_and_recheck_via_original_decoder():
    source, guides, r1, r2, manifest = fixture()
    changed = [g.replace(b'+Hello', b'+Edited hello world!') for g in guides]
    changed[2] = changed[2].replace(b'+Bye', b'+An edited ending')
    r = call(manifest, b'\0'.join(changed))
    assert r.status_code == 200, r.text
    assert r.headers['x-import-rebuilt'] == 'true'
    assert r.headers['x-source-plaintext-edited'] == 'unknown'  # No source hashes in lean layout
    output = r.text
    assert output != source
    assert output.startswith('RXP\n3|') and output.endswith('|40000\n')
    assert '\n' in output
    assert len(extract_chunks(output, None)) == 2
    recovered, chunks = decode_payload(ID, output)
    assert recovered == changed and chunks == 2
    transformed = [decode_chunk(c, initial_permutation(derive_base(ID)), 16*1024*1024) for c in extract_chunks(output, None)]
    assert transformed[0] == b'\0' + changed[0] + b'\0\0' + changed[1] + b'\0'
    assert transformed[1] == b'\0' + changed[2] + b'\0\0'


def test_wrong_id_is_rejected():
    _, guides, _, _, manifest = fixture()
    r = call(manifest, b'\0'.join(guides), 'Another#4444')
    assert r.status_code == 422
    assert 'fingerprint' in r.json()['error']


def test_guide_count_cannot_change():
    _, guides, _, _, manifest = fixture()
    r = call(manifest, b'\0'.join(guides[:2]))
    assert r.status_code == 422
    assert 'count' in r.json()['error'].lower()


def test_malformed_manifest_cannot_generate_fake_header():
    _, guides, _, _, manifest = fixture()
    obj = json.loads(manifest)
    obj['header'] = 'BROKEN'
    r = call(json.dumps(obj).encode(), b'\0'.join(guides))
    assert r.status_code == 422
    assert 'header' in r.json()['error'].lower()


def test_api_errors_and_UI():
    assert client.post('/api/rebuild', json={}).status_code == 400
    assert client.post('/api/rebuild', content=b'x', headers={'content-type': 'text/plain'}).status_code == 415
    assert 'id="encryptManifest"' in client.get('/encrypt').text
    assert client.get('/assets/encrypt-v1.1.5.js').status_code == 200
    assert 'script-src \'self\'' in client.get('/encrypt').headers['content-security-policy']


def test_plaintext_is_not_archived_ciphertext():
    _, guides, _, _, manifest = fixture()
    assert b'encryptedBase64' not in manifest
    assert 'original_payload' not in manifest.decode()
    assert call(manifest, b'\0'.join(guides)).status_code == 200


def test_legacy_full_manifest_is_still_accepted():
    from webapp.import_bundle import make_import_manifest, manifest_json
    source, guides, _, _, layout = fixture()
    m, _, _ = make_import_manifest(source, ID, guides, max_output_bytes=16*1024*1024, max_chunks=512)
    resp = call(manifest_json(m), b'\0'.join(guides))
    assert resp.status_code == 200, resp.text
    assert resp.headers['x-source-plaintext-edited'] == 'false'


def test_lean_layout_has_no_original_data_hashes():
    _, guides, _, _, layout = fixture()
    m = json.loads(layout)
    assert set(m) == {'schema', 'schema_version', 'description', 'account_key_fingerprint',
                      'header', 'footer', 'inter_chunk_text', 'guide_count', 'chunks'}
    assert 'payload_sha256' not in str(m)
    assert len(layout) < 2500
    assert call(layout, b'\0'.join(guides)).status_code == 200
