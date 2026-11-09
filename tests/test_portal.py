"""RXPTool v2.1 secure portal integration and native roundtrip coverage."""
from __future__ import annotations

import importlib
import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rxp_decrypt import decode_chunk, derive_base, extract_chunks, initial_permutation
from webapp.editable_document import rebuild_from_editable_document

DOCUMENT = (b'#!RXPTOOL/1\n'
            b'#!header="|1|"\n'
            b'#!footer="|1"\n'
            b'#!account_key_fingerprint="test"\n'
            b'#!chunk\n'
            b'#!guide trailing_lf=1\n'
            b'step\n'
            b'.goto 100/1,1.0,2.0\n'
            b'#!endguide\n'
            b'#!endchunk\n'
            b'#!end\n')


def load(role, tmp_path, monkeypatch):
    monkeypatch.setenv("RXP_PORTAL_ROLE", role)
    monkeypatch.setenv("RXP_PORTAL_DB", str(tmp_path / "data.db"))
    monkeypatch.setenv("RXP_PORTAL_ADMIN_USER", "administrator")
    monkeypatch.setenv("RXP_PORTAL_ADMIN_PASSWORD", "a-very-strong-private-test-password")
    import portal.entry
    return importlib.reload(portal.entry)


def credentials():
    import base64
    return {"Authorization": "Basic " + base64.b64encode(
        b"administrator:a-very-strong-private-test-password").decode()}


def test_native_encoder_roundtrip():
    account = "PortalTest#1234"
    encrypted, count, chunks, raw = rebuild_from_editable_document(DOCUMENT, account)
    perm = initial_permutation(derive_base(account))
    decoded = [decode_chunk(chunk, perm, 16 * 1024 * 1024)
               for chunk in extract_chunks(encrypted, None)]
    assert raw == decoded
    assert count == 1 and chunks == 1


def test_publisher_and_public_are_separate(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as a:
        assert a.get("/admin/publish").status_code == 401
        headers = {**credentials(), "X-RXP-Admin": "1"}
        assert a.get("/admin/publish", headers=headers).status_code == 200
        assert a.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                      headers=headers).status_code == 200
        result = a.post("/api/publish", content=DOCUMENT,
                        headers={**headers, "Content-Type": "application/octet-stream",
                                 "X-Guide-Filename": "Guide.txt"})
        assert result.status_code == 200, result.text
        assert result.json()["published"]["version"] == 1
        assert a.get("/api/state", headers=headers).json()["allowlist"] == ["PortalTest#1234"]
    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as c:
        assert c.get("/download").status_code == 200
        for path in ("/api/state", "/api/encrypt", "/api/decrypt", "/admin/publish",
                     "/assets/admin.js"):
            assert c.get(path).status_code == 404
        assert c.post("/api/publish", content=DOCUMENT).status_code == 404
        assert c.post("/api/download", json={"battle_id": "NotAllowed#1234"}).status_code == 404
        result = c.post("/api/download", json={"battle_id": "PortalTest#1234"})
        assert result.status_code == 200, result.text
        assert result.headers["X-Package-Verified"] == "true"
        output = result.content.decode()
        perm = initial_permutation(derive_base("PortalTest#1234"))
        assert [decode_chunk(chunk, perm, 16 * 1024 * 1024)
                for chunk in extract_chunks(output, None)] == [
                    b"step\n.goto 100/1,1.0,2.0\n"
                ]


def test_admin_auth_csrf_and_rollback(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    headers = {**credentials(), "X-RXP-Admin": "1"}
    with TestClient(admin.app) as client:
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers=credentials()).status_code == 403
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers={**headers, "Origin": "https://evil.example"}).status_code == 403
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers=headers).status_code == 200
        assert client.post("/api/publish", content=DOCUMENT,
                           headers={**headers, "Content-Type": "application/octet-stream"}).status_code == 200
        assert client.post("/api/publish", content=DOCUMENT,
                           headers={**headers, "Content-Type": "application/octet-stream"}).status_code == 200
        restored = client.post("/api/publish/restore", json={"version": 1}, headers=headers)
        assert restored.status_code == 200
        assert restored.json()["published"]["version"] == 3
        assert client.post("/api/allowlist/remove", json={"battle_id": "PortalTest#1234"},
                           headers=headers).status_code == 200
        assert client.get("/api/state", headers=headers).json()["allowlist"] == []
