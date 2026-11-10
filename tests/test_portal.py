"""RXPTool v2.1 secure portal integration and native roundtrip coverage."""
from __future__ import annotations

import importlib
import os
import re
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


def sign_in(client):
    response = client.post("/api/login",
                           json={"username": "administrator",
                                 "password": "a-very-strong-private-test-password"},
                           headers={"X-RXP-Login": "1"})
    assert response.status_code == 200, response.text
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    assert "rxptool_admin_session" in client.cookies
    return {"X-RXP-Admin": "1"}


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
        assert a.get("/admin/publish", follow_redirects=False).status_code == 303
        assert a.get("/login").status_code == 200
        assert a.get("/api/state").status_code == 401
        headers = sign_in(a)
        admin_page = a.get("/admin/publish", headers=headers)
        assert admin_page.status_code == 200
        assert "img-src 'self'" in admin_page.headers["Content-Security-Policy"]
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
        assert re.fullmatch(
            r'attachment; filename="RXPTool!PortalTest#1234_20\d{2}-\d{2}-\d{2}_\d{2}-\d{2}\.txt"',
            result.headers["Content-Disposition"],
        )
        output = result.content.decode()
        perm = initial_permutation(derive_base("PortalTest#1234"))
        assert [decode_chunk(chunk, perm, 16 * 1024 * 1024)
                for chunk in extract_chunks(output, None)] == [
                    b"step\n.goto 100/1,1.0,2.0\n"
                ]


def test_admin_auth_csrf_and_rollback(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers={"X-RXP-Admin": "1"}).status_code == 401
        assert client.post("/api/login",
                           json={"username": "administrator", "password": "wrong"},
                           headers={"X-RXP-Login": "1"}).status_code == 401
        assert client.post("/api/login",
                           json={"username": "administrator",
                                 "password": "a-very-strong-private-test-password"}).status_code == 403
        assert client.post("/api/login",
                           json={"username": "administrator",
                                 "password": "a-very-strong-private-test-password"},
                           headers={"X-RXP-Login": "1",
                                    "Origin": "https://evil.example"}).status_code == 403
        headers = sign_in(client)
        assert client.get("/login", follow_redirects=False).status_code == 303
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"}).status_code == 403
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
        assert client.post("/api/logout", headers=headers).status_code == 200
        assert client.get("/api/state").status_code == 401
        assert client.get("/admin/publish", follow_redirects=False).headers["location"] == "/login"

def test_admin_session_restarts_and_public_auth_isolation(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        sign_in(client)
        assert client.get("/api/state").status_code == 200
        # An application restart invalidates memory-resident sessions.
        new_app = load("admin", tmp_path, monkeypatch)
        with TestClient(new_app.app) as restarted:
            restarted.cookies.set("rxptool_admin_session",
                                  client.cookies.get("rxptool_admin_session"))
            assert restarted.get("/api/state").status_code == 401

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        for url in ("/login", "/assets/login.js", "/api/login", "/api/logout"):
            assert client.get(url).status_code == 404
        assert client.post("/api/login", json={}).status_code == 404


def test_public_page_settings_persist_update_live_and_escape_html(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as c:
        defaults = c.get("/api/state")
        assert defaults.status_code == 401
        headers = sign_in(c)
        state = c.get("/api/state").json()
        assert state["public_page"]["headline"] == "Your guide, ready to import."
        assert state["public_page"]["message"].startswith("Enter a whitelisted Battle.net ID")

        original_version = state["current"]
        endpoint = "/api/settings/public-page"
        payload = {"headline": '<img src=x onerror=alert(1)>',
                   "message": 'New line one\n<script>alert(1)</script> & more'}
        assert c.post(endpoint, json=payload).status_code == 403
        assert c.post(endpoint, json=payload, headers={"X-RXP-Admin": "1",
                          "Origin": "https://evil.example"}).status_code == 403
        assert c.post(endpoint, json={"headline": "", "message": "Hello"},
                      headers=headers).status_code == 400
        assert c.post(endpoint, json={"headline": "X" * 161, "message": "Hello"},
                      headers=headers).status_code == 400
        assert c.post(endpoint, json={"headline": "Line\nTwo", "message": "Hello"},
                      headers=headers).status_code == 400
        assert c.post(endpoint, json={"headline": "Valid", "message": "Y" * 1001},
                      headers=headers).status_code == 400
        assert c.post(endpoint, json=payload, headers=headers).status_code == 200
        new_state = c.get("/api/state").json()
        assert new_state["public_page"] == payload
        assert new_state["current"] == original_version

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as c:
        response = c.get("/download")
        assert response.status_code == 200
        assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
        assert "<img src=x onerror=alert(1)>" not in response.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; more" in response.text
        assert "New line one\n" in response.text
        assert c.get("/assets/settings.js").status_code == 404
        assert c.get("/api/settings/public-page").status_code == 404
        assert c.post("/api/settings/public-page", json=payload).status_code == 404

        # The PUBLIC container is already running while a separate publisher
        # updates SQLite. A new GET sees changes without any restarts.
        with sqlite3.connect(tmp_path / "data.db") as db:
            db.execute("UPDATE page_settings SET value=? WHERE name='headline'",
                       ("Changed live",))
        updated = c.get("/download")
        assert "Changed live" in updated.text
        assert "&lt;img" not in updated.text

    # A fresh admin process still sees the same persisted site text.
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as c:
        sign_in(c)
        persisted = c.get("/api/state").json()["public_page"]
        assert persisted["headline"] == "Changed live"
        assert persisted["message"] == payload["message"]


def test_public_pirate_design_preserves_dynamic_copy_and_download_contract(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        headers = sign_in(client)
        changed = client.post(
            "/api/settings/public-page",
            headers=headers,
            json={
                "headline": "Raise the Red <Sails>!",
                "message": 'Latest guides & fresh loot\nClaim yours today.'
            },
        )
        assert changed.status_code == 200, changed.text

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        response = client.get("/download")
        assert response.status_code == 200
        assert "THE PRIVATEER'S CACHE" in response.text
        assert "public-crest" in response.text
        assert "Raise the Red &lt;Sails&gt;!" in response.text
        assert "Latest guides &amp; fresh loot\nClaim yours today." in response.text
        assert "{{PUBLIC_HEADLINE}}" not in response.text
        assert "{{PUBLIC_MESSAGE}}" not in response.text
        assert 'id="form"' in response.text
        assert 'id="id"' in response.text
        assert 'id="submit"' in response.text
        assert 'id="status"' in response.text
        assert '/assets/download.js' in response.text
        assert '<link rel="icon" type="image/svg+xml" sizes="any" href="/assets/favicon.svg">' in response.text
        policy = response.headers["Content-Security-Policy"]
        assert "default-src 'none'" in policy
        assert "img-src 'self'" in policy
        assert "img-src *" not in policy
        favicon = client.get("/assets/favicon.svg")
        assert favicon.status_code == 200
        assert favicon.headers["content-type"].startswith("image/svg+xml")
        assert '<svg' in favicon.text
        assert 'id="crestGold"' in favicon.text
        assert 'id="crestRed"' in favicon.text
        assert "crossed cutlasses" in favicon.text
        assert client.get("/assets/favicon.png").status_code == 404
        css = client.get("/assets/style.css")
        assert css.status_code == 200
        assert "public-download-page" in css.text
        assert "public-deck" in css.text
        assert client.get("/api/state").status_code == 404


def test_public_download_filename_supports_unicode_battletags(tmp_path, monkeypatch):
    from urllib.parse import unquote

    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as a:
        headers = sign_in(a)
        assert a.post("/api/allowlist/add",
                      json={"battle_id": "Piratañ#1234"}, headers=headers).status_code == 200
        assert a.post("/api/publish", content=DOCUMENT,
                      headers={**headers, "Content-Type": "application/octet-stream"}).status_code == 200

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as c:
        result = c.post("/api/download", json={"battle_id": "Piratañ#1234"})
        assert result.status_code == 200, result.text
        disposition = result.headers["Content-Disposition"]
        assert "filename*=UTF-8''" in disposition
        extended = disposition.split("filename*=UTF-8''", 1)[1]
        assert re.fullmatch(
            r'RXPTool!Piratañ#1234_20\d{2}-\d{2}-\d{2}_\d{2}-\d{2}\.txt',
            unquote(extended),
        )


def test_publication_age_relative_units(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    portal = load("admin", tmp_path, monkeypatch)
    fixed = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    cases = (
        (timedelta(seconds=0), "just now"),
        (timedelta(seconds=59), "just now"),
        (timedelta(minutes=1), "1 minute ago"),
        (timedelta(minutes=12), "12 minutes ago"),
        (timedelta(hours=1), "1 hour ago"),
        (timedelta(hours=23), "23 hours ago"),
        (timedelta(days=1), "1 day ago"),
        (timedelta(days=4), "4 days ago"),
        (timedelta(days=7), "1 week ago"),
        (timedelta(days=21), "3 weeks ago"),
        (timedelta(days=30), "1 month ago"),
        (timedelta(days=90), "3 months ago"),
        (timedelta(days=365), "1 year ago"),
        (timedelta(days=730), "2 years ago"),
        (timedelta(days=-1), "just now"),
    )
    for elapsed, expected in cases:
        assert portal.relative_publication_age(fixed - elapsed, current=fixed) == expected


def test_publication_badge_when_nothing_published(tmp_path, monkeypatch):
    load("admin", tmp_path, monkeypatch)
    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        page = client.get("/download")
        assert page.status_code == 200
        assert "Awaiting first guide publication" in page.text
        assert "Guide last updated" not in page.text


def test_publication_age_is_live_and_uses_existing_published_timestamp(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        headers = sign_in(client)
        # Existing deployments contain no publication until the first upload.
        assert client.get("/api/state").json()["current"] is None
        assert client.post("/api/publish", content=DOCUMENT, headers={
            **headers, "Content-Type": "application/octet-stream"}).status_code == 200
        initial = client.get("/api/state").json()["current"]["published_at"]
        assert initial

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        page = client.get("/download")
        assert page.status_code == 200
        assert "Guide last updated" in page.text
        assert "just now</time>" in page.text
        assert "title=" in page.text
        assert initial in page.text

        # The public container reads publication metadata on every page
        # load, so the visible age changes without restarting the service.
        historical = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat(timespec="seconds")
        with sqlite3.connect(tmp_path / "data.db") as db:
            db.execute("UPDATE publication SET published_at=? WHERE singleton=1", (historical,))
        aged = client.get("/download")
        assert "Guide last updated" in aged.text
        assert "2 weeks ago</time>" in aged.text
        assert historical in aged.text
        assert aged.headers["Cache-Control"] == "no-store"

        with sqlite3.connect(tmp_path / "data.db") as db:
            db.execute("UPDATE publication SET published_at=? WHERE singleton=1",
                       ((datetime.now(timezone.utc) - timedelta(days=400)).isoformat(timespec="seconds"),))
        assert "1 year ago</time>" in client.get("/download").text

    # The timestamp is refreshed when a new upload is published.
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        headers = sign_in(client)
        pub = client.post("/api/publish", content=DOCUMENT, headers={
            **headers, "Content-Type": "application/octet-stream"})
        assert pub.status_code == 200
        assert pub.json()["published"]["version"] == 2
    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        assert "just now</time>" in client.get("/download").text


def test_private_workspace_links_persist_and_public_cannot_access_them(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        assert client.get("/api/state").status_code == 401
        assert client.post("/api/settings/navigation",
                           json={"editor_url": "http://editor.lan:8787",
                                 "public_url": "https://rxp.dynastic-host.com/download"},
                           headers={"X-RXP-Admin": "1"}).status_code == 401

        headers = sign_in(client)
        page = client.get("/admin/publish")
        assert page.status_code == 200
        assert 'id="nav-decrypt"' in page.text
        assert 'id="nav-encrypt"' in page.text
        assert 'id="nav-public"' in page.text
        assert '/assets/navigation.js' in page.text
        assert client.get("/assets/navigation.js").status_code == 200
        assert client.get("/api/state").json()["navigation"] == {
            "editor_url": "", "public_url": ""
        }

        endpoint = "/api/settings/navigation"
        links = {
            "editor_url": "http://editor.lan:8787/",
            "public_url": "https://rxp.dynastic-host.com/download/"
        }
        assert client.post(endpoint, json=links).status_code == 403
        assert client.post(endpoint, json=links, headers={
            **headers, "Origin": "https://evil.example"
        }).status_code == 403
        unsafe = [
            {"editor_url": "javascript:alert(1)", "public_url": ""},
            {"editor_url": "https://user:password@example.com", "public_url": ""},
            {"editor_url": "https://editor.example/extra", "public_url": ""},
            {"editor_url": "https://example.com/?token=secret", "public_url": ""},
            {"editor_url": "https://editor.example", "public_url": "data:text/html,X"},
            {"editor_url": "https://editor.example", "public_url": "https://example.com/admin/publish"},
            {"editor_url": "https://editor.example", "public_url": "https://example.com/download#fragment"},
        ]
        for invalid in unsafe:
            response = client.post(endpoint, json=invalid, headers=headers)
            assert response.status_code == 400, (invalid, response.text)

        response = client.post(endpoint, json=links, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["navigation"] == {
            "editor_url": "http://editor.lan:8787",
            "public_url": "https://rxp.dynastic-host.com/download"
        }
        state = client.get("/api/state").json()
        assert state["navigation"] == response.json()["navigation"]
        assert state["current"] is None

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        page = client.get("/download")
        assert page.status_code == 200
        assert "editor.lan" not in page.text
        assert "rxp.dynastic-host.com" not in page.text
        assert client.get("/assets/navigation.js").status_code == 404
        assert client.get("/api/settings/navigation").status_code == 404
        assert client.post("/api/settings/navigation", json=links).status_code == 404

    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        sign_in(client)
        assert client.get("/api/state").json()["navigation"] == state["navigation"]
        clear = client.post(endpoint, headers={"X-RXP-Admin": "1"},
                            json={"editor_url": "", "public_url": ""})
        assert clear.status_code == 200
        assert clear.json()["navigation"] == {"editor_url": "", "public_url": ""}


def test_classic_editor_publisher_theme_keeps_forms_and_authentication(tmp_path, monkeypatch):
    """Private workspace restyle must not rename any live JS/API hook IDs."""
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as c:
        # Unauthenticated callers still cannot access publisher content.
        assert c.get("/admin/publish", follow_redirects=False).status_code == 303
        login = c.get("/login")
        assert login.status_code == 200
        assert 'class="publisher-login"' in login.text
        assert 'id="login-form"' in login.text
        assert 'id="username"' in login.text
        assert 'id="password"' in login.text
        assert 'id="submit"' in login.text
        assert 'id="login-status"' in login.text
        assert 'PRIVATE PUBLISHING WORKSPACE' in login.text
        assert 'stroke="#5EEAD4"' in login.text
        assert "script-src 'self'" in login.headers["Content-Security-Policy"]

        sign_in(c)
        page = c.get("/admin/publish")
        assert page.status_code == 200
        assert 'class="publisher-admin"' in page.text
        assert 'class="publisher-grid"' in page.text
        assert 'class="publisher-hero"' in page.text
        assert 'PRIVATE PUBLISHING WORKSPACE' in page.text
        assert 'stroke="#5EEAD4"' in page.text
        for element_id in (
            "logout", "nav-decrypt", "nav-encrypt", "nav-public",
            "publication", "publish", "guide", "publishbutton",
            "add", "id", "ids", "history", "status",
            "public-page-settings", "public-page-form", "public-headline",
            "public-message", "public-page-save", "public-preview-headline",
            "public-preview-message", "public-page-status",
            "navigation-settings", "navigation-form", "editor-url",
            "public-url", "navigation-save", "navigation-status",
        ):
            assert f'id="{element_id}"' in page.text

        for filename in ("admin.js", "settings.js", "navigation.js"):
            assert f'/assets/{filename}' in page.text
        assert "default-src 'none'" in page.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in page.headers["Content-Security-Policy"]
        css = c.get("/assets/style.css")
        assert css.status_code == 200
        assert "body.publisher-admin" in css.text
        assert "body.publisher-login" in css.text
        assert "--work-teal: #6cebd4;" in css.text
        assert "--work-blue: #6d9df8;" in css.text

        # All functional admin APIs retain their original semantics.
        state = c.get("/api/state")
        assert state.status_code == 200
        assert state.json()["navigation"] == {"editor_url": "", "public_url": ""}
        assert c.post("/api/allowlist/add", json={"battle_id": "Cosmetic#1234"},
                      headers={"X-RXP-Admin": "1"}).status_code == 200
        assert "Cosmetic#1234" in c.get("/api/state").json()["allowlist"]


def test_classic_publisher_theme_does_not_affect_public_pirate_page(tmp_path, monkeypatch):
    load("admin", tmp_path, monkeypatch)
    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as c:
        page = c.get("/download")
        assert page.status_code == 200
        assert 'class="public-download-page"' in page.text
        assert "THE PRIVATEER'S CACHE" in page.text
        assert "publisher-admin" not in page.text
        assert "PRIVATE PUBLISHING WORKSPACE" not in page.text
        assert "public-crest" in page.text
        assert '/assets/favicon.svg' in page.text
        assert c.get("/assets/style.css").status_code == 200


def test_private_admin_uses_exact_classic_editor_favicon_assets(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    original_assets = Path(__file__).resolve().parents[1] / "webapp" / "static"
    assets = (
        ("/assets/favicon.svg", "favicon.svg", "image/svg+xml"),
        ("/assets/favicon-32.png", "favicon-32.png", "image/png"),
        ("/assets/apple-touch-icon.png", "apple-touch-icon.png", "image/png"),
        ("/favicon.ico", "favicon.ico", "image/x-icon"),
    )
    with TestClient(admin.app) as client:
        # Icons need to work for the login screen BEFORE a session exists.
        page = client.get("/login")
        assert page.status_code == 200
        for route, filename, media_type in assets:
            assert f'href="{route}"' in page.text
            response = client.get(route)
            assert response.status_code == 200
            assert response.headers["content-type"].startswith(media_type)
            assert response.content == (original_assets / filename).read_bytes()

        assert "img-src 'self'" in page.headers["Content-Security-Policy"]
        assert "default-src 'none'" in page.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in page.headers["Content-Security-Policy"]
        assert client.get("/api/state").status_code == 401
        assert client.get("/admin/publish", follow_redirects=False).status_code == 303

        sign_in(client)
        dashboard = client.get("/admin/publish")
        assert dashboard.status_code == 200
        for route, _, _ in assets:
            assert f'href="{route}"' in dashboard.text
        assert "img-src 'self'" in dashboard.headers["Content-Security-Policy"]

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        # Public and private roles still have DIFFERENT icons at the same URL.
        public_icon = client.get("/assets/favicon.svg")
        assert public_icon.status_code == 200
        assert b"crestRed" in public_icon.content
        assert public_icon.content != (original_assets / "favicon.svg").read_bytes()
        for route in ("/assets/favicon-32.png", "/assets/apple-touch-icon.png",
                      "/favicon.ico", "/api/state"):
            assert client.get(route).status_code == 404
        assert client.get("/login").status_code == 404
