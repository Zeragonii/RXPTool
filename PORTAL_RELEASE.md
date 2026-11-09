# RXPTool v2.1.0 portal extension

RXPTool's existing **Decrypt** (`/`) and **Encrypt** (`/encrypt`) application stays unchanged. This release adds two isolated roles to the *same* GHCR image: a private publisher and a public account-specific guide download page.

## Portainer deployment

1. Deploy your existing RXPTool stack unchanged. **Do not proxy its port to the internet.**
2. Push/merge this PR to `main` and wait for GitHub Actions to publish `ghcr.io/zeragonii/rxptool:edge`. For stable production, tag `v2.1.0` after reviewing successful CI, then switch `RXP_IMAGE` to `ghcr.io/zeragonii/rxptool:2.1.0`.
3. Create or reuse a Docker network shared with your Nginx Proxy Manager instance, e.g. `docker network create rxptool-proxy` followed by `docker network connect rxptool-proxy YOUR_NPM_CONTAINER`. Set `RXP_PROXY_NETWORK` if using another existing network.
4. Add `portainer-portal-stack.yml` in Portainer as a **separate stack**, using the same image, not another repository.
5. Set `RXP_PORTAL_ADMIN_USER` and a **unique 20+ character password** in Portainer's Stack Environment. Do not commit the password. Admin listens only on host `127.0.0.1:8788` unless you explicitly configure `RXP_ADMIN_BIND_IP` to the server's private LAN IP. Restrict the port to trusted devices or VPN clients.
6. Access `http://HOST:8788/login` (the admin dashboard redirects to this page when signed out). Sign in with your existing portal admin username/password; there is **no browser Basic Auth popup**. Then add approved Battle.net IDs and upload an **RXPTool editable TXT** (starting with `#!RXPTOOL/1`). Publication tests a complete native encrypt/decrypt roundtrip before switching the current guide.
7. In Nginx Proxy Manager, proxy **only** `rxptool-download:8787` to your public HTTPS hostname. Enable Force SSL, reverse-proxy request throttling and other safeguards. **Never proxy** the publisher or original editor.

## Operational notes

- Whitelisted Battle.net IDs are access identifiers, not authentication. Anyone who knows a whitelisted ID can trigger an encrypted download. The output is still encrypted for that specific ID.
- Shared SQLite database stores plaintext uploaded guides. The publisher mounts it read/write; the public container mounts it read-only, but the public application necessarily reads plaintext in memory to encrypt.
- Admin sessions use a randomly generated, HttpOnly, SameSite=Strict cookie, expire after eight hours, and are invalidated on logout and container restart. The login is rate-limited. Your existing `RXP_PORTAL_ADMIN_USER` and `RXP_PORTAL_ADMIN_PASSWORD` values continue to work; **no new credentials** are required.
- Only access the admin over a trusted LAN, VPN, or private HTTPS reverse proxy. Passwords are sent in the request body, so **plain HTTP is not safe on untrusted networks**. If administering through a private HTTPS hostname, set `RXP_PORTAL_COOKIE_SECURE=true` on the publisher and configure the host/origin consistently; this makes the session cookie HTTPS-only.
- A public instance has no Decrypt, Encrypt, admin, or whitelist-management routes; the original service remains a separate process.
- Publishing keeps three previous guide versions for rollback. All publication changes and list updates are transactional.
- Downloads are rate limited by direct peer and by account ID; behind NPM all client requests may share one peer IP, so configure additional real-client IP rate limits at NPM. The public app intentionally does **not** trust `X-Forwarded-For`.
- Keep your proxy network tightly scoped. The admin container has no proxy network.
- Back up the `rxptool_portal_data` volume. Restore its SQLite file when the containers are stopped.
- Upload format is the *editable* TXT produced by existing RXPTool, not arbitrary raw Lua/plain text. Guide contents and markers can be edited before publication.
- On a fresh install, public startup waits for publisher health to initialize the database. A first publication is required before downloads work.
- No runtime changes are made to the original `webapp.main`.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
node --check portal/static/admin.js
node --check portal/static/download.js
```

Release after CI passes:

```bash
git add .
git commit -m "v2.1.0 - Secure guide publisher and public downloads"
git push
git tag v2.1.0
git push origin v2.1.0
```
