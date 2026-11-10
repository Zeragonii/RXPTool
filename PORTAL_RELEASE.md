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

## Editing the public page text

From the **private publisher** at `/admin/publish`, find the **Public downloads page** section. Edit the headline and message, review the live preview, and click **Save public page text**.

- Changes become visible to public visitors when they next refresh `/download`. **No new guide publication, environment variables or container restart required.**
- The settings are stored in the existing `rxptool_portal_data` SQLite volume, separate from published guide versions and allowlist entries. Container redeployments preserve the values.
- The default text is exactly the original RXPTool download page headline and description; existing installations gain these settings automatically when the admin container starts.
- Headline accepts 1–160 characters on one line. Message accepts 1–1000 characters and line breaks.
- These fields accept *plain text only*, with HTML escaped when the public page is rendered. They cannot inject scripts, links or HTML markup.
- Changing these values affects **only the public downloads page**. The admin login, original Decrypt and Encrypt screens, guide contents, and public-download security restrictions are unchanged.

## Public download filenames

All public guide downloads are named consistently as `RXPTool!BattleTag#1234_YYYY-MM-DD_HH-MM.txt` (UTC). The uploaded guide's original filename does not affect the download name. This uses the original editor's safe Windows filename and Content-Disposition logic, preserves the # in BattleTags, and supports Unicode BattleTags in browsers. The encrypted guide content is unchanged.

## Public guide last-updated indicator

The public Privateer's Cache page shows a gold-accented **Guide last updated ... ago** label beneath the configurable description. It derives from the existing UTC `publication.published_at` timestamp in the SQLite volume, recorded on each successful upload (and refreshed when a version is restored).

The label shows just now, minutes, hours, days, weeks, months or years as appropriate, with the exact publication date and UTC time available on hover. The relative age is recalculated on every public page load; no new API endpoints, JavaScript, configuration, or database migration are required. Before the first publication the page shows **Awaiting first guide publication**.

## Private workspace navigation

The publisher's private **Publishing** dashboard now includes navigation to the original **Decrypt** and **Encrypt** pages and the public **Downloads** page. In **Workspace links**, save the URL of your original editor (e.g. `http://LAN-SERVER:8787`) and the public site (e.g. `https://rxp.example.com/download`). These links are stored privately in the existing SQLite volume and require no Portainer changes. The public downloader does **not** expose the editor URL or private publisher dashboard.

For a return link **from the original editor** to the publisher, optionally set `RXP_PORTAL_ADMIN_URL=http://PRIVATE-SERVER:8788/admin/publish` in the **original editor stack**, then update that original stack with an image that includes this feature (currently the `:edge` image). Both Decrypt and Encrypt show a **Publishing** tab only when this is configured. The link opens a separate tab and is not an authentication shortcut. Do not set this on an internet-facing editor if you want to keep the private dashboard hostname/address undisclosed. **Never expose the publisher's port publicly** merely to make a link work: browser access to that private host over LAN/VPN is still required.

Links use explicit HTTP(S) URLs without credentials/query fragments, open external destinations with `noopener noreferrer`, and leave existing user authentication, session cookies, permissions and routing intact. The public downloads page does not gain an admin link.
