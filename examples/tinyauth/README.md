# TinyAuth OIDC acceptance fixture

This local Docker Compose fixture provisions TinyAuth v5.2.0, a fixed OIDC client,
a fixture user and Caddy TLS entirely from files. It exercises Toolframe as an
OIDC client and OAuth issuer, with a real FastMCP client. It does not replace
Toolframe's local permissions, consent or token service.

## Start

```sh
cd examples/tinyauth
python3 prepare.py
docker compose up -d --wait
docker compose cp tls:/data/caddy/pki/authorities/local/root.crt certs/root.crt
```

Default addresses are `https://tinyauth.localhost:18443` and
`https://app.localhost:18444`. Caddy proxies the latter to a host Toolframe process
on port 9876. Docker Desktop supplies `host.docker.internal`; on Linux configure
that host mapping explicitly. Both published ports bind **127.0.0.1 only**.
No Docker socket is mounted. Volumes retain the database, OIDC signing keys and
TLS CA. Stop with `docker compose down`; retain volumes to preserve that state.

TinyAuth requires an HTTPS issuer with a multi-label hostname. Ensure these
names resolve to loopback in the host process as well as the browser. DNS proxies
may intercept `.localhost`; `prepare.py --issuer https://YOUR_LOCAL_NAME:18443
--app-origin https://YOUR_APP_NAME:18444` selects existing local names. The helper
never overwrites `.env` or existing secret files; edit `.env` explicitly when
changing an already provisioned fixture. Use only the dedicated fixture ports.

The deliberately public fixture credentials are **user / password** and a
fixture-only client secret in `secrets/tinyauth-client-secret`. These are not
production credentials. The helper writes credentials as mode 0600; `.env`,
`secrets/` and `certs/` are ignored by Git. Do not expose this fixture publicly.

Trust the generated CA in a dedicated test browser/profile according to your
browser's certificate policy. Application and Python tests load `certs/root.crt`
explicitly; they never disable TLS verification. Browser trust is separate from
Python trust. TinyAuth's upstream-provider `INSECURE` setting is not an option
for making TinyAuth itself an HTTP OIDC server.

### Use an existing mkcert CA

If your browser already trusts a local [mkcert](https://github.com/FiloSottile/mkcert)
CA, issue a certificate for the two fixture hostnames and select the Compose
override instead of Caddy's internal CA. Adjust the names to match `.env`:

```sh
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem tinyauth.localhost app.localhost
chmod 600 certs/localhost-key.pem
cp "$(mkcert -CAROOT)/rootCA.pem" certs/root.crt
docker compose -f compose.yaml -f compose.mkcert.yaml up -d --wait
```

Only the public CA certificate and the fixture's leaf certificate/key are used;
never copy or mount mkcert's `rootCA-key.pem`. This does not install a new trust
root or disable TLS verification. Use both Compose files on subsequent commands,
or set `COMPOSE_FILE=compose.yaml:compose.mkcert.yaml` in the local `.env`.
If switching a running fixture, restart the Toolframe OIDC worker after replacing
`certs/root.crt`, since its HTTP client retains the previous CA in memory.
Do not run the Caddy CA export command when using this override.

## Configure the installed application

Follow the plugin README's coordinated package installation and Auth v2 migration.
Use these provider values (adjust origin/issuer if `.env` was customized):

```toml
[application]
public_url = "https://app.localhost:18444"

[access]
mode = "protected"
failure_mode = "closed"
oidc_provider = "oidc-auth"

[plugins.auth.config]
identity_provider = "oidc-auth"
federated_identities = [
  { issuer = "https://tinyauth.localhost:18443", subject = "17e12ef3-faf9-5376-ba5b-f38fc41da87f", label = "TinyAuth fixture user", scopes = ["entry-register.read", "entry-register.write"] },
]

[plugins.oidc-auth.config]
public_url = "https://app.localhost:18444"
# Entry Register's published MCP tool needs only read permission.
scopes = ["entry-register.read"]
dynamic_registration = true

[plugins.oidc-auth.config.providers.tinyauth]
label = "TinyAuth"
issuer = "https://tinyauth.localhost:18443"
server_metadata_url = "https://tinyauth.localhost:18443/.well-known/openid-configuration"
client_id = "toolframe-local"
client_secret_file = "/absolute/path/to/examples/tinyauth/secrets/tinyauth-client-secret"
ca_file = "/absolute/path/to/examples/tinyauth/certs/root.crt"
```

The subject above is specific to TinyAuth's `user` plus `toolframe-local` client
ID. Changing either requires verifying the new subject. The registration's exact
callback is supplied by `TOOLFRAME_OIDC_CALLBACK` in `.env`. No email-based account
merging or implicit user provisioning is enabled. Also enable `mcp-auth`, set
`[mcp_access] mode="protected"`, and retain the normal storage/Dashboard plugins.
Apply the reviewed composition with `toolframe --home APP apply`.

## Verify

In a Python 3.14 environment with the matching SDK/Auth/storage packages and
`fastmcp==4.0.0` installed, run from this plugin checkout:

```sh
python examples/tinyauth/verify.py
```

The script reads `.env`, loads the fixture CA, signs in at the real IdP, visits the
real Toolframe callback, and uses FastMCP's own OAuth discovery, DCR, PKCE and token
exchange. Only the human browser interaction is automated using TinyAuth v5.2.0's
first-party login/consent APIs. It calls an actual MCP tool, checks local identity
reuse, refresh rotation, revocation on an existing connection and continued
Dashboard sign-in. It creates client/grant audit records, then revokes the test
grant; it does not edit application business data or existing credentials.

Separately open the Dashboard login page in the test browser, choose TinyAuth,
sign in and inspect **Connected agents**. Complete a browser consent flow and
revoke its grant from that page. This manual/browser check covers actual
cross-site cookies, redirects and Streamlit rendering; the script alone does
not establish those browser behaviors.

TinyAuth discovery and implementation are pinned to
[v5.2.0](https://github.com/tinyauthapp/tinyauth/releases/tag/v5.2.0).
Its user-login and consent APIs are fixture internals, not a general IdP API.
