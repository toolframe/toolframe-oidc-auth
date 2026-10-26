# Set up OIDC sign-in

This plugin requires SDK >=0.4.0,<1, Core 0.7.0, Auth 0.3.0, Dashboard Auth 0.2.0 and
MCP Auth 0.3.0.
The OIDC plugin is optional and is not enabled by the Entry Register template.

## Quick start

1. Install compatible Core, Auth and Dashboard packages. For an existing Auth v1
   store, back it up with its retained secrets, stage the new Auth wheel with
   `toolframe --home APP plugin update auth --source pypi:toolframe-auth==0.3.2`, inspect
   `toolframe --home APP migrate plan auth`, then apply that returned plan using
   `toolframe --home APP migrate apply auth --plan-id PLAN_ID`. Migration v2 only
   adds user, external-identity, session and agent-grant tables.
2. Register a confidential web client at the upstream identity provider, with
   the exact callback `https://app.example/_toolframe/oidc/callback/google`.
   Store its client secret in a regular file readable only by the application
   owner (`chmod 600`); use an absolute path in configuration.
3. Add the following desired-state settings to `APP/toolframe.toml`, preserving
   the application's existing ID, plugin declarations and storage configuration.
   Replace example values, then run `toolframe --home APP apply`. Core installs
   the declared package together with its configuration; adding it with an empty
   configuration fails validation even when it is disabled.

```toml
[application]
# Keep the existing application ID and other settings.
public_url = "https://app.example"

[access]
mode = "protected"
failure_mode = "closed"
auth_provider = "auth"
dashboard_auth = "dashboard-auth"
oidc_provider = "oidc-auth"

[mcp_access]
mode = "protected"
auth_provider = "mcp-auth"

[plugins.auth.config]
identity_provider = "oidc-auth"
federated_identities = [
  { issuer = "https://accounts.google.com", subject = "VERIFIED_GOOGLE_SUB", label = "Alice", scopes = ["entry-register.read"] },
]

[plugins.oidc-auth]
source = "pypi:toolframe-oidc-auth==0.3.2"
enabled = true

[plugins.oidc-auth.config]
public_url = "https://app.example"
scopes = ["entry-register.read"]
dynamic_registration = true
max_clients = 1000
access_token_seconds = 300
grant_seconds = 2592000

[plugins.oidc-auth.config.providers.google]
label = "Google"
issuer = "https://accounts.google.com"
server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
client_id = "GOOGLE_CLIENT_ID"
client_secret_file = "/absolute/private/google-client-secret"
```

The `auth`, `dashboard-auth`, `mcp-auth` and SQLite provider must be enabled in the
existing composition. Set Core's `application.public_url` and this plugin's
`public_url` identically. Terminate HTTPS at a reverse proxy and preserve the
canonical Host. Core never derives its issuer from forwarded headers. Only
explicit OAuth routes allow cross-origin entry; Dashboard management and consent
submission remain same-origin. Public-host requests cannot inherit proxy-loopback
operator privileges. Configure proxy request limits for publicly exposed login
and dynamic-registration endpoints.

The login page offers **Continue with Google** alongside Access Password login.
Admission uses an administrator-verified **issuer + subject**, never an email
address. The allowlist creates a local user on first successful login. Later
changes belong to **User access** or the protected user-management API; changing
that initial-admission entry does not overwrite an existing user. Unlisted
identities are rejected. A user needs the relevant business scopes before they
can delegate them to an agent. `system.auth.users` grants scoped user management;
each federated user receives `system.auth.self` for their own connections.

## Google, Keycloak and TinyAuth

Upstream providers share the same Authlib adapter; they do not need separate
Toolframe authentication implementations. Use Keycloak as an identity broker by
setting its realm issuer and discovery URL and registering the same Toolframe
callback under a chosen provider ID, for example `keycloak`. Google can then be
configured as an upstream provider within Keycloak. Toolframe still owns local
permissions and issues the app-specific access token.

Each provider accepts `issuer`, `server_metadata_url`, `client_id`,
`client_secret_file`, optional `label`, optional `ca_file`, and
`token_endpoint_auth_method` (`client_secret_basic`, the default, or
`client_secret_post`). HTTPS certificate validation stays enabled. `ca_file` adds
a private CA for a controlled deployment; client secrets and IdP tokens are never
included in browser presentation or the configuration journal. A changed secret
file requires plugin reload. Provider metadata is discovered lazily, so an IdP
outage does not prevent plugin startup or invalidate existing local sessions.

See the [TinyAuth Docker fixture](../examples/tinyauth/README.md) for reproducible,
local TLS, user and client provisioning. Real acceptance covers TinyAuth; Google
and Keycloak use the documented generic path but need deployment-specific live
verification. [Google OIDC documentation](https://developers.google.com/identity/openid-connect/openid-connect),
[Keycloak identity brokering](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker),
[Authlib Starlette OIDC client](https://docs.authlib.org/en/latest/client/starlette.html)
and [Authlib authorization server](https://docs.authlib.org/en/latest/oauth2/server.html)
describe the upstream protocols and library integration.

## PostgreSQL storage

Version 0.3 requires SDK 0.4 and declares PostgreSQL migration SQL alongside the
unchanged SQLite history. Provision this plugin’s stable store owner with the
PostgreSQL provider before enabling it. The application still runs one Core;
retain its private keys and configuration with the application home. Existing
SQLite records are not imported automatically.
