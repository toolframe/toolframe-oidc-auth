# Agent authorization, revocation and recovery

Give an OAuth-capable MCP client `https://app.example/mcp`. A protected request
returns a Bearer challenge pointing at protected-resource metadata. The client
can discover the authorization server, register, request consent and exchange an
authorization code using PKCE S256. Consent displays the client ID, name, redirect
URI, target resource and requested scopes; display names are unverified client
metadata. If necessary, the user signs in at the upstream provider. Dashboard
and Agent flows resolve to the same local user, with independent credentials.

OAuth endpoints are `/oauth/authorize`, `/oauth/token`, `/oauth/register` (when
enabled) and `/oauth/revoke`. Authorization-server metadata is
`/.well-known/oauth-authorization-server/oauth`; resource metadata is
`/.well-known/oauth-protected-resource/mcp`. Both authorization and token requests
must include `resource=https://app.example/mcp`. This is the default allowed
resource; `resources` can declare additional exact URLs for custom consumers of
the generic verifier. Core currently integrates that verifier with MCP only.

This release supports public clients, authorization-code + S256, refresh-token
rotation, static registration and bounded RFC 7591 dynamic registration. An
omitted registration authentication method selects `none`, explicitly returned
in the registration response. Explicit secret-based client authentication is
rejected. No wildcard redirects are accepted: redirects must exactly match an
HTTPS URL or an HTTP loopback URL. To disable DCR, use:

```toml
[plugins.oidc-auth.config]
# Include the other required settings from the OIDC setup guide.
dynamic_registration = false
clients = [
  { client_id = "desktop-agent", client_name = "Desktop agent", redirect_uris = ["http://127.0.0.1:8347/callback"] },
]
```

Advertise only the business scopes you intend to expose through this issuer.
Some MCP clients request every scope in resource metadata. Consent always shows
the actual requested set. System permissions cannot be delegated. Client ID
Metadata Documents (CIMD), confidential downstream clients, device grants,
client-credentials grants, SAML, downstream OIDC ID tokens and automatic
account linking are outside this release. An upstream ID/access token is never
accepted as an app bearer token. Existing `tf_mcp_` keys remain usable alongside
OAuth; an unavailable optional OAuth plugin does not disable key verification.

## Credentials, revocation and backup

OAuth access tokens last 300 seconds by default (30–900 configurable); grants
last 30 days by default (60 seconds–one year configurable). Tokens use 256 random
bits and only digests are persisted. Codes expire after 60 seconds and are single
use. Refresh tokens rotate, cannot outlive the grant, and replay revokes the
whole grant. Every MCP admission checks token expiry, resource binding, current
user permissions and grant status. Already admitted operations may finish.

**Connected agents** lets the user revoke a connection without signing out of
Dashboard. Disabling the user invalidates sessions and revokes all their grants.
Logout ends the local browser session; it does not globally log out the IdP or
revoke agent grants. Permission reductions take effect on subsequent admissions.
OAuth authorization is explicit on each new flow; there is no implicit consent
based solely on an upstream login.

The plugin persists encrypted, browser-bound ten-minute authorization flows and
code/token digests in its managed store. Pending flows are capped at 1000 and
expired flows are removed when new flows are created. Dynamic registrations are
bounded by `max_clients`. New, unconsented registrations expire after
`pending_client_seconds` (3600 by default) and can be replaced under capacity
pressure. Signed-in consent flows receive ten-minute protection; user-consented
clients remain persistent. Pre-v2 registrations remain protected until explicit
cross-store recovery. See [registration capacity and recovery](../docs/registration.md)
for retry behavior, migration, operator recovery and anonymous traffic limits.
Token and grant history currently requires operator-managed retention. Back up
`data/plugins/auth/data.sqlite`, `data/plugins/oidc-auth/data.sqlite`, retained
`.toolframe/secrets/`, composition, and referenced upstream secret files together,
using consistent SQLite backups. Keep the `oidc-auth/flow-key.key` secret across
reloads/restarts. A missing key with an existing store blocks activation; restore it from backup.
