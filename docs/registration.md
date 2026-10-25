# Dynamic registration capacity and recovery

Dynamic registration remains disabled unless `dynamic_registration = true`.
Public MCP clients need no registration credential. `max_clients` (default 1000,
range 1–10000) bounds all persisted dynamic registrations together, including
retained clients. Static clients are configured separately and are never removed
by registration cleanup.

New registrations are **pending** until a user explicitly consents. A pending
client ID is usable for `pending_client_seconds` (default 3600, range 60–86400).
Successful registration requests remove expired, unprotected pending clients.
When full, the same transaction replaces the oldest unprotected pending clients
needed to fit the new registration. Invalid metadata and disabled registration
do not evict clients. An expired pending ID is rejected even before physical
cleanup. Anonymous authorization/login flows do not reserve registration capacity.

A validated authorization request from a signed-in user protects its pending
client for the ten-minute consent window, including across restarts. Expired
reservations can be reclaimed. On explicit user consent, retention is persisted
before creating the Auth grant, so cancellation or a process crash cannot leave a
committed grant pointing at a reclaimable client. Failed issuance after consent
conservatively retains the client too. Retained registrations are not
automatically deleted, even after revocation or expiry of their grants/tokens.
Existing authorization codes, tokens and refresh tokens retain their normal
lifetimes and checks.

If capacity is entirely retained or temporarily protected, registration returns
`invalid_client_metadata`; retry after consent reservations expire or contact the
operator. Cleanup does not remove active authorizations to make room. If a
pending ID expires or is displaced before sign-in, clients must register again
and restart authorization. This includes an anonymous browser flow that was
waiting for upstream sign-in. Repeated anonymous traffic can still displace
other pending IDs before users sign in; this design removes permanent anonymous
capacity occupation, but cannot guarantee fair onboarding under sustained
traffic. Proxy request limits can reduce traffic; they do not establish a
per-registrant capacity guarantee.

## Upgrade from store revision v1

Apply the plugin's v2 store migration through normal Toolframe update/migration
management. The v1 SQL and checksums are unchanged for both SQLite and PostgreSQL.
All existing clients become **legacy**, retaining their previous behavior.
OIDC code/token absence alone cannot prove an old client never received an Auth
grant: grant creation can commit before code issuance fails. Consequently, a
full legacy store stays protected until the operator performs the following
cross-store recovery. Never delete old client rows based only on age or OIDC
token expiry.

### Local SQLite recovery

Use a Python environment containing this package and its `maintenance` extra
(`toolframe-core>=0.8.0,<1`). Stop the application cleanly, allow outstanding
ten-minute authorization flows to expire while stopped, and retain the normal
complete application backup, including composition and private keys. Use the
current complete Auth and OIDC stores; do not substitute historical or partial
copies. Recovery derives their paths from Core's validated stopped inventory.

```sh
python -m toolframe_oidc_auth.maintenance --home ./my-app
# Review the eligible count before applying. The backup directory must not exist.
python -m toolframe_oidc_auth.maintenance --home ./my-app \
  --apply --backup-directory ./registration-recovery-backup
```

The command defaults to dry-run. It holds Core's public `stopped_application`
context and application lock throughout inventory, backup and mutation, refusing
running applications, uncertain worker ownership, external stores and unsafe
layouts. It also locks both SQLite stores, verifies their application/owner
identities, refuses any unexpired flow, and preserves **every** client referenced
by any Auth grant, OIDC code or OIDC token, including historical records.
Missing/malformed evidence aborts recovery. Apply first writes consistent private
SQLite backups of both stores, then reclassifies only unreferenced legacy rows
as pending; it deletes no clients, grants, codes or tokens. Their original age
then makes them eligible for normal registration cleanup. Restart the application
and retry registration. Do not restore just one store independently of its paired
backup and the application's normal backup set.

Recovery also requires a Core maintenance parser compatible with the host's
process inventory. Published Core 0.8.0 rejects inventories containing PGID 0,
which can prevent recovery on Linux hosts reporting such entries even when the
application is stopped. This OIDC package does not change or bypass that check.
On affected hosts, recovery requires a Core release containing the PGID 0
inventory correction, targeted for 0.8.1. Verify that the selected released
artifact contains that correction before recovery; Core 0.8.0 does not fix this
limitation. The declared minimum describes maintenance API availability and does
not require an unpublished Core version. Keep the stores unchanged if ownership
cannot be proven.

### PostgreSQL recovery

The local SQLite command deliberately refuses external stores. PostgreSQL v2
migration SQL is included, but automated stopped-application inventory and backup
are not available through that command for PostgreSQL. A database administrator
must perform this equivalent procedure with a separate administrative connection:

1. Stop every Core instance/replica and hold `application_lock(home)` for every
   application home throughout maintenance. Fence database writers before taking
   the backup: record the existing `rolcanlogin` settings, disable login for the
   application's manager and **all** store controller login roles, then terminate
   their existing sessions in this application's database. Runtime roles are
   reached through these connections. Verify no application writers remain;
   include any additional operator/integration writers in the fence. A shared
   deployment must also prevent automatic role reprovisioning during maintenance.
   This database fence prevents a restart or another host from reconnecting.
2. Verify `_toolframe_platform.identity` and both store metadata identities match
   the intended application. Obtain the exact store and metadata schema names
   from the PostgreSQL provisioning configuration. Confirm complete current Auth
   grant history is available. Take and verify a full database backup with
   `pg_dump`, retaining the application's composition and secret backups too.
3. Wait for all existing ten-minute OIDC flows to expire. Run the checked-in
   [recovery SQL](legacy-registration-postgresql.sql) using `psql -X` and explicit
   variables. It defaults to rollback after listing candidate IDs:

   ```sh
   psql -X "$ADMIN_DSN" -v application_id="$APPLICATION_ID" \
     -v oidc_schema="$OIDC_SCHEMA" -v oidc_meta="$OIDC_META_SCHEMA" \
     -v auth_schema="$AUTH_SCHEMA" -v auth_meta="$AUTH_META_SCHEMA" \
     -f docs/legacy-registration-postgresql.sql
   # Repeat the same command with -v apply=true only after review and backup.
   ```

   The transaction locks identity and authority tables, rejects mismatched
   identities/live flows/malformed code bindings, and changes only legacy clients
   with no grant/code/token references to pending. It preserves historical
   references as well as active ones. Any error rolls back on disconnect.
4. Verify the reclassified rows and preserved references before restoring only
   the recorded login settings, releasing application locks, and starting Core.
   Keep the writer fence in place until the transaction and verification finish.

The SQL file implements classification and mutation, not the operational writer
fence or backup. Run it only after those steps are independently verified. SQL
execution against a temporary PostgreSQL database does not establish successful
managed PostgreSQL deployment, multi-host fencing, or restore verification.

## Verification boundaries

The maintenance unit tests use a synthetic Core journal/artifact layout and a
controlled `ps` response. They execute Core's real inventory parser, worker
ownership checks and application lock, alongside real managed SQLite and Auth
grants. They verify rejection of matching workers and invalid process snapshots,
but do not establish compatibility with a live Linux host's complete process
table. Validate the installed Core version's maintenance behavior on the target
host before relying on offline recovery.
