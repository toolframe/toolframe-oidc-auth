"""Shared OIDC client and OAuth issuer. Core owns public HTTP admission."""

import asyncio
import base64
import hmac
import html
import json
import logging
import re
import secrets
import ssl
import time
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from authlib.integrations.starlette_client import OAuth
from authlib.oauth2.rfc6749 import OAuth2Error
from cryptography.fernet import Fernet
from toolframe_sdk import (
    AuthorizationSpec,
    MethodSpec,
    Migration,
    Plugin,
    PluginDefinition,
    PluginError,
    Principal,
    Requirement,
    ServiceSpec,
    StoreSchema,
)

from .authorization import Request, Server
from .models import REGISTRATION_SCHEMA, SCHEMA, digest, valid_redirect

SERVICE = "toolframe.oidc"
TOKEN_SERVICE = "toolframe.oauth.tokens"
BROWSER_COOKIE = "toolframe_oidc_browser"


def response(body, status=200, *, headers=None):
    return {
        "status": status,
        "body": json.dumps(body) if isinstance(body, dict) else body,
        "headers": {
            "Content-Type": "application/json"
            if isinstance(body, dict)
            else "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            **(headers or {}),
        },
    }


def redirect(url):
    return response("", 303, headers={"Location": url})


def page(title, body):
    return response(
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)} · Toolframe</title><style>"
        "body{font:16px system-ui;max-width:36rem;margin:10vh auto;padding:2rem;line-height:1.6;color:#172337;background:#f6f8fb}"
        "button,select{font:inherit;padding:.7rem 1rem;margin:.5rem .5rem .5rem 0}button{cursor:pointer}code{overflow-wrap:anywhere}"
        f"</style><h1>{html.escape(title)}</h1>{body}</html>",
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "X-Frame-Options": "DENY",
        },
    )


class OidcAuth(Plugin):
    def __init__(self, context):
        super().__init__(context)
        self.config, self.store = context.config, context.sql()
        self.origin = self.config.get("public_url", "").rstrip("/")
        self.issuer = self.origin + "/oauth"
        self.scopes = self.config.get("scopes", [])
        self.resources = self.config.get("resources", [self.origin + "/mcp"])
        self.lock = asyncio.Lock()
        self.oauth = OAuth()
        self.cipher = None

    async def activate(self):
        origin = urlsplit(self.origin)
        if not valid_redirect(self.origin) or origin.path or origin.query:
            raise PluginError(
                "config_invalid",
                "public_url must be an HTTPS origin or HTTP loopback origin",
            )
        if any(not valid_redirect(uri) for uri in self.resources) or any(
            not re.fullmatch(r"[a-z][a-z0-9_.-]+", scope) or scope.startswith("system.")
            for scope in self.scopes
        ):
            raise PluginError(
                "config_invalid", "Supply resource URLs and business scopes"
            )
        clients = self.config.get("clients", [])
        if len({c["client_id"] for c in clients}) != len(clients) or any(
            not valid_redirect(uri)
            for client in clients
            for uri in client["redirect_uris"]
        ):
            raise PluginError(
                "config_invalid",
                "Static clients require unique IDs and exact secure redirects",
            )
        self.cipher = Fernet(
            base64.urlsafe_b64encode(
                bytes.fromhex(self.context.private_secrets["flow-key"])
            )
        )
        for identifier, provider in self.config["providers"].items():
            if any(
                not valid_redirect(provider[key])
                for key in ("issuer", "server_metadata_url")
            ):
                raise PluginError(
                    "config_invalid",
                    "Identity provider URLs must use HTTPS or loopback HTTP",
                )
            if provider.get(
                "token_endpoint_auth_method", "client_secret_basic"
            ) not in {"client_secret_basic", "client_secret_post"}:
                raise PluginError(
                    "config_invalid",
                    "Unsupported upstream client authentication method",
                )
            path = Path(provider["client_secret_file"])
            if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                raise PluginError(
                    "config_invalid",
                    "OIDC client secret files must be private regular files (0600)",
                )
            secret = path.read_text().strip()
            if not secret or len(secret) > 16384:
                raise PluginError(
                    "config_invalid", "OIDC client secret file is empty or too large"
                )
            tls = ssl.create_default_context(cafile=provider.get("ca_file"))
            self.oauth.register(
                identifier,
                server_metadata_url=provider["server_metadata_url"],
                client_id=provider["client_id"],
                client_secret=secret,
                client_kwargs={
                    "scope": "openid profile email",
                    "code_challenge_method": "S256",
                    "verify": tls,
                    "timeout": 15,
                    "trust_env": False,
                    "token_endpoint_auth_method": provider.get(
                        "token_endpoint_auth_method", "client_secret_basic"
                    ),
                },
            )
        logging.getLogger("authlib").setLevel(logging.WARNING)
        await self.store.query("SELECT id FROM oauth_flows LIMIT 1")

    def metadata(self):
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.issuer + "/authorize",
            "token_endpoint": self.issuer + "/token",
            "revocation_endpoint": self.issuer + "/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "scopes_supported": self.scopes,
            **(
                {"registration_endpoint": self.issuer + "/register"}
                if self.config.get("dynamic_registration")
                else {}
            ),
        }

    def providers(self):
        return [
            {
                "id": name,
                "label": value.get("label", name),
                "url": "/_toolframe/oidc/login/" + name,
            }
            for name, value in self.config["providers"].items()
        ]

    async def flow(self, identifier, browser, *, consume=False):
        if not isinstance(identifier, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", identifier
        ):
            raise PluginError(
                "invalid_request", "Authorization transaction is invalid or expired"
            )
        rows = await self.store.query(
            "SELECT * FROM oauth_flows WHERE id=?", [identifier]
        )
        if (
            not rows
            or rows[0]["expires_at"] <= time.time()
            or not hmac.compare_digest(rows[0]["browser_digest"], digest(browser))
        ):
            raise PluginError(
                "invalid_request", "Authorization transaction is invalid or expired"
            )
        if consume:
            await self.store.execute("DELETE FROM oauth_flows WHERE id=?", [identifier])
        return json.loads(self.cipher.decrypt(rows[0]["data"].encode()))

    async def save_flow(self, browser, data, identifier=None):
        await self.store.execute(
            "DELETE FROM oauth_flows WHERE expires_at<=?", [time.time()]
        )
        count = (await self.store.query("SELECT COUNT(*) AS n FROM oauth_flows"))[0][
            "n"
        ]
        if count >= 1000:
            raise PluginError("rate_limited", "Too many pending authorizations")
        identifier = identifier or secrets.token_urlsafe(32)
        await self.store.execute(
            "INSERT INTO oauth_flows VALUES(?,?,?,?)",
            [
                identifier,
                digest(browser),
                self.cipher.encrypt(json.dumps(data).encode()).decode(),
                time.time() + 600,
            ],
        )
        return identifier

    async def upstream_login(self, provider_id, browser, *, pending=None):
        provider = self.config["providers"].get(provider_id)
        if provider is None:
            raise PluginError("invalid_request", "Unknown login provider")
        client = self.oauth.create_client(provider_id)
        metadata = await client.load_server_metadata()
        if metadata.get("issuer") != provider["issuer"]:
            raise PluginError(
                "auth_unavailable",
                "Identity provider issuer does not match configuration",
            )
        callback = self.origin + "/_toolframe/oidc/callback/" + provider_id
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(32)
        result = await client.create_authorization_url(
            callback, state=state, nonce=nonce, code_verifier=verifier
        )
        await self.save_flow(
            browser,
            {
                "provider": provider_id,
                "redirect_uri": callback,
                "nonce": nonce,
                "code_verifier": verifier,
                "pending": pending,
            },
            state,
        )
        return redirect(result["url"])

    async def upstream_callback(self, provider_id, query, browser):
        data = await self.flow(query.get("state"), browser, consume=True)
        if (
            data.get("provider") != provider_id
            or not query.get("code")
            or query.get("error")
        ):
            raise PluginError("invalid_request", "Invalid login callback")
        provider = self.config["providers"][provider_id]
        if query.get("iss") and query["iss"] != provider["issuer"]:
            raise PluginError("invalid_credentials", "Login issuer mismatch")
        client = self.oauth.create_client(provider_id)
        token = await client.fetch_access_token(
            code=query["code"],
            redirect_uri=data["redirect_uri"],
            code_verifier=data["code_verifier"],
        )
        claims = await client.parse_id_token(
            token,
            nonce=data["nonce"],
            claims_options={
                "iss": {"essential": True, "value": provider["issuer"]},
                "sub": {"essential": True},
                "aud": {"essential": True},
            },
        )
        # Claims and upstream credentials stay inside the authentication adapter.
        login = await self.context.call(
            "auth",
            "federated_login",
            {"issuer": provider["issuer"], "subject": claims["sub"]},
        )
        result = (
            await self.authorize_user(data["pending"], login["principal"])
            if data.get("pending")
            else redirect("/")
        )
        result["session"] = {"token": login["token"], "expires_at": login["expires_at"]}
        return result

    async def authorization_server(self, action, request, *, user=None, protect=False):
        loop = asyncio.get_running_loop()
        async with self.store.transaction() as store:
            server = Server(self, loop, store)

            def execute():
                if action == "register":
                    return server.create_endpoint_response(
                        "client_registration", request
                    ).result()
                oauth_request = Request(
                    request["method"],
                    request["uri"],
                    request.get("body", ""),
                    request.get("headers"),
                )
                if oauth_request.values.get("resource") not in self.resources:
                    return response(
                        {
                            "error": "invalid_target",
                            "error_description": "Supply the configured resource URI",
                        },
                        400,
                    )
                if action == "validate":
                    grant = server.get_consent_grant(oauth_request)
                    if not grant.request.scope:
                        return response({"error": "invalid_scope"}, 400)
                    if protect:
                        server.sync(
                            store.execute(
                                "UPDATE oauth_clients SET protected_until=? "
                                "WHERE id=? AND registration_state='pending'",
                                [time.time() + 600, grant.request.client.client_id],
                            )
                        )
                    return {
                        "client_id": grant.request.client.client_id,
                        "client_name": grant.request.client.metadata.get(
                            "client_name", "Agent"
                        ),
                        "scope": grant.request.scope,
                        "resource": oauth_request.values["resource"],
                        "redirect_uri": oauth_request.values.get("redirect_uri"),
                    }
                if action == "authorize":
                    return server.create_authorization_response(
                        oauth_request,
                        grant_user=user,
                        grant=server.get_authorization_grant(oauth_request),
                    ).result()
                return server.create_token_response(oauth_request).result()

            # A cancelled HTTP request must not release the transaction while
            # Authlib's thread is still consuming a code or rotating a token.
            task = asyncio.create_task(asyncio.to_thread(execute))
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                try:
                    await task
                finally:
                    raise

    async def authorize_user(self, pending, actor):
        if actor.get("kind") != "user" or not actor.get("user_id"):
            raise PluginError("forbidden", "Use a user identity to authorize an agent")
        expiry = min(
            time.time() + self.config.get("grant_seconds", 2592000),
            actor.get("expires_at") or float("inf"),
        )
        if expiry <= time.time():
            raise PluginError(
                "invalid_credentials", "Sign in again to authorize an agent"
            )
        # An anonymous pre-login flow does not reserve capacity. It may need a
        # new registration by the time upstream authentication completes.
        validated = await self.authorization_server(
            "validate", pending["request"], protect=True
        )
        if "status" in validated:
            return validated

        # Persist retention before the cross-store grant call. Even a process
        # crash after Auth commits must not leave its client reclaimable.
        # A failed issuance conservatively retains this user-consented client.
        await self.store.execute(
            "UPDATE oauth_clients SET registration_state='retained',protected_until=0 WHERE id=?",
            [pending["client_id"]],
        )
        grant = await self.context.call(
            "auth",
            "grant_create",
            {
                "user_id": actor["user_id"],
                "issuer": self.issuer,
                "client_id": pending["client_id"],
                "client_name": pending["client_name"],
                "resource": pending["resource"],
                "scopes": pending["scope"].split(),
                "expires_at": expiry,
            },
        )
        return await self.authorization_server(
            "authorize", pending["request"], user=grant
        )

    async def consent(self, query, browser, actor):
        pending = await self.flow(query.get("transaction"), browser, consume=True)
        if pending.get("phase") != "consent" or not hmac.compare_digest(
            pending["csrf"], query.get("csrf", "")
        ):
            raise PluginError("invalid_request", "Invalid consent transaction")
        if query.get("decision") != "allow":
            return await self.authorization_server(
                "authorize", pending["request"], user=None
            )
        if pending["user_id"]:
            if not actor or actor.get("user_id") != pending["user_id"]:
                raise PluginError(
                    "invalid_request", "Sign-in changed; start authorization again"
                )
            return await self.authorize_user(pending, actor)
        return await self.upstream_login(
            query.get("provider", ""), browser, pending=pending
        )

    async def verify(self, params, *, resolve=False):
        if resolve:
            identifier = params.get("id", "")
            if not isinstance(identifier, str) or not re.fullmatch(
                r"oauth:[0-9a-f]{32}", identifier
            ):
                raise PluginError("invalid_credentials", "Invalid OAuth credential")
            rows = await self.store.query(
                "SELECT * FROM oauth_tokens WHERE id=?", [identifier[6:]]
            )
        else:
            value = params.get("token", "")
            if not isinstance(value, str) or not re.fullmatch(
                r"tf_oauth_[A-Za-z0-9_-]{43}", value
            ):
                raise PluginError("invalid_credentials", "Invalid OAuth credential")
            rows = await self.store.query(
                "SELECT * FROM oauth_tokens WHERE access_digest=?", [digest(value)]
            )
        if not rows:
            raise PluginError("invalid_credentials", "Invalid OAuth credential")
        token = rows[0]
        if (
            token["revoked"]
            or token["expires_at"] <= time.time()
            or token["resource"] != params.get("resource")
        ):
            raise PluginError(
                "invalid_credentials", "Expired or invalid resource credential"
            )
        grant = (
            await self.context.call("auth", "grant_check", {"id": token["grant_id"]})
        )["grant"]
        if (
            grant["issuer"] != self.issuer
            or grant["client_id"] != token["client_id"]
            or grant["resource"] != token["resource"]
        ):
            raise PluginError("invalid_credentials", "Invalid authorization binding")
        actor = Principal(
            kind="delegated",
            credential_id="oauth:" + token["id"],
            user_id=grant["user_id"],
            client_id=token["client_id"],
            grant_id=grant["id"],
            resource=token["resource"],
            scopes=tuple(
                sorted(set(json.loads(token["scopes"])) & set(grant["scopes"]))
            ),
            expires_at=min(token["expires_at"], grant["expires_at"]),
        )
        if not actor.allows(
            params.get("required_scopes", []),
            self.context.call_info.get("scope_catalog", {}),
        ):
            raise PluginError(
                "forbidden", "This agent has not been granted the required permissions"
            )
        return {"principal": actor.model_dump()}

    async def http(self, params):
        if self.context.call_info.get("owner") != self.context.plugin_id:
            raise PluginError(
                "forbidden",
                "Only the gateway may dispatch authentication HTTP requests",
            )
        method, path = params["method"], params["path"]
        browser = params.get("browser", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", browser):
            browser = secrets.token_urlsafe(32)
        pairs = parse_qs(
            params.get("query", "") if method == "GET" else params.get("body", ""),
            keep_blank_values=True,
        )
        if any(len(value) != 1 for value in pairs.values()):
            raise PluginError("invalid_request", "Duplicate authorization parameters")
        query = {key: value[0] for key, value in pairs.items()}
        request = {
            "method": method,
            "uri": self.origin
            + path
            + ("?" + params["query"] if params.get("query") else ""),
            "body": params.get("body", ""),
            "headers": params.get("headers", {}),
        }
        actor = self.context.call_info.get("principal")
        if path.startswith("/_toolframe/oidc/login/") and method == "GET":
            result = await self.upstream_login(path.rsplit("/", 1)[-1], browser)
        elif path.startswith("/_toolframe/oidc/callback/") and method == "GET":
            result = await self.upstream_callback(
                path.rsplit("/", 1)[-1], query, browser
            )
        elif path == "/oauth/authorize" and method == "GET":
            signed_in = bool(
                actor
                and actor.get("kind") == "user"
                and actor.get("user_id")
                and (
                    actor.get("expires_at") is None or actor["expires_at"] > time.time()
                )
            )
            pending = await self.authorization_server(
                "validate", request, protect=signed_in
            )
            if "status" in pending:
                return pending
            pending.update(
                request=request,
                phase="consent",
                csrf=secrets.token_urlsafe(32),
                user_id=actor["user_id"] if signed_in else None,
            )
            identifier = await self.save_flow(browser, pending)
            options = "".join(
                f'<option value="{html.escape(p["id"], quote=True)}">{html.escape(p["label"])}</option>'
                for p in self.providers()
            )
            select = (
                f'<label>Sign in with <select name="provider">{options}</select></label>'
                if not pending["user_id"]
                else "<p>You are already signed in to Toolframe.</p>"
            )
            scopes = "".join(
                f"<li>{html.escape(s)}</li>" for s in pending["scope"].split()
            )
            result = page(
                "Connect an agent",
                f"<p><strong>{html.escape(pending['client_name'])}</strong> requests access to <code>{html.escape(pending['resource'])}</code>.</p>"
                f"<p>Client: <code>{html.escape(pending['client_id'])}</code></p><p>Return to: <code>{html.escape(pending['redirect_uri'] or '')}</code></p><ul>{scopes}</ul>"
                f'<form method="post" action="/oauth/consent"><input type="hidden" name="transaction" value="{identifier}">'
                f'<input type="hidden" name="csrf" value="{pending["csrf"]}">{select}'
                '<button name="decision" value="allow">Allow access</button><button name="decision" value="deny">Cancel</button></form>',
            )
        elif path == "/oauth/consent" and method == "POST":
            result = await self.consent(query, browser, actor)
        elif path in {"/oauth/token", "/oauth/register"} and method == "POST":
            return await self.authorization_server(path.rsplit("/", 1)[-1], request)
        elif path == "/oauth/revoke" and method == "POST":
            value = query.get("token", "")
            rows = await self.store.query(
                "SELECT * FROM oauth_tokens WHERE access_digest=? OR refresh_digest=?",
                [digest(value), digest(value)],
            )
            if rows and rows[0]["client_id"] == query.get("client_id"):
                await self.context.call(
                    "auth", "revoke_grant", {"id": rows[0]["grant_id"]}
                )
            return response({})
        else:
            return response({"error": "invalid_request"}, 404)
        result["browser"] = browser
        return result

    async def invoke(self, service, method, params):
        # Local verification stays available while a browser waits on the IdP.
        # Storage owns isolation between these reads and protocol transactions.
        if service == TOKEN_SERVICE:
            return await self.verify(params, resolve=method == "resolve")
        if method == "metadata":
            return {
                "authorization_server": self.metadata(),
                "providers": self.providers(),
                "resources": self.resources,
            }
        async with self.lock:
            try:
                return await self.http(params)
            except OAuth2Error as error:
                return response(
                    {"error": error.error, "error_description": error.description},
                    error.status_code,
                )
            except PluginError:
                raise
            except Exception as error:  # noqa: BLE001 -- library faults must not change Dashboard access mode.
                logging.getLogger(__name__).warning(
                    "OIDC operation failed (%s)", type(error).__name__
                )
                raise PluginError(
                    "auth_unavailable",
                    "Authentication is temporarily unavailable; restart the authorization",
                ) from None


PROVIDER_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["issuer", "server_metadata_url", "client_id", "client_secret_file"],
    "properties": {
        name: {"type": "string", "minLength": 1}
        for name in (
            "issuer",
            "server_metadata_url",
            "client_id",
            "client_secret_file",
            "label",
            "ca_file",
            "token_endpoint_auth_method",
        )
    },
}

plugin = PluginDefinition(
    id="oidc-auth",
    kind="provider",
    provider_kind="oidc-auth",
    factory="toolframe_oidc_auth.plugin:OidcAuth",
    authorization=AuthorizationSpec(),
    private_secrets=("flow-key",),
    requires={
        "sql": Requirement(service="toolframe.sql"),
        "auth": Requirement(service="toolframe.auth"),
    },
    services={
        SERVICE: ServiceSpec(
            methods={
                "http": MethodSpec(audience="internal"),
                "metadata": MethodSpec(audience="internal", read_only=True),
            }
        ),
        TOKEN_SERVICE: ServiceSpec(
            methods={
                name: MethodSpec(audience="internal", read_only=True)
                for name in ("verify", "resolve")
            }
        ),
    },
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "required": ["public_url", "providers", "scopes"],
        "properties": {
            "public_url": {"type": "string", "minLength": 1},
            "providers": {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 16,
                "propertyNames": {"pattern": "^[a-z][a-z0-9-]{0,63}$"},
                "additionalProperties": PROVIDER_SCHEMA,
            },
            "scopes": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "resources": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "dynamic_registration": {"type": "boolean"},
            "max_clients": {"type": "integer", "minimum": 1, "maximum": 10000},
            "pending_client_seconds": {
                "type": "integer",
                "minimum": 60,
                "maximum": 86400,
            },
            "access_token_seconds": {"type": "integer", "minimum": 30, "maximum": 900},
            "grant_seconds": {"type": "integer", "minimum": 60, "maximum": 31536000},
            "clients": {
                "type": "array",
                "maxItems": 1000,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["client_id", "client_name", "redirect_uris"],
                    "properties": {
                        "client_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                        },
                        "client_name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 120,
                        },
                        "redirect_uris": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 10,
                            "items": {"type": "string"},
                        },
                    },
                },
            },
        },
    },
    store=StoreSchema(
        revision="v2",
        migrations=(
            Migration(
                revision="v1",
                sql=SCHEMA,
                dialects={
                    "postgresql": files(__package__)
                    .joinpath("migrations", "v1.postgresql.sql")
                    .read_text()
                },
            ),
            Migration(
                revision="v2",
                parent="v1",
                sql=REGISTRATION_SCHEMA,
                dialects={
                    "postgresql": files(__package__)
                    .joinpath("migrations", "v2.postgresql.sql")
                    .read_text()
                },
            ),
        ),
    ),
)
