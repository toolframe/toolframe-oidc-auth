"""Authlib authorization server adapted to Toolframe's asynchronous stores.

Each call runs in a worker thread while storage stays on the owning event loop.
The caller holds a provider lock and one managed SQL transaction for code/token
consumption and issuance. OAuth validation remains in Authlib's grant classes.
"""

import asyncio
import json
import secrets
import time
import uuid
from concurrent.futures import TimeoutError as FutureTimeout
from urllib.parse import parse_qs, urlsplit

from authlib.oauth2.rfc6749 import (
    AuthorizationServer,
    InvalidGrantError,
    InvalidRequestError,
    OAuth2Request,
)
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload, JsonRequest
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
from authlib.oauth2.rfc7591.errors import InvalidClientMetadataError
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9207 import IssuerParameter
from starlette.datastructures import Headers
from toolframe_sdk import PluginError

from .models import Client, Code, Token, digest, valid_redirect


class Request(OAuth2Request):
    def __init__(self, method, uri, body="", headers=None):
        super().__init__(method, uri, headers=Headers(headers or {}))
        pairs = parse_qs(
            urlsplit(uri).query if method == "GET" else body, keep_blank_values=True
        )
        if any(len(values) != 1 for values in pairs.values()):
            raise InvalidRequestError("Duplicate OAuth parameters")
        self.values = {key: values[0] for key, values in pairs.items()}
        self.payload = BasicOAuth2Payload(self.values)

    @property
    def form(self):
        return self.values if self.method == "POST" else {}

    @property
    def args(self):
        return self.values if self.method == "GET" else {}


class Reply:
    def __init__(self, status, body, headers):
        self.status, self.body, self.headers = status, body, dict(headers)

    @property
    def location(self):
        return self.headers.get("Location")

    @location.setter
    def location(self, value):
        self.headers["Location"] = value

    def result(self):
        return {
            "status": self.status,
            "body": json.dumps(self.body) if isinstance(self.body, dict) else self.body,
            "headers": self.headers,
        }


class S256(CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ("S256",)

    def validate_code_challenge(self, grant, redirect_uri):
        if grant.request.payload.data.get("code_challenge_method") != "S256":
            raise InvalidRequestError("PKCE S256 is required")
        return super().validate_code_challenge(grant, redirect_uri)


class Issuer(IssuerParameter):
    def __init__(self, issuer):
        self.issuer = issuer

    def get_issuer(self):
        return self.issuer


class CodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ("none",)

    def save_authorization_code(self, code, request):
        data = {
            "client_id": request.client.client_id,
            "redirect_uri": request.payload.redirect_uri,
            "scope": request.scope,
            "code_challenge": request.payload.data["code_challenge"],
            "resource": request.payload.data["resource"],
            "grant_id": request.user["id"],
        }
        self.server.sync(
            self.server.store.execute(
                "INSERT INTO oauth_codes(digest,data,expires_at) VALUES(?,?,?)",
                [digest(code), json.dumps(data), time.time() + 60],
            )
        )

    def query_authorization_code(self, code, client):
        rows = self.server.sync(
            self.server.store.query(
                "SELECT * FROM oauth_codes WHERE digest=?", [digest(code)]
            )
        )
        if not rows or rows[0]["used"] or rows[0]["expires_at"] <= time.time():
            return None
        value = Code(rows[0])
        if value.data["client_id"] != client.client_id or value.data[
            "resource"
        ] != self.request.values.get("resource"):
            return None
        return value

    def delete_authorization_code(self, code):
        self.server.sync(
            self.server.store.execute(
                "UPDATE oauth_codes SET used=1 WHERE digest=?", [code.digest]
            )
        )

    def authenticate_user(self, code):
        return self.server.active_grant(code.data["grant_id"], code.get_scope())


class RefreshGrant(RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ("none",)
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, value):
        rows = self.server.sync(
            self.server.store.query(
                "SELECT * FROM oauth_tokens WHERE refresh_digest=?", [digest(value)]
            )
        )
        if not rows:
            return None
        token = Token(rows[0])
        if not token.check_client(self.request.client):
            return None
        if token.data["refresh_used"]:
            # Keep this denial's revocation in the committed SQL transaction.
            self.server.sync(
                self.server.store.execute(
                    "UPDATE oauth_tokens SET revoked=1 WHERE grant_id=?",
                    [token.data["grant_id"]],
                )
            )
            self.server.sync(
                self.server.plugin.context.call(
                    "auth", "revoke_grant", {"id": token.data["grant_id"]}
                )
            )
            return None
        if (
            token.data["revoked"]
            or token.data["refresh_expires_at"] <= time.time()
            or token.data["resource"] != self.request.values.get("resource")
        ):
            return None
        return token

    def authenticate_user(self, token):
        return self.server.active_grant(
            token.data["grant_id"], self.request.payload.scope or token.get_scope()
        )

    def revoke_old_credential(self, token):
        self.server.sync(
            self.server.store.execute(
                "UPDATE oauth_tokens SET refresh_used=1 WHERE id=?", [token.data["id"]]
            )
        )


class Registration(ClientRegistrationEndpoint):
    def extract_client_metadata(self, request):
        # This AS registers public clients only. Select and explicitly return
        # 'none' when a client leaves its authentication method to the server.
        # Explicit requests for secret-based methods remain validation errors.
        if "token_endpoint_auth_method" not in request.payload.data:
            request.payload.data["token_endpoint_auth_method"] = "none"
        return super().extract_client_metadata(request)

    def authenticate_token(self, request):
        return self.server.plugin.config.get("dynamic_registration", False)

    def generate_client_info(self, request):
        return {
            "client_id": secrets.token_urlsafe(24),
            "client_id_issued_at": int(time.time()),
        }

    def get_server_metadata(self):
        return self.server.plugin.metadata()

    def save_client(self, info, metadata, request):
        redirects = metadata.get("redirect_uris", [])
        if (
            not isinstance(redirects, list)
            or not 1 <= len(redirects) <= 10
            or not all(valid_redirect(uri) for uri in redirects)
            or metadata.get("token_endpoint_auth_method", "client_secret_basic")
            != "none"
        ):
            raise InvalidClientMetadataError(
                "Public clients require exact HTTPS or loopback redirects and auth method none"
            )
        name = metadata.get("client_name", "Agent")
        if not isinstance(name, str) or not 1 <= len(name) <= 120:
            raise InvalidClientMetadataError(
                "Supply a client name up to 120 characters"
            )
        scopes = metadata.get("scope", " ".join(self.server.plugin.scopes)).split()
        if not set(scopes) <= set(self.server.plugin.scopes):
            raise InvalidClientMetadataError("Unknown client scopes")
        metadata.update(
            scope=" ".join(scopes),
            client_name=name,
            grant_types=metadata.get(
                "grant_types", ["authorization_code", "refresh_token"]
            ),
        )
        now = time.time()
        self.server.sync(
            self.server.store.execute(
                "DELETE FROM oauth_clients WHERE registration_state='pending' "
                "AND created_at<=? AND protected_until<=?",
                [
                    now - self.server.plugin.config.get("pending_client_seconds", 3600),
                    now,
                ],
            )
        )
        count = self.server.sync(
            self.server.store.query("SELECT COUNT(*) AS n FROM oauth_clients")
        )[0]["n"]
        limit = self.server.plugin.config.get("max_clients", 1000)
        if count >= limit:
            needed = count - limit + 1
            candidates = self.server.sync(
                self.server.store.query(
                    "SELECT id FROM oauth_clients WHERE registration_state='pending' "
                    "AND protected_until<=? ORDER BY created_at,id LIMIT ?",
                    [now, needed],
                )
            )
            if len(candidates) < needed:
                raise InvalidClientMetadataError(
                    "Client registration capacity is protected; retry later or contact the operator"
                )
            for candidate in candidates:
                self.server.sync(
                    self.server.store.execute(
                        "DELETE FROM oauth_clients WHERE id=?", [candidate["id"]]
                    )
                )
        self.server.sync(
            self.server.store.execute(
                "INSERT INTO oauth_clients(id,metadata,created_at,registration_state) "
                "VALUES(?,?,?,'pending')",
                [info["client_id"], json.dumps(metadata), now],
            )
        )
        return Client(info["client_id"], metadata)


class Server(AuthorizationServer):
    def __init__(self, plugin, loop, store):
        super().__init__(scopes_supported=plugin.scopes)
        self.plugin, self.loop, self.store = plugin, loop, store
        self.register_grant(CodeGrant, [S256(required=True)])
        self.register_grant(RefreshGrant)
        self.register_extension(Issuer(plugin.issuer))
        self.register_endpoint(Registration)
        self.register_token_generator(
            "default",
            BearerTokenGenerator(
                lambda **_: "tf_oauth_" + secrets.token_urlsafe(32),
                lambda **_: "tf_refresh_" + secrets.token_urlsafe(32),
                lambda _client, _grant_type: plugin.config.get(
                    "access_token_seconds", 300
                ),
            ),
        )

    def sync(self, coroutine):
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        try:
            return future.result(timeout=25)
        except FutureTimeout:
            future.cancel()
            raise

    def query_client(self, client_id):
        for client in self.plugin.config.get("clients", []):
            if client["client_id"] == client_id:
                return Client(
                    client_id, {"scope": " ".join(self.plugin.scopes), **client}
                )
        rows = self.sync(
            self.store.query("SELECT * FROM oauth_clients WHERE id=?", [client_id])
        )
        if (
            rows
            and rows[0]["registration_state"] == "pending"
            and rows[0]["created_at"]
            + self.plugin.config.get("pending_client_seconds", 3600)
            <= time.time()
            and rows[0]["protected_until"] <= time.time()
        ):
            return None
        return Client(client_id, json.loads(rows[0]["metadata"])) if rows else None

    def active_grant(self, identifier, scope):
        try:
            result = self.sync(
                self.plugin.context.call("auth", "grant_check", {"id": identifier})
            )["grant"]
        except PluginError:
            raise InvalidGrantError("Authorization is no longer available") from None
        if not set(scope.split()) <= set(result["scopes"]):
            raise InvalidGrantError("User permissions changed; authorize again")
        return result

    def save_token(self, token, request):
        grant, now = request.user, time.time()
        lifetime = min(token["expires_in"], int(grant["expires_at"] - now))
        if lifetime <= 0:
            raise InvalidGrantError("Authorization expired")
        token["expires_in"] = lifetime
        self.sync(
            self.store.execute(
                "INSERT INTO oauth_tokens(id,access_digest,refresh_digest,grant_id,client_id,resource,scopes,expires_at,refresh_expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    uuid.uuid4().hex,
                    digest(token["access_token"]),
                    digest(token["refresh_token"])
                    if token.get("refresh_token")
                    else None,
                    grant["id"],
                    request.client.client_id,
                    grant["resource"],
                    json.dumps(token.get("scope", "").split()),
                    now + lifetime,
                    grant["expires_at"],
                ],
            )
        )

    def create_oauth2_request(self, request):
        return request

    def create_json_request(self, request):
        value = JsonRequest(
            request["method"], request["uri"], Headers(request.get("headers", {}))
        )
        try:
            data = json.loads(request.get("body", "{}"))
        except ValueError:
            raise InvalidRequestError("Supply a JSON object") from None
        if not isinstance(data, dict):
            raise InvalidRequestError("Supply a JSON object")
        value.payload = BasicOAuth2Payload(data)
        return value

    def handle_response(self, status, body, headers):
        return Reply(status, body, headers)

    def send_signal(self, *_args, **_kwargs):
        pass
