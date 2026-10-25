"""Protocol records: only digests of externally usable credentials are stored."""

import hashlib
import json
import time
from urllib.parse import urlsplit

from authlib.oauth2.rfc6749 import ClientMixin

SCHEMA = """
CREATE TABLE oauth_clients (id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE oauth_flows (
 id TEXT PRIMARY KEY, browser_digest TEXT NOT NULL, data TEXT NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE oauth_codes (
 digest TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE oauth_tokens (
 id TEXT PRIMARY KEY, access_digest TEXT NOT NULL UNIQUE, refresh_digest TEXT UNIQUE,
 grant_id TEXT NOT NULL, client_id TEXT NOT NULL, resource TEXT NOT NULL,
 scopes TEXT NOT NULL, expires_at REAL NOT NULL, refresh_expires_at REAL NOT NULL,
 refresh_used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX oauth_tokens_grant ON oauth_tokens(grant_id);
"""

# Existing registrations cannot be classified without the Auth store: a grant
# may have committed before issuance of a local code failed.
REGISTRATION_SCHEMA = """
ALTER TABLE oauth_clients ADD COLUMN registration_state TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE oauth_clients ADD COLUMN protected_until REAL NOT NULL DEFAULT 0;
CREATE INDEX oauth_clients_registration ON oauth_clients(registration_state,created_at);
"""


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_redirect(value):
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(c) < 33 for c in value)
    ):
        return False
    try:
        uri = urlsplit(value)
        return bool(
            uri.hostname
            and not uri.username
            and not uri.password
            and not uri.fragment
            and (uri.port is None or uri.port > 0)
            and (
                uri.scheme == "https"
                or (
                    uri.scheme == "http"
                    and uri.hostname in {"127.0.0.1", "::1", "localhost"}
                )
            )
        )
    except ValueError:
        return False


class Client(ClientMixin):
    def __init__(self, client_id, metadata):
        self.client_id, self.metadata = client_id, metadata

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.metadata["redirect_uris"][0]

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.metadata["redirect_uris"]

    def get_allowed_scope(self, scope):
        allowed = self.metadata.get("scope", "").split()
        return " ".join(s for s in (scope or " ".join(allowed)).split() if s in allowed)

    def check_client_secret(self, secret):
        return False

    def check_endpoint_auth_method(self, method, endpoint):
        return method == "none"

    def check_response_type(self, response_type):
        return response_type == "code"

    def check_grant_type(self, grant_type):
        return grant_type in self.metadata.get(
            "grant_types", ["authorization_code", "refresh_token"]
        )


class Code:
    def __init__(self, record):
        self.digest = record["digest"]
        self.data = json.loads(record["data"])
        self.code_challenge = self.data["code_challenge"]
        self.code_challenge_method = "S256"

    def get_redirect_uri(self):
        return self.data["redirect_uri"]

    def get_scope(self):
        return self.data["scope"]


class Token:
    def __init__(self, record):
        self.data = record

    def check_client(self, client):
        return self.data["client_id"] == client.client_id

    def get_scope(self):
        return " ".join(json.loads(self.data["scopes"]))

    def is_expired(self):
        return self.data["expires_at"] <= time.time()

    def is_revoked(self):
        return bool(self.data["revoked"])
