
CREATE TABLE oauth_clients (id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL);
CREATE TABLE oauth_flows (
 id TEXT PRIMARY KEY, browser_digest TEXT NOT NULL, data TEXT NOT NULL, expires_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE oauth_codes (
 digest TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at DOUBLE PRECISION NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE oauth_tokens (
 id TEXT PRIMARY KEY, access_digest TEXT NOT NULL UNIQUE, refresh_digest TEXT UNIQUE,
 grant_id TEXT NOT NULL, client_id TEXT NOT NULL, resource TEXT NOT NULL,
 scopes TEXT NOT NULL, expires_at DOUBLE PRECISION NOT NULL, refresh_expires_at DOUBLE PRECISION NOT NULL,
 refresh_used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX oauth_tokens_grant ON oauth_tokens(grant_id);
