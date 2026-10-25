"""Capacity recovery through the real Authlib endpoint and managed SQLite."""

import json
import re
import secrets
import time
from contextlib import asynccontextmanager

import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from conftest import caller
from test_oauth import code, http
from toolframe_auth.plugin import AuthProvider
from toolframe_sql_sqlite.plugin import SqliteProvider

from toolframe_oidc_auth.plugin import TOKEN_SERVICE, OidcAuth


async def register(oidc, **changes):
    return await http(
        oidc,
        "/oauth/register",
        method="POST",
        body=json.dumps(
            {
                "client_name": "Desktop Agent",
                "redirect_uris": ["http://127.0.0.1:4444/callback"],
                **changes,
            }
        ),
    )


async def test_full_pending_pool_accepts_another_client(provider):
    oidc, _, _ = provider
    oidc.config["max_clients"] = 2
    first, second = await register(oidc), await register(oidc)
    assert first["status"] == second["status"] == 201
    assert (
        json.loads(first["body"])["client_id"]
        != json.loads(second["body"])["client_id"]
    )
    third = await register(oidc, client_name="Another legitimate agent")
    assert third["status"] == 201, third
    with caller():
        rows = await oidc.store.query("SELECT * FROM oauth_clients")
    assert len(rows) == 2
    assert json.loads(third["body"])["client_id"] in {row["id"] for row in rows}


async def authorize(oidc, client_id, actor=None):
    return await http(
        oidc,
        "/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:4444/callback",
            "response_type": "code",
            "scope": "notes.read",
            "resource": "https://app.test/mcp",
            "code_challenge_method": "S256",
            "code_challenge": create_s256_code_challenge(secrets.token_urlsafe(48)),
        },
        actor=actor,
    )


async def rows(oidc):
    with caller():
        return await oidc.store.query(
            "SELECT * FROM oauth_clients ORDER BY created_at,id"
        )


@asynccontextmanager
async def restart(provider, storage):
    oidc, auth, login = provider
    await storage.dispose()
    replacement = SqliteProvider(storage.context)
    await replacement.activate()
    oidc.context.peer.router["sql"] = replacement
    auth = AuthProvider(auth.context)
    oidc.context.peer.router["auth"] = auth
    oidc = OidcAuth(oidc.context)
    try:
        with caller("auth"):
            await auth.activate()
        with caller():
            await oidc.activate()
        yield oidc, auth, login
    finally:
        await replacement.dispose()


async def test_pending_expiry_is_enforced_and_reclaimed(provider):
    oidc, _, _ = provider
    oidc.config.update(max_clients=2, pending_client_seconds=60)
    old = json.loads((await register(oidc))["body"])["client_id"]
    other = json.loads((await register(oidc))["body"])["client_id"]
    with caller():
        await oidc.store.execute(
            "UPDATE oauth_clients SET created_at=? WHERE id=?", [time.time() - 61, old]
        )
    assert (await authorize(oidc, old))["status"] == 400
    assert (await register(oidc))["status"] == 201
    assert old not in {row["id"] for row in await rows(oidc)}
    assert other in {row["id"] for row in await rows(oidc)}


async def test_authenticated_flow_has_bounded_protection_across_restart(
    provider, storage
):
    oidc, _, login = provider
    oidc.config["max_clients"] = 1
    identifier = json.loads((await register(oidc))["body"])["client_id"]
    consent = await authorize(oidc, identifier, login["principal"])
    assert consent["status"] == 200
    fields = dict(
        re.findall(r'name="(transaction|csrf)" value="([^"]+)"', consent["body"])
    )
    assert (await register(oidc))["status"] == 400
    async with restart(provider, storage) as (oidc, _, _):
        assert (await register(oidc))["status"] == 400
        allowed = await http(
            oidc,
            "/oauth/consent",
            {**fields, "decision": "allow"},
            method="POST",
            browser=consent["browser"],
            actor=login["principal"],
        )
        assert allowed["status"] == 302, allowed
        assert (await rows(oidc))[0]["registration_state"] == "retained"


async def test_anonymous_flow_does_not_reserve_and_expired_lease_reclaims(provider):
    oidc, _, login = provider
    oidc.config["max_clients"] = 1
    identifier = json.loads((await register(oidc))["body"])["client_id"]
    assert (await authorize(oidc, identifier))["status"] == 200
    assert (await rows(oidc))[0]["protected_until"] == 0
    assert (await register(oidc))["status"] == 201
    assert (await authorize(oidc, identifier))["status"] == 400
    identifier = (await rows(oidc))[0]["id"]
    assert (await authorize(oidc, identifier, login["principal"]))["status"] == 200
    with caller():
        await oidc.store.execute(
            "UPDATE oauth_clients SET protected_until=?", [time.time() - 1]
        )
    assert (await register(oidc))["status"] == 201
    assert identifier not in {row["id"] for row in await rows(oidc)}


async def test_retained_client_code_tokens_and_refresh_survive_pressure_and_restart(
    provider, storage
):
    oidc, _, login = provider
    oidc.config["max_clients"] = 2
    identifier = json.loads((await register(oidc))["body"])["client_id"]
    request = await code(oidc, login["principal"], client_id=identifier)
    assert (await rows(oidc))[0]["registration_state"] == "retained"
    for _ in range(4):
        assert (await register(oidc))["status"] == 201
    wrong = await http(
        oidc, "/oauth/token", {**request, "code_verifier": "x" * 43}, method="POST"
    )
    assert wrong["status"] == 400
    async with restart(provider, storage) as (oidc, _, _):
        result = await http(oidc, "/oauth/token", request, method="POST")
        assert result["status"] == 200, result
        token = json.loads(result["body"])
        for _ in range(3):
            assert (await register(oidc))["status"] == 201
        with caller():
            verified = await oidc.invoke(
                TOKEN_SERVICE,
                "verify",
                {
                    "token": token["access_token"],
                    "resource": "https://app.test/mcp",
                },
            )
        assert verified["principal"]["client_id"] == identifier
        refresh = await http(
            oidc,
            "/oauth/token",
            {
                "grant_type": "refresh_token",
                "client_id": identifier,
                "refresh_token": token["refresh_token"],
                "resource": "https://app.test/mcp",
            },
            method="POST",
        )
        assert refresh["status"] == 200, refresh
        assert json.loads(refresh["body"])["refresh_token"] != token["refresh_token"]
        assert (await code(oidc, login["principal"]))["client_id"] == "agent"


async def test_all_retained_capacity_rejects_without_deleting_and_disabled_is_inert(
    provider,
):
    oidc, _, login = provider
    oidc.config["max_clients"] = 1
    identifier = json.loads((await register(oidc))["body"])["client_id"]
    await code(oidc, login["principal"], client_id=identifier)
    before = await rows(oidc)
    assert (await register(oidc))["status"] == 400
    assert await rows(oidc) == before
    oidc.config["dynamic_registration"] = False
    assert (await register(oidc))["status"] != 201
    assert "registration_endpoint" not in oidc.metadata()
    assert await rows(oidc) == before


@pytest.mark.parametrize(
    "metadata", [{"scope": "unknown"}, {"redirect_uris": ["http://remote.test/cb"]}]
)
async def test_invalid_metadata_does_not_evict_pending(provider, metadata):
    oidc, _, _ = provider
    oidc.config["max_clients"] = 1
    assert (await register(oidc))["status"] == 201
    before = await rows(oidc)
    assert (await register(oidc, **metadata))["status"] == 400
    assert await rows(oidc) == before


async def test_disabled_registration_does_not_reclaim_expired_pending(provider):
    oidc, _, _ = provider
    assert (await register(oidc))["status"] == 201
    with caller():
        await oidc.store.execute("UPDATE oauth_clients SET created_at=0")
    oidc.config["dynamic_registration"] = False
    before = await rows(oidc)
    assert (await register(oidc))["status"] != 201
    assert await rows(oidc) == before
