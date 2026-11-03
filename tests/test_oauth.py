import json
import re
import secrets
import uuid
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from conftest import caller
from toolframe_sdk import PluginError

from toolframe_oidc_auth.plugin import SERVICE, TOKEN_SERVICE


async def http(
    provider, path, data=None, *, method="GET", browser="", actor=None, body=None
):
    with caller(actor=actor, root_id=uuid.uuid4().hex):
        return await provider.invoke(
            SERVICE,
            "http",
            {
                "method": method,
                "path": path,
                "query": urlencode(data or {}) if method == "GET" else "",
                "body": body
                if body is not None
                else urlencode(data or {})
                if method == "POST"
                else "",
                "browser": browser,
                "headers": {},
            },
        )


async def code(provider, actor, **changes):
    verifier = secrets.token_urlsafe(48)
    request = {
        "client_id": "agent",
        "redirect_uri": "http://127.0.0.1:4444/callback",
        "response_type": "code",
        "state": "client-state",
        "scope": "notes.read",
        "resource": "https://app.test/mcp",
        "code_challenge_method": "S256",
        "code_challenge": create_s256_code_challenge(verifier),
        **changes,
    }
    consent = await http(provider, "/oauth/authorize", request, actor=actor)
    assert consent["status"] == 200, consent
    fields = dict(
        re.findall(r'name="(transaction|csrf)" value="([^"]+)"', consent["body"])
    )
    result = await http(
        provider,
        "/oauth/consent",
        {**fields, "decision": "allow"},
        method="POST",
        browser=consent["browser"],
        actor=actor,
    )
    assert result["status"] == 302, result
    callback = parse_qs(urlsplit(result["headers"]["Location"]).query)
    assert callback["state"] == ["client-state"] and callback["iss"] == [
        "https://app.test/oauth"
    ]
    return {
        "grant_type": "authorization_code",
        "client_id": request["client_id"],
        "code": callback["code"][0],
        "redirect_uri": request["redirect_uri"],
        "resource": request["resource"],
        "code_verifier": verifier,
    }


async def test_code_pkce_resource_replay_and_revocation(provider):
    oidc, auth, login = provider
    request = await code(oidc, login["principal"])
    wrong = await http(
        oidc, "/oauth/token", {**request, "code_verifier": "x" * 43}, method="POST"
    )
    assert wrong["status"] == 400
    wrong_resource = await http(
        oidc,
        "/oauth/token",
        {**request, "resource": "https://other.test/mcp"},
        method="POST",
    )
    assert wrong_resource["status"] == 400
    result = await http(oidc, "/oauth/token", request, method="POST")
    assert result["status"] == 200, result
    token = json.loads(result["body"])
    assert token["scope"] == "notes.read" and "id_token" not in token
    with caller():
        identity = (
            await oidc.invoke(
                TOKEN_SERVICE,
                "verify",
                {"token": token["access_token"], "resource": "https://app.test/mcp"},
            )
        )["principal"]
        assert identity["kind"] == "delegated" and identity["scopes"] == ("notes.read",)
        with pytest.raises(PluginError):
            await oidc.invoke(
                TOKEN_SERVICE,
                "verify",
                {"token": token["access_token"], "resource": "https://other.test/mcp"},
            )
        with pytest.raises(PluginError):
            await oidc.invoke(
                TOKEN_SERVICE,
                "verify",
                {"token": token["refresh_token"], "resource": "https://app.test/mcp"},
            )
    with caller("auth", login["principal"]):
        await auth.invoke(
            "toolframe.auth", "revoke_grant", {"id": identity["grant_id"]}
        )
        assert (
            await auth.invoke("toolframe.auth", "resolve", {"token": login["token"]})
        )["principal"]["kind"] == "user"
    with caller(), pytest.raises(PluginError):
        await oidc.invoke(
            TOKEN_SERVICE,
            "resolve",
            {"id": identity["credential_id"], "resource": "https://app.test/mcp"},
        )


async def test_refresh_rotation_replay_revokes_family(provider):
    oidc, _, login = provider
    request = await code(oidc, login["principal"])
    first = json.loads(
        (await http(oidc, "/oauth/token", request, method="POST"))["body"]
    )
    refresh = {
        "grant_type": "refresh_token",
        "client_id": "agent",
        "resource": "https://app.test/mcp",
        "refresh_token": first["refresh_token"],
    }
    result = await http(oidc, "/oauth/token", refresh, method="POST")
    assert result["status"] == 200, result
    second = json.loads(result["body"])
    assert second["refresh_token"] != first["refresh_token"]
    assert (await http(oidc, "/oauth/token", refresh, method="POST"))["status"] == 400
    with caller(), pytest.raises(PluginError):
        await oidc.invoke(
            TOKEN_SERVICE,
            "verify",
            {"token": second["access_token"], "resource": "https://app.test/mcp"},
        )


async def test_consent_browser_binding_and_bad_redirect(provider):
    oidc, _, login = provider
    invalid = await http(
        oidc,
        "/oauth/authorize",
        {
            "client_id": "agent",
            "redirect_uri": "https://evil.test/callback",
            "response_type": "code",
        },
    )
    assert invalid["status"] == 400 and "Location" not in invalid["headers"]
    verifier = secrets.token_urlsafe(48)
    result = await http(
        oidc,
        "/oauth/authorize",
        {
            "client_id": "agent",
            "redirect_uri": "http://127.0.0.1:4444/callback",
            "response_type": "code",
            "scope": "notes.read",
            "resource": "https://app.test/mcp",
            "code_challenge_method": "S256",
            "code_challenge": create_s256_code_challenge(verifier),
        },
        actor=login["principal"],
    )
    fields = dict(
        re.findall(r'name="(transaction|csrf)" value="([^"]+)"', result["body"])
    )
    with pytest.raises(PluginError, match="transaction"):
        await http(
            oidc,
            "/oauth/consent",
            {**fields, "decision": "allow"},
            method="POST",
            browser="a" * 43,
            actor=login["principal"],
        )
    assert (
        await http(
            oidc,
            "/oauth/consent",
            {**fields, "decision": "deny"},
            method="POST",
            browser=result["browser"],
            actor=login["principal"],
        )
    )["status"] == 302


async def test_dynamic_registration_and_upstream_token_rejection(provider):
    oidc, _, _ = provider
    registration = {
        "client_name": "Desktop Agent",
        "redirect_uris": ["http://127.0.0.1:53212/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    result = await http(
        oidc, "/oauth/register", method="POST", body=json.dumps(registration)
    )
    assert result["status"] == 201, result
    assert "client_id" in json.loads(result["body"])
    assert json.loads(result["body"])["token_endpoint_auth_method"] == "none"
    result = await http(
        oidc,
        "/oauth/register",
        method="POST",
        body=json.dumps({**registration, "redirect_uris": ["http://remote.test/cb"]}),
    )
    assert result["status"] == 400
    with caller(), pytest.raises(PluginError):
        await oidc.invoke(
            TOKEN_SERVICE,
            "verify",
            {"token": "google-access-token", "resource": "https://app.test/mcp"},
        )


async def test_local_verification_does_not_wait_on_upstream_login(provider):
    import asyncio

    oidc, _, login = provider
    request = await code(oidc, login["principal"])
    token = json.loads(
        (await http(oidc, "/oauth/token", request, method="POST"))["body"]
    )
    # Browser operations hold this lock while contacting the IdP.
    async with oidc.lock:
        with caller():
            result = await asyncio.wait_for(
                oidc.invoke(
                    TOKEN_SERVICE,
                    "verify",
                    {
                        "token": token["access_token"],
                        "resource": "https://app.test/mcp",
                    },
                ),
                1,
            )
            assert result["principal"]["kind"] == "delegated"


async def verify(oidc, token, *, resolve=None):
    with caller():
        return (
            await oidc.invoke(
                TOKEN_SERVICE,
                "resolve" if resolve else "verify",
                {"id": resolve, "resource": "https://app.test/mcp"}
                if resolve
                else {"token": token, "resource": "https://app.test/mcp"},
            )
        )["principal"]


async def test_authenticated_code_replay_revokes_only_its_grant(provider):
    oidc, auth, login = provider
    # Distinct configured client/resource bindings exercise the inner checks too.
    oidc.config["clients"].append(
        {"client_id": "other", "redirect_uris": ["http://127.0.0.1:4444/callback"]}
    )
    oidc.resources.append("https://app.test/other")
    request = await code(oidc, login["principal"])
    independent = await code(oidc, login["principal"])
    other = json.loads(
        (await http(oidc, "/oauth/token", independent, method="POST"))["body"]
    )
    token = json.loads(
        (await http(oidc, "/oauth/token", request, method="POST"))["body"]
    )
    identity = await verify(oidc, token["access_token"])
    assert (await verify(oidc, None, resolve=identity["credential_id"])) == identity
    rotated = json.loads(
        (
            await http(
                oidc,
                "/oauth/token",
                {
                    "grant_type": "refresh_token",
                    "client_id": "agent",
                    "resource": request["resource"],
                    "refresh_token": token["refresh_token"],
                },
                method="POST",
            )
        )["body"]
    )
    for change in (
        {"client_id": "other"},
        {"client_id": "missing"},
        {"redirect_uri": "http://127.0.0.1:4444/wrong"},
        {"resource": "https://app.test/other"},
        {"code_verifier": "x" * 43},
        {"code_verifier": ""},
        {"code_verifier": "!" * 43},
    ):
        denied = await http(oidc, "/oauth/token", {**request, **change}, method="POST")
        assert denied["status"] == 400, denied
        await verify(oidc, rotated["access_token"])
    replay = await http(oidc, "/oauth/token", request, method="POST")
    assert (
        replay["status"] == 400
        and json.loads(replay["body"])["error"] == "invalid_grant"
    )
    for value in (token, rotated):
        with pytest.raises(PluginError):
            await verify(oidc, value["access_token"])
        denied = await http(
            oidc,
            "/oauth/token",
            {
                "grant_type": "refresh_token",
                "client_id": "agent",
                "resource": request["resource"],
                "refresh_token": value["refresh_token"],
            },
            method="POST",
        )
        assert denied["status"] == 400
    with pytest.raises(PluginError):
        await verify(oidc, None, resolve=identity["credential_id"])
    await verify(oidc, other["access_token"])
    with caller():
        with pytest.raises(PluginError):
            await auth.invoke(
                "toolframe.auth", "grant_check", {"id": identity["grant_id"]}
            )
        assert (
            await auth.invoke("toolframe.auth", "resolve", {"token": login["token"]})
        )["principal"]["kind"] == "user"


async def test_expired_used_code_cannot_revoke_an_existing_grant(provider):
    oidc, _, login = provider
    request = await code(oidc, login["principal"])
    issued = await http(oidc, "/oauth/token", request, method="POST")
    assert issued["status"] == 200
    with caller():
        await oidc.store.execute("UPDATE oauth_codes SET expires_at=0 WHERE used=1")
    assert (await http(oidc, "/oauth/token", request, method="POST"))["status"] == 400
    await verify(oidc, json.loads(issued["body"])["access_token"])


async def test_concurrent_code_exchange_issues_once_then_revokes(provider):
    import asyncio

    oidc, _, login = provider
    request = await code(oidc, login["principal"])
    replies = await asyncio.gather(
        *(http(oidc, "/oauth/token", request, method="POST") for _ in range(8))
    )
    assert sorted(reply["status"] for reply in replies) == [200] + [400] * 7
    token = json.loads(
        next(reply["body"] for reply in replies if reply["status"] == 200)
    )
    with caller():
        records = await oidc.store.query("SELECT id,revoked FROM oauth_tokens")
    assert len(records) == 1 and records[0]["revoked"] == 1
    with pytest.raises(PluginError):
        await verify(oidc, token["access_token"])


async def test_logout_permissions_and_account_offboarding(provider):
    oidc, auth, login = provider
    request = await code(oidc, login["principal"], scope="notes.read notes.write")
    token = json.loads(
        (await http(oidc, "/oauth/token", request, method="POST"))["body"]
    )
    with caller():
        await auth.invoke("toolframe.auth", "logout", {"token": login["token"]})
    assert set((await verify(oidc, token["access_token"]))["scopes"]) == {
        "notes.read",
        "notes.write",
    }
    update = {
        "id": login["principal"]["user_id"],
        "scopes": ["notes.read"],
        "disabled": False,
    }
    with caller(actor={"kind": "operator"}):
        await auth.invoke("toolframe.auth", "user_update", update)
    assert (await verify(oidc, token["access_token"]))["scopes"] == ("notes.read",)
    with caller(actor={"kind": "operator"}):
        await auth.invoke("toolframe.auth", "user_update", {**update, "disabled": True})
    with pytest.raises(PluginError):
        await verify(oidc, token["access_token"])
    with caller(actor={"kind": "operator"}):
        await auth.invoke("toolframe.auth", "user_update", update)
    # Re-enabling the account does not restore revoked connections.
    with pytest.raises(PluginError):
        await verify(oidc, token["access_token"])


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
async def test_v1_code_and_token_survive_migration_and_replay(provider, storage):
    import time

    from toolframe_sql_sqlite.plugin import ADMIN_SERVICE

    from toolframe_oidc_auth.models import digest
    from toolframe_oidc_auth.plugin import plugin

    oidc, auth, login = provider
    verifier, value = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    with caller(actor=login["principal"]):
        grant = await auth.invoke(
            "toolframe.auth",
            "grant_create",
            {
                "user_id": login["principal"]["user_id"],
                "issuer": oidc.issuer,
                "client_id": "agent",
                "client_name": "Agent",
                "resource": "https://app.test/mcp",
                "scopes": ["notes.read"],
                "expires_at": time.time() + 3600,
            },
        )
        await oidc.store.execute(
            "INSERT INTO oauth_codes(digest,data,expires_at) VALUES(?,?,?)",
            [
                digest(value),
                json.dumps(
                    {
                        "client_id": "agent",
                        "redirect_uri": "http://127.0.0.1:4444/callback",
                        "scope": "notes.read",
                        "resource": "https://app.test/mcp",
                        "grant_id": grant["id"],
                        "code_challenge": create_s256_code_challenge(verifier),
                    }
                ),
                time.time() + 60,
            ],
        )
    request = {
        "grant_type": "authorization_code",
        "client_id": "agent",
        "code": value,
        "redirect_uri": "http://127.0.0.1:4444/callback",
        "resource": "https://app.test/mcp",
        "code_verifier": verifier,
    }
    result = await http(oidc, "/oauth/token", request, method="POST")
    assert result["status"] == 200, result
    token = json.loads(result["body"])
    with caller(management=True):
        plan = await storage.invoke(
            ADMIN_SERVICE,
            "plan",
            {"owner": "oidc-auth", "schema": plugin.store.model_dump()},
        )
        await storage.invoke(
            ADMIN_SERVICE,
            "apply",
            {
                "owner": "oidc-auth",
                "schema": plugin.store.model_dump(),
                "plan_id": plan["plan_id"],
            },
        )
    await verify(oidc, token["access_token"])
    assert (await http(oidc, "/oauth/token", request, method="POST"))["status"] == 400
    with pytest.raises(PluginError):
        await verify(oidc, token["access_token"])
