import json
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from conftest import caller
from toolframe_sdk import PluginError

from toolframe_oidc_auth.plugin import SERVICE, TOKEN_SERVICE


async def http(
    provider, path, data=None, *, method="GET", browser="", actor=None, body=None
):
    with caller(actor=actor):
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
    replay = await http(oidc, "/oauth/token", request, method="POST")
    assert replay["status"] == 400
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
