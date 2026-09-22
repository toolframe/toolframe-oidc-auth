"""Exercise Authlib OIDC verification against a signed, controlled identity provider."""

import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from conftest import caller
from joserfc import jwt
from joserfc.jwk import RSAKey
from test_oauth import http
from toolframe_sdk import PluginError


@pytest.mark.parametrize("invalid", [None, "iss", "aud", "nonce", "exp", "signature"])
async def test_oidc_signature_claims_pkce_and_browser_binding(provider, invalid):
    oidc, auth, existing = provider
    key = RSAKey.generate_key(2048)
    key.ensure_kid()
    authorization = {}
    exchanges = []

    def upstream(request):
        if request.url.path == "/.well-known/openid-configuration":
            return httpx2.Response(
                200,
                json={
                    "issuer": "https://identity.test",
                    "authorization_endpoint": "https://identity.test/authorize",
                    "token_endpoint": "https://identity.test/token",
                    "jwks_uri": "https://identity.test/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if request.url.path == "/jwks":
            return httpx2.Response(200, json={"keys": [key.as_dict(private=False)]})
        assert request.url.path == "/token"
        form = parse_qs(request.content.decode())
        assert (
            create_s256_code_challenge(form["code_verifier"][0])
            == authorization["code_challenge"][0]
        )
        assert form["redirect_uri"] == [
            "https://app.test/_toolframe/oidc/callback/fixture"
        ]
        exchanges.append(form)
        claims = {
            "iss": "https://identity.test",
            "sub": "user",
            "aud": "app",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "nonce": authorization["nonce"][0],
        }
        if invalid in {"iss", "aud", "nonce"}:
            claims[invalid] = "wrong"
        elif invalid == "exp":
            claims["exp"] = int(time.time()) - 600
        signing_key = RSAKey.generate_key(2048) if invalid == "signature" else key
        encoded = jwt.encode({"alg": "RS256", "kid": key.kid}, claims, signing_key)
        return httpx2.Response(
            200,
            json={
                "access_token": "upstream-only",
                "token_type": "Bearer",
                "id_token": encoded,
            },
        )

    client = oidc.oauth.create_client("fixture")
    client.client_kwargs["transport"] = httpx2.MockTransport(upstream)
    start = await http(oidc, "/_toolframe/oidc/login/fixture")
    authorization.update(parse_qs(urlsplit(start["headers"]["Location"]).query))
    data = {"state": authorization["state"][0], "code": "upstream-code"}
    with pytest.raises(PluginError, match="transaction"):
        await http(oidc, "/_toolframe/oidc/callback/fixture", data, browser="x" * 43)
    assert not exchanges
    if invalid:
        with pytest.raises(PluginError):
            await http(
                oidc,
                "/_toolframe/oidc/callback/fixture",
                data,
                browser=start["browser"],
            )
    else:
        result = await http(
            oidc, "/_toolframe/oidc/callback/fixture", data, browser=start["browser"]
        )
        assert result["headers"]["Location"] == "/"
        with caller():
            resolved = await auth.invoke(
                "toolframe.auth", "resolve", {"token": result["session"]["token"]}
            )
        assert resolved["principal"]["user_id"] == existing["principal"]["user_id"]
        assert "upstream-only" not in json.dumps(result)
    with pytest.raises(PluginError, match="transaction"):
        await http(
            oidc, "/_toolframe/oidc/callback/fixture", data, browser=start["browser"]
        )
