"""Opt-in installed-app acceptance using TinyAuth v5.2.0 and a real FastMCP OAuth client.

Requires the integration dependency group. Changes only this fixture user's
agent grants; existing application data and credentials are not edited.
"""

import argparse
import asyncio
import json
import re
import ssl
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx2
from fastmcp import Client
from fastmcp.client.auth import OAuth
from fastmcp.client.transports import StreamableHttpTransport
from mcp.shared.auth import AuthorizationCodeResult
from mcp.shared.exceptions import MCPError


async def tinyauth(browser, url, issuer):
    authorization = await browser.get(url)
    assert authorization.status_code == 302, "TinyAuth authorization failed"
    ticket = parse_qs(urlsplit(authorization.headers["location"]).query)["oidc_ticket"][
        0
    ]
    login = await browser.post(
        issuer + "/api/user/login", json={"username": "user", "password": "password"}
    )
    assert login.status_code == 200, "TinyAuth fixture login failed"
    consent = await browser.post(
        issuer + "/api/oidc/authorize-complete", json={"ticket": ticket}
    )
    assert consent.status_code == 200, "TinyAuth consent failed"
    result = await browser.get(
        consent.json()["redirect_uri"],
        headers={
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
    )
    assert result.status_code in (302, 303), (
        f"Toolframe callback failed: {result.status_code} {result.text}"
    )
    return result


async def run(origin, issuer, ca):
    tls = ssl.create_default_context(cafile=ca)

    def factory(**kwargs):
        return httpx2.AsyncClient(**{"verify": tls, "trust_env": False, **kwargs})

    async with factory() as dashboard, factory() as agent_browser:
        login = await dashboard.get(origin + "/_toolframe/oidc/login/tinyauth")
        assert login.status_code == 303, (
            f"Login start: {login.status_code} {login.text}"
        )
        await tinyauth(dashboard, login.headers["location"], issuer)
        landing = await dashboard.get(
            origin + "/",
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
        )
        assert landing.status_code == 200, (
            f"Dashboard return: {landing.status_code} {landing.text}"
        )
        context = (await dashboard.get(origin + "/_toolframe/auth/context")).json()
        assert context["actor"] == "user" and not context["local_control"], context
        assert "system.auth.self" in context["allowed_scopes"]
        assert (
            await dashboard.get(origin + "/_toolframe/v1/status")
        ).status_code == 403
        print(
            "PASS: real upstream OIDC callback and scoped Dashboard session", flush=True
        )

        class BrowserOAuth(OAuth):
            authorizations = 0
            result = None

            async def redirect_handler(self, authorization_url):
                self.authorizations += 1
                assert self.authorizations == 1, (
                    "Revoked authorization requires a fresh consent"
                )
                page = await agent_browser.get(authorization_url)
                assert page.status_code == 200, (
                    f"Consent: {page.status_code} {page.text}"
                )
                fields = dict(
                    re.findall(r'name="(transaction|csrf)" value="([^"]+)"', page.text)
                )
                assert len(fields) == 2
                consent = await agent_browser.post(
                    origin + "/oauth/consent",
                    data={**fields, "decision": "allow", "provider": "tinyauth"},
                )
                assert consent.status_code == 303, (
                    f"Allow consent: {consent.status_code} {consent.text}"
                )
                callback = await tinyauth(
                    agent_browser, consent.headers["location"], issuer
                )
                query = parse_qs(urlsplit(callback.headers["location"]).query)
                self.result = AuthorizationCodeResult(
                    code=query["code"][0], state=query["state"][0], iss=query["iss"][0]
                )

            async def callback_handler(self):
                assert self.result is not None
                return self.result

        auth = BrowserOAuth(
            origin + "/mcp",
            scopes=["entry-register.read"],
            client_name="Toolframe TinyAuth acceptance",
            httpx_client_factory=factory,
        )
        transport = StreamableHttpTransport(
            origin + "/mcp", auth=auth, httpx_client_factory=factory
        )
        async with Client(transport) as agent:
            tools = await agent.list_tools()
            assert tools, "No scoped tools published"
            tool = next(t for t in tools if "list" in t.name)
            result = await agent.call_tool(tool.name, {})
            assert not result.is_error
            print(
                "PASS: FastMCP discovery, DCR, PKCE, token exchange and real tool call",
                flush=True,
            )
            tokens = await auth.token_storage_adapter.get_tokens()
            assert tokens and tokens.access_token.startswith("tf_oauth_")
            assert "id_token" not in tokens.model_dump(exclude_none=True)
            grants = (
                await dashboard.post(origin + "/_toolframe/v1/auth/grants", json={})
            ).json()["grants"]
            grant = next(
                g
                for g in grants
                if g["client_id"] == auth.context.client_info.client_id
            )
            assert grant["user_id"] == context["user_id"] and grant["scopes"] == [
                "entry-register.read"
            ]
            refreshed = await dashboard.post(
                origin + "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": grant["client_id"],
                    "resource": origin + "/mcp",
                    "refresh_token": tokens.refresh_token,
                },
            )
            assert refreshed.status_code == 200, refreshed.status_code
            rotated = refreshed.json()
            assert rotated["refresh_token"] != tokens.refresh_token
            # Use a real open MCP connection with the refreshed bearer to verify
            # that revocation is checked on the following request, not just login.
            delegated = StreamableHttpTransport(
                origin + "/mcp",
                auth=rotated["access_token"],
                httpx_client_factory=factory,
            )
            async with Client(delegated) as connected:
                assert await connected.list_tools()
                revoke = await dashboard.post(
                    origin + "/_toolframe/v1/auth/revoke_grant",
                    json={"id": grant["id"]},
                )
                assert revoke.status_code == 200
                try:
                    await connected.list_tools()
                except MCPError:
                    print(
                        "PASS: existing MCP connection rejected after revocation",
                        flush=True,
                    )
                else:
                    raise AssertionError("Existing connection survived revocation")
            assert (await dashboard.get(origin + "/_toolframe/auth/context")).json()[
                "actor"
            ] == "user"
            rejected = await dashboard.post(
                origin + "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": grant["client_id"],
                    "resource": origin + "/mcp",
                    "refresh_token": rotated["refresh_token"],
                },
            )
            assert rejected.status_code == 400
            print(
                "PASS: refresh rotation, same local identity, immediate grant revocation; Dashboard stays signed in",
                flush=True,
            )
        print(
            json.dumps(
                {
                    "origin": origin,
                    "issuer": issuer,
                    "tools": [t.name for t in tools],
                    "status": "passed",
                }
            )
        )


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    env = dict(
        line.split("=", 1)
        for line in (root / ".env").read_text().splitlines()
        if line and not line.startswith("#")
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--origin", default=env.get("TOOLFRAME_URL", "https://app.localhost:18444")
    )
    parser.add_argument(
        "--issuer", default=env.get("TINYAUTH_URL", "https://tinyauth.localhost:18443")
    )
    parser.add_argument("--ca", default=str(root / "certs/root.crt"))
    args = parser.parse_args()
    asyncio.run(run(args.origin, args.issuer, args.ca))
