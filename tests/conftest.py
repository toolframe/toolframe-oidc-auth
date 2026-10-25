import time
from contextlib import contextmanager

import pytest
from toolframe_auth.plugin import AuthProvider
from toolframe_auth.plugin import plugin as auth_definition
from toolframe_sdk import RuntimeContext, call_context
from toolframe_sql_sqlite.plugin import ADMIN_SERVICE, SQL_SERVICE, SqliteProvider

from toolframe_oidc_auth.plugin import OidcAuth, plugin

CATALOG = {
    "notes.read": {"category": "business"},
    "notes.write": {"category": "business"},
    "system.auth.self": {"category": "system"},
}


@contextmanager
def caller(owner="oidc-auth", actor=None, **extra):
    handle = call_context.set(
        {
            "owner": owner,
            "owner_generation": "one",
            "root_id": "root",
            "chain": [owner],
            "application_id": "test",
            "deadline": time.time() + 30,
            "scope_catalog": CATALOG,
            "principal": actor,
            **extra,
        }
    )
    try:
        yield
    finally:
        call_context.reset(handle)


class Peer:
    def __init__(self, owner, router):
        self.owner, self.router = owner, router

    async def request(self, method, params, timeout=None):
        assert method == "service.call"
        target = self.router[params["alias"]]
        current = call_context.get() or {}
        with caller(self.owner, current.get("principal")):
            return await target.invoke(
                SQL_SERVICE if params["alias"] == "sql" else "toolframe.auth",
                params["method"],
                params["params"],
            )


@pytest.fixture
async def storage(tmp_path):
    storage = SqliteProvider(
        RuntimeContext(
            None,
            plugin_id="sql-sqlite",
            generation="one",
            state_directory=tmp_path / "data",
        )
    )
    await storage.activate()
    try:
        yield storage
    finally:
        await storage.dispose()


@pytest.fixture
async def provider(tmp_path, storage, request):
    for definition in (auth_definition, plugin):
        schema = definition.store.model_dump()
        if definition.id == "oidc-auth" and getattr(request, "param", None) == "v1":
            schema["revision"] = "v1"
            schema["migrations"] = schema["migrations"][:1]
        with caller(management=True):
            await storage.invoke(
                ADMIN_SERVICE,
                "ensure_store",
                {"owner": definition.id, "schema": schema},
            )
    router = {"sql": storage}
    auth = AuthProvider(
        RuntimeContext(
            Peer("auth", router),
            plugin_id="auth",
            generation="one",
            private_secrets={"password-lookup": "ab" * 32},
            config={
                "federated_identities": [
                    {
                        "issuer": "https://identity.test",
                        "subject": "user",
                        "label": "User",
                        "scopes": ["notes.read", "notes.write"],
                    }
                ],
            },
        )
    )
    router["auth"] = auth
    secret = tmp_path / "client-secret"
    secret.write_text("fixture-client-secret")
    secret.chmod(0o600)
    oidc = OidcAuth(
        RuntimeContext(
            Peer("oidc-auth", router),
            plugin_id="oidc-auth",
            generation="one",
            private_secrets={"flow-key": "cd" * 32},
            config={
                "public_url": "https://app.test",
                "scopes": ["notes.read", "notes.write"],
                "dynamic_registration": True,
                "providers": {
                    "fixture": {
                        "issuer": "https://identity.test",
                        "server_metadata_url": "https://identity.test/.well-known/openid-configuration",
                        "client_id": "app",
                        "client_secret_file": str(secret),
                    }
                },
                "clients": [
                    {
                        "client_id": "agent",
                        "client_name": "Example Agent",
                        "redirect_uris": ["http://127.0.0.1:4444/callback"],
                    }
                ],
            },
        )
    )
    with caller("auth"):
        await auth.activate()
    with caller():
        await oidc.activate()
        login = await auth.invoke(
            "toolframe.auth",
            "federated_login",
            {"issuer": "https://identity.test", "subject": "user"},
        )
    yield oidc, auth, login
