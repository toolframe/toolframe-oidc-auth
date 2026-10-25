"""Legacy recovery with real managed stores and Core's maintenance boundary.

The Core journal/artifact inventory is a synthetic stopped-layout fixture, not
an installed worker deployment. Its process snapshot is controlled at the ps
collection seam; Core's parser, ownership checks and HostLock remain real.
Auth grants below use the real Auth provider.
"""

import hashlib
import importlib.util
import json
import platform
import shutil
import sqlite3
import subprocess
import time
from contextlib import closing

import pytest
from conftest import caller
from test_registration import register, restart
from toolframe_auth.plugin import plugin as auth_definition
from toolframe_sdk import PluginError
from toolframe_sql_sqlite.plugin import ADMIN_SERVICE
from toolframe_sql_sqlite.plugin import plugin as sql_definition

from toolframe_oidc_auth.maintenance import recover_legacy
from toolframe_oidc_auth.plugin import plugin

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("toolframe_core") is None,
    reason="Core-only offline recovery requires the operator extra; validated in the operator CI lane",
)


@pytest.fixture
def process_snapshot(monkeypatch):
    """Supply this synthetic home's machine inventory without bypassing checks."""
    import toolframe_core.maintenance as core_maintenance

    snapshot = {"stdout": "1 1 /sbin/init\n", "calls": 0}
    run = subprocess.run

    def collect(command, *args, **kwargs):
        if command == ["/bin/ps", "-axo", "pid=,pgid=,command="]:
            snapshot["calls"] += 1
            return subprocess.CompletedProcess(command, 0, snapshot["stdout"], "")
        return run(command, *args, **kwargs)

    monkeypatch.setattr(core_maintenance.subprocess, "run", collect)
    return snapshot


def stopped_layout(tmp_path, data):
    """Build Core's actual validated journal layout around managed SQLite files."""
    import tomlkit
    from toolframe_core._state_sqlite import SQLiteCoreState
    from toolframe_core.config import (
        ConfigFile,
        PluginRequest,
        atomic_write,
        management_token,
    )

    home = tmp_path / "home"
    config = ConfigFile(home)
    composition = config.initialize()
    composition.application.id = "test"
    state = SQLiteCoreState(home)
    management_token(home)
    selected = {}
    for definition in (sql_definition, auth_definition, plugin):
        name = definition.id
        # Inventory verifies hashes, names and interpreter/lock compatibility;
        # no worker is installed or executed by this fixture.
        contents = name.encode()
        checksum = hashlib.sha256(contents).hexdigest()
        relative = f".toolframe/artifacts/{checksum}/{name.replace('-', '_')}-1.0-py3-none-any.whl"
        artifact = home / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(contents)
        environment_id = hashlib.sha256((name + "environment").encode()).hexdigest()
        environment_home = home / f".toolframe/environments/{environment_id}"
        environment_home.mkdir(parents=True)
        (environment_home / "pyvenv.cfg").write_text(
            f"implementation = {platform.python_implementation()}\nversion_info = {platform.python_version()}\n"
        )
        candidate = {
            "id": hashlib.sha256(name.encode()).hexdigest(),
            "plugin_id": name,
            "version": "1.0",
            "artifact": relative,
            "artifact_hash": checksum,
            "definition": definition.model_dump(),
            "config": {},
            "source": {"request": name},
            "environment": {
                "id": environment_id,
                "python": f".toolframe/environments/{environment_id}/bin/python",
                "lock": 'lock-version = "1.0"\n[[packages]]\n'
                f'name = "{name}"\nversion = "1.0"\n'
                f'wheels = [{{url = "file://${{TOOLFRAME_HOME}}/{relative}", hashes = {{sha256 = "{checksum}"}}}}]\n',
            },
        }
        composition.plugins[name] = PluginRequest(source=name)
        state.save_candidate(candidate)
        state.select(name, candidate["id"])
        state.runtime(name, {"state": "stopped", "host_run": "a" * 32})
        selected[name] = {
            "current_candidate": {
                key: candidate[key]
                for key in (
                    "id",
                    "version",
                    "artifact",
                    "artifact_hash",
                    "environment",
                    "source",
                )
            },
            "last_candidate": {
                key: candidate[key]
                for key in (
                    "id",
                    "version",
                    "artifact",
                    "artifact_hash",
                    "environment",
                    "source",
                )
            },
        }
    atomic_write(config.path, tomlkit.dumps(composition.model_dump()))
    state.set_meta("host_run", "a" * 32)
    state.set_meta("worker_owners", {})
    state.set_meta("store_bindings", {"auth": "sql-sqlite", "oidc-auth": "sql-sqlite"})
    state.set_meta("last_valid_composition", composition.model_dump())
    state.set_meta("desired_revision", config.revision)
    state.close()
    atomic_write(
        home / "toolframe.lock",
        json.dumps(
            {
                "format": 1,
                "desired_revision": config.revision,
                "plugins": selected,
            }
        ),
    )
    for owner in ("auth", "oidc-auth"):
        target = home / f"data/plugins/{owner}/data.sqlite"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(data / owner / "data.sqlite", target)
        for secret in (auth_definition if owner == "auth" else plugin).private_secrets:
            key = home / f".toolframe/secrets/{owner}/{secret}.key"
            key.parent.mkdir(parents=True, exist_ok=True)
            key.write_text("ab" * 32)
            key.chmod(0o600)
    return home


@pytest.fixture
async def legacy_home(provider, storage, tmp_path, process_snapshot):
    oidc, auth, login = provider
    with caller():
        # Seed pre-v2 registrations, including an Auth-only grant with no local
        # code/token. Its real cross-provider authority must prevent recovery.
        for identifier in ("unused", "granted"):
            await oidc.store.execute(
                "INSERT INTO oauth_clients VALUES(?,?,?)",
                [
                    identifier,
                    json.dumps(
                        {
                            "client_name": identifier,
                            "redirect_uris": ["http://127.0.0.1:4444/callback"],
                            "token_endpoint_auth_method": "none",
                            "scope": "notes.read",
                        }
                    ),
                    time.time() - 7200,
                ],
            )
        grant = await auth.invoke(
            "toolframe.auth",
            "grant_create",
            {
                "user_id": login["principal"]["user_id"],
                "issuer": oidc.issuer,
                "client_id": "granted",
                "client_name": "Retained",
                "resource": oidc.resources[0],
                "scopes": ["notes.read"],
                "expires_at": time.time() + 3600,
            },
        )
    with caller(management=True):
        plan = await storage.invoke(
            ADMIN_SERVICE,
            "plan",
            {"owner": plugin.id, "schema": plugin.store.model_dump()},
        )
        assert plan["current"] == "v1" and plan["target"] == "v2"
        applied = await storage.invoke(
            ADMIN_SERVICE,
            "apply",
            {
                "owner": plugin.id,
                "schema": plugin.store.model_dump(),
                "plan_id": plan["plan_id"],
            },
        )
        assert applied["revision"] == "v2" and applied["backup"]
    with caller():
        assert (
            await auth.invoke("toolframe.auth", "grant_check", {"id": grant["id"]})
        )["grant"]["client_id"] == "granted"
    oidc.config["max_clients"] = 2
    assert (await register(oidc))["status"] == 400
    await storage.dispose()
    home = stopped_layout(tmp_path, tmp_path / "data")
    # Prove this layout is accepted before each test adds its rejection case.
    assert recover_legacy(home) == {"eligible": 1, "reclassified": 0}
    assert process_snapshot["calls"] == 1
    return home, grant["id"]


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
async def test_legacy_recovery_preserves_auth_only_grant_and_restores_capacity(
    legacy_home, provider, storage, tmp_path
):
    home, grant_id = legacy_home
    assert recover_legacy(home) == {"eligible": 1, "reclassified": 0}
    path = home / "data/plugins/oidc-auth/data.sqlite"
    with closing(sqlite3.connect(path)) as database, database:
        assert database.execute(
            "SELECT DISTINCT registration_state FROM oauth_clients"
        ).fetchall() == [("legacy",)]
    backups = tmp_path / "backups"
    assert recover_legacy(home, apply=True, backup_directory=backups) == {
        "eligible": 1,
        "reclassified": 1,
    }
    assert {p.name for p in backups.iterdir()} == {"auth.sqlite", "oidc-auth.sqlite"}
    with closing(sqlite3.connect(path)) as database, database:
        assert dict(
            database.execute("SELECT id,registration_state FROM oauth_clients")
        ) == {"unused": "pending", "granted": "legacy"}
    # Restart real providers over the recovered databases, including grant data.
    for owner in ("auth", "oidc-auth"):
        shutil.copy2(
            home / f"data/plugins/{owner}/data.sqlite",
            tmp_path / f"data/{owner}/data.sqlite",
        )
    provider[0].config["max_clients"] = 2
    async with restart(provider, storage) as (oidc, auth, _):
        assert (await register(oidc))["status"] == 201
        with caller():
            clients = await oidc.store.query("SELECT id FROM oauth_clients")
            assert (
                await auth.invoke("toolframe.auth", "grant_check", {"id": grant_id})
            )["grant"]["client_id"] == "granted"
        assert "granted" in {row["id"] for row in clients}
        assert "unused" not in {row["id"] for row in clients}


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
async def test_maintenance_refuses_running_application_and_holds_startup_lock(
    legacy_home, tmp_path, monkeypatch
):
    from toolframe_core.maintenance import application_lock

    home, _ = legacy_home
    with application_lock(home), pytest.raises(PluginError):
        recover_legacy(home)
    original = sqlite3.connect
    attempts = []

    def connect(*args, **kwargs):
        # Every DB operation, including backup, occurs inside Core's HostLock.
        with pytest.raises(PluginError), application_lock(home):
            pass
        attempts.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)
    assert (
        recover_legacy(home, apply=True, backup_directory=tmp_path / "backup")[
            "reclassified"
        ]
        == 1
    )
    assert attempts


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
@pytest.mark.parametrize("damage", ["identity", "missing", "evidence", "flow"])
async def test_recovery_refuses_incomplete_or_unsafe_evidence(legacy_home, damage):
    home, _ = legacy_home
    auth_path = home / "data/plugins/auth/data.sqlite"
    oidc_path = home / "data/plugins/oidc-auth/data.sqlite"
    if damage == "missing":
        auth_path.unlink()
    elif damage == "identity":
        with closing(sqlite3.connect(auth_path)) as database, database:
            database.execute("UPDATE _toolframe_identity SET application_id='other'")
    elif damage == "evidence":
        with closing(sqlite3.connect(auth_path)) as database, database:
            database.execute("DROP TABLE agent_grants")
    else:
        with closing(sqlite3.connect(oidc_path)) as database, database:
            database.execute(
                "INSERT INTO oauth_flows VALUES('flow','browser','encrypted',?)",
                [time.time() + 600],
            )
    with pytest.raises((ValueError, sqlite3.Error, PluginError)):
        recover_legacy(home, apply=True, backup_directory=home / "backup")


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
@pytest.mark.parametrize("reference", ["code", "token"])
async def test_recovery_preserves_local_authority_history(
    legacy_home, reference, tmp_path
):
    home, _ = legacy_home
    with (
        closing(
            sqlite3.connect(home / "data/plugins/oidc-auth/data.sqlite")
        ) as database,
        database,
    ):
        if reference == "code":
            database.execute(
                "INSERT INTO oauth_codes VALUES('digest','{\"client_id\":\"unused\"}',0,1)"
            )
        else:
            database.execute(
                "INSERT INTO oauth_tokens VALUES('t','a',NULL,'g','unused','r','[]',0,0,1,1)"
            )
    assert recover_legacy(home, apply=True, backup_directory=tmp_path / "backup") == {
        "eligible": 0,
        "reclassified": 0,
    }


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
async def test_apply_requires_unused_backup_and_preserves_preimage(
    legacy_home, tmp_path
):
    home, _ = legacy_home
    with pytest.raises(ValueError):
        recover_legacy(home, apply=True)
    backup = tmp_path / "backup"
    backup.mkdir()
    with pytest.raises(FileExistsError):
        recover_legacy(home, apply=True, backup_directory=backup)
    backup.rmdir()
    recover_legacy(home, apply=True, backup_directory=backup)
    with closing(sqlite3.connect(backup / "oidc-auth.sqlite")) as database:
        assert (
            database.execute(
                "SELECT count(*) FROM oauth_clients WHERE registration_state='legacy'"
            ).fetchone()[0]
            == 2
        )


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
async def test_process_snapshot_rejects_matching_worker_but_allows_other_run(
    legacy_home, process_snapshot, tmp_path
):
    home, _ = legacy_home
    process_snapshot["stdout"] += (
        "42 42 python -m toolframe_sdk.worker --host-token " + "b" * 32 + "/auth\n"
    )
    assert recover_legacy(home)["eligible"] == 1
    process_snapshot["stdout"] += (
        "43 43 python -m toolframe_sdk.worker --host-token " + "a" * 32 + "/auth\n"
    )
    backup = tmp_path / "refused-backup"
    with pytest.raises(
        PluginError, match="An application worker is still present"
    ) as error:
        recover_legacy(home, apply=True, backup_directory=backup)
    assert error.value.code == "maintenance_ownership_unproven"
    assert not backup.exists()


@pytest.mark.parametrize("provider", ["v1"], indirect=True)
@pytest.mark.parametrize(
    "snapshot", ["not-a-pid 1 command\n", "1 1 init\n1 1 duplicate\n"]
)
async def test_process_snapshot_parser_still_rejects_unproven_inventory(
    legacy_home, process_snapshot, snapshot, tmp_path
):
    home, _ = legacy_home
    process_snapshot["stdout"] = snapshot
    backup = tmp_path / "refused-backup"
    with pytest.raises(PluginError) as error:
        recover_legacy(home, apply=True, backup_directory=backup)
    assert error.value.code == "maintenance_ownership_unproven"
    assert not backup.exists()
