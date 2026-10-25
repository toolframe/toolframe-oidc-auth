"""Native SQL checks, separate from managed PostgreSQL deployment acceptance."""

import shutil
import socket
import subprocess
from importlib.resources import files
from pathlib import Path

import pytest


@pytest.mark.skipif(
    not all(shutil.which(command) for command in ("initdb", "pg_ctl", "psql")),
    reason="Local PostgreSQL server tools are required for native SQL checks",
)
def test_postgresql_migration_and_recovery_sql(tmp_path):
    cluster = tmp_path / "cluster"
    subprocess.run(
        [
            "initdb",
            "-D",
            str(cluster),
            "--auth=trust",
            "--username=operator",
            "--locale=C",
            "--encoding=UTF8",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    subprocess.run(
        [
            "pg_ctl",
            "-D",
            str(cluster),
            "-l",
            str(tmp_path / "postgres.log"),
            "-o",
            f"-h 127.0.0.1 -k '' -p {port}",
            "-w",
            "start",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    psql = [
        "psql",
        "-X",
        "-h",
        "127.0.0.1",
        "-p",
        str(port),
        "-U",
        "operator",
        "-d",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
    ]

    def sql(statement):
        return subprocess.run(
            [*psql, "-At", "-c", statement],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()

    def recover(*arguments):
        return subprocess.run(
            [
                *psql,
                "-v",
                "application_id=fixture",
                "-v",
                "oidc_schema=oidc",
                "-v",
                "oidc_meta=oidc_meta",
                "-v",
                "auth_schema=auth",
                "-v",
                "auth_meta=auth_meta",
                *arguments,
                "-f",
                str(
                    Path(__file__).resolve().parents[1]
                    / "docs/legacy-registration-postgresql.sql"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    try:
        sql(
            "CREATE SCHEMA oidc; CREATE SCHEMA auth; CREATE SCHEMA oidc_meta; CREATE SCHEMA auth_meta; "
            "CREATE SCHEMA _toolframe_platform; "
            "CREATE TABLE _toolframe_platform.identity(application_id TEXT); "
            "INSERT INTO _toolframe_platform.identity VALUES('fixture'); "
            "CREATE TABLE oidc_meta.identity(application_id TEXT,owner TEXT); "
            "CREATE TABLE auth_meta.identity(application_id TEXT,owner TEXT); "
            "INSERT INTO oidc_meta.identity VALUES('fixture','oidc-auth'); "
            "INSERT INTO auth_meta.identity VALUES('fixture','auth'); "
            "CREATE TABLE auth.agent_grants(client_id TEXT); INSERT INTO auth.agent_grants VALUES('grant-only');"
        )
        migrations = files("toolframe_oidc_auth").joinpath("migrations")
        sql(
            "SET search_path TO oidc,pg_catalog; "
            + migrations.joinpath("v1.postgresql.sql").read_text()
        )
        sql(
            "INSERT INTO oidc.oauth_clients VALUES('unused','{}',0),('grant-only','{}',0),('coded','{}',0),('tokenized','{}',0)"
        )
        sql(
            "SET search_path TO oidc,pg_catalog; "
            + migrations.joinpath("v2.postgresql.sql").read_text()
        )
        assert (
            sql(
                "SELECT count(*) FROM oidc.oauth_clients WHERE registration_state='legacy'"
            )
            == "4"
        )
        sql(
            "INSERT INTO oidc.oauth_codes VALUES('digest','{\"client_id\":\"coded\"}',0,0); "
            "INSERT INTO oidc.oauth_tokens VALUES('t','a',NULL,'g','tokenized','r','[]',0,0,0,0)"
        )
        assert recover().returncode == 0
        assert (
            sql(
                "SELECT count(*) FROM oidc.oauth_clients WHERE registration_state='legacy'"
            )
            == "4"
        )
        applied = recover("-v", "apply=true")
        assert applied.returncode == 0, applied.stderr
        assert (
            sql("SELECT id FROM oidc.oauth_clients WHERE registration_state='pending'")
            == "unused"
        )
        assert (
            sql(
                "SELECT count(*) FROM oidc.oauth_clients WHERE registration_state='legacy'"
            )
            == "3"
        )
        sql(
            "INSERT INTO oidc.oauth_flows VALUES('f','b','encrypted',extract(epoch FROM clock_timestamp())+600)"
        )
        assert recover("-v", "apply=true").returncode != 0
        sql(
            "DELETE FROM oidc.oauth_flows; UPDATE auth_meta.identity SET application_id='wrong'"
        )
        assert recover("-v", "apply=true").returncode != 0
    finally:
        subprocess.run(
            ["pg_ctl", "-D", str(cluster), "-m", "immediate", "-w", "stop"],
            check=True,
            capture_output=True,
            timeout=30,
        )
