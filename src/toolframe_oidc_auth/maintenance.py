"""Offline, conservative recovery of legacy SQLite registration capacity."""

import argparse
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from toolframe_sdk import PluginError


def connect(path):
    # Never create a missing store or mistake a new empty file for evidence.
    return sqlite3.connect(
        Path(path).resolve().as_uri() + "?mode=rw", uri=True, timeout=1
    )


def recover_legacy(home, *, apply=False, backup_directory=None):
    """Hold Core's stopped-application boundary throughout recovery and backup."""
    from toolframe_core.maintenance import stopped_application

    with stopped_application(home) as inventory:
        stores = {item.owner: inventory.home / item.path for item in inventory.stores}
        if not {"auth", "oidc-auth"} <= stores.keys():
            raise ValueError(
                "Both current Auth and OIDC managed SQLite stores are required"
            )
        return _recover_stores(
            stores["oidc-auth"],
            stores["auth"],
            inventory.application_id,
            apply=apply,
            backup_directory=backup_directory,
        )


def _recover_stores(
    oidc_store, auth_store, application_id, *, apply=False, backup_directory=None
):
    """Reclassify only legacy clients absent from both stores' authority records.

    The caller holds Core's stopped_application lock and derives paths from its
    inventory, rather than accepting caller-selected partial store copies.
    """
    if Path(oidc_store).samefile(auth_store):
        raise ValueError("Supply distinct current OIDC and Auth stores")
    with closing(connect(auth_store)) as auth, closing(connect(oidc_store)) as oidc:
        try:
            auth.execute("BEGIN IMMEDIATE")
            oidc.execute("BEGIN IMMEDIATE")
            auth_identity = auth.execute(
                "SELECT owner,application_id FROM _toolframe_identity"
            ).fetchall()
            oidc_identity = oidc.execute(
                "SELECT owner,application_id FROM _toolframe_identity"
            ).fetchall()
            if (
                len(auth_identity) != 1
                or len(oidc_identity) != 1
                or auth_identity[0][0] != "auth"
                or oidc_identity[0][0] != "oidc-auth"
                or auth_identity[0][1] != oidc_identity[0][1]
                or auth_identity[0][1] != application_id
            ):
                raise ValueError(
                    "Stores must belong to Auth and OIDC in the same application"
                )
            if oidc.execute(
                "SELECT 1 FROM oauth_flows WHERE expires_at>? LIMIT 1", [time.time()]
            ).fetchone():
                raise ValueError(
                    "Wait for all ten-minute authorization flows to expire while stopped"
                )
            referenced = {
                row[0] for row in auth.execute("SELECT client_id FROM agent_grants")
            }
            referenced.update(
                row[0] for row in oidc.execute("SELECT client_id FROM oauth_tokens")
            )
            for (data,) in oidc.execute("SELECT data FROM oauth_codes"):
                code = json.loads(data)
                if not isinstance(code, dict) or not isinstance(
                    code.get("client_id"), str
                ):
                    raise TypeError(
                        "Cannot classify malformed authorization code records"
                    )
                referenced.add(code["client_id"])
            candidates = [
                identifier
                for (identifier,) in oidc.execute(
                    "SELECT id FROM oauth_clients WHERE registration_state='legacy'"
                )
                if identifier not in referenced
            ]
            if apply:
                if backup_directory is None:
                    raise ValueError(
                        "An unused backup directory is required with --apply"
                    )
                backup_directory = Path(backup_directory)
                backup_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
                for name, source in (("auth", auth_store), ("oidc-auth", oidc_store)):
                    # Separate read connections see the stable committed snapshot
                    # while the maintenance connections exclude store writers.
                    with (
                        closing(connect(source)) as reader,
                        closing(
                            sqlite3.connect(backup_directory / f"{name}.sqlite")
                        ) as backup,
                    ):
                        reader.backup(backup)
                oidc.executemany(
                    "UPDATE oauth_clients SET registration_state='pending',protected_until=0 "
                    "WHERE id=? AND registration_state='legacy'",
                    [(identifier,) for identifier in candidates],
                )
                oidc.commit()
            return {
                "eligible": len(candidates),
                "reclassified": len(candidates) if apply else 0,
            }
        finally:
            oidc.rollback()
            auth.rollback()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup-directory", type=Path)
    args = parser.parse_args()
    try:
        result = recover_legacy(
            args.home,
            apply=args.apply,
            backup_directory=args.backup_directory,
        )
    except ImportError, OSError, ValueError, TypeError, sqlite3.Error, PluginError:
        parser.exit(
            1,
            "Recovery refused: require Core 0.8 maintenance support, a cleanly stopped "
            "local SQLite application, matching complete stores, no live flows, "
            "and an unused backup directory with --apply.\n",
        )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
