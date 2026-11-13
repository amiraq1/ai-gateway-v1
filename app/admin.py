from __future__ import annotations

import argparse
from pathlib import Path

from .auth import create_client_key
from .config import load_config
from .database import Database
from .secret_loader import SecretLoadError, resolve_secret


def main() -> int:
    parser = argparse.ArgumentParser(description="Local AI Gateway administration; never exposes an HTTP admin endpoint.")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-key")
    create.add_argument("--name", required=True)
    create.add_argument("--rpm", type=int, default=60)
    revoke = sub.add_parser("revoke-key")
    revoke.add_argument("client_id")
    sub.add_parser("list-clients")
    usage = sub.add_parser("usage")
    usage.add_argument("client_id")
    usage.add_argument("--limit", type=int, default=100)
    backup = sub.add_parser("backup")
    backup.add_argument("destination")
    args = parser.parse_args()
    config = load_config()
    pepper: str | None = None
    if args.command == "create-key":
        try:
            pepper = resolve_secret("GATEWAY_PEPPER")
        except SecretLoadError:
            parser.exit(2, "error: required secret is unavailable.\n")
    db = Database(config.settings.database_path)
    db.init()
    if args.command == "create-key":
        assert pepper is not None
        client_id, raw_key = create_client_key(db, pepper, args.name, args.rpm)
        print(f"client_id={client_id}")
        print(f"api_key={raw_key}")
        print("Store this API key securely; it will not be shown again.")
    elif args.command == "revoke-key":
        print("revoked" if db.revoke_client(args.client_id) else "not_found_or_already_revoked")
    elif args.command == "list-clients":
        for item in db.list_clients():
            print(" ".join(f"{key}={value}" for key, value in item.items()))
    elif args.command == "usage":
        for item in db.usage_for_client(args.client_id, args.limit):
            print(" ".join(f"{key}={value}" for key, value in item.items()))
    elif args.command == "backup":
        destination = Path(args.destination)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        db.backup_to(str(destination))
        print(f"backup_created={destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
