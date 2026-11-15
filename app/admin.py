from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .audit import record_audit_event
from .auth import (
    AdminBootstrapError,
    bootstrap_first_admin,
    create_client_key,
    revoke_admin_user_sessions,
    set_admin_user_active,
)
from .config import load_config
from .database import Database
from .secret_loader import SecretLoadError, resolve_secret

IP_RULES_CLEAR_PHRASE = "DELETE-ALL-ADMIN-IP-RULES"
_CLI_AGENT = "local-cli"
_BREAK_GLASS_SOURCE = {"source": "break-glass-cli"}


def _build_parser() -> argparse.ArgumentParser:
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

    bootstrap = sub.add_parser("bootstrap-admin", help="Create the first administrator. Refused if one exists.")
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--password-stdin", action="store_true",
                           help="Read the password from the first line of stdin instead of a terminal prompt.")

    for name, help_text in (
        ("disable-admin", "Disable an administrator and revoke its sessions."),
        ("enable-admin", "Enable a disabled administrator."),
        ("revoke-admin-sessions", "Revoke every active session of an administrator."),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("username")

    ip_rules = sub.add_parser("ip-rules", help="Break-glass controls for admin IP rules.")
    ip_sub = ip_rules.add_subparsers(dest="ip_command", required=True)
    ip_sub.add_parser("list")
    disable_rule = ip_sub.add_parser("disable", help="Deactivate one rule without deleting it.")
    disable_rule.add_argument("rule_id", type=int)
    delete_rule = ip_sub.add_parser("delete", help="Delete one rule.")
    delete_rule.add_argument("rule_id", type=int)
    ip_sub.add_parser("reopen", help="Deactivate every allow rule, which lifts the allowlist and keeps deny rules.")
    clear = ip_sub.add_parser("clear", help="Delete every admin IP rule. Requires explicit confirmation.")
    clear.add_argument("--confirm", default=None, help=f"Must equal {IP_RULES_CLEAR_PHRASE}")
    return parser


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        line = sys.stdin.readline()
        if not line:
            raise ValueError("no password was provided on stdin")
        return line.rstrip("\r\n")
    if not sys.stdin.isatty():
        raise ValueError("run in a terminal or pass --password-stdin")
    first = getpass.getpass("Admin password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise ValueError("passwords do not match")
    return first


def _print_ip_rules(db: Database) -> int:
    with db.connect() as conn:
        rows = conn.execute("SELECT id, rule_type, ip_or_cidr, is_active, description FROM admin_ip_rules ORDER BY id").fetchall()
    for row in rows:
        print(f"id={row['id']} rule_type={row['rule_type']} ip_or_cidr={row['ip_or_cidr']} "
              f"is_active={int(row['is_active'])} description={row['description']}")
    if not rows:
        print("no_admin_ip_rules")
    return 0


def _disable_rule(db: Database, rule_id: int) -> int:
    with db.transaction() as conn:
        row = conn.execute("SELECT rule_type, ip_or_cidr FROM admin_ip_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            print("not_found")
            return 1
        conn.execute("UPDATE admin_ip_rules SET is_active = 0 WHERE id = ?", (rule_id,))
        record_audit_event(conn, action="breakglass.ip_rule.disable", target=f"ip_rule:{rule_id}",
                           user_agent=_CLI_AGENT, metadata={**_BREAK_GLASS_SOURCE, "rule_type": str(row["rule_type"]),
                                                            "cidr": str(row["ip_or_cidr"])})
    print("disabled")
    return 0


def _delete_rule(db: Database, rule_id: int) -> int:
    with db.transaction() as conn:
        row = conn.execute("SELECT rule_type, ip_or_cidr FROM admin_ip_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            print("not_found")
            return 1
        conn.execute("DELETE FROM admin_ip_rules WHERE id = ?", (rule_id,))
        record_audit_event(conn, action="breakglass.ip_rule.delete", target=f"ip_rule:{rule_id}",
                           user_agent=_CLI_AGENT, metadata={**_BREAK_GLASS_SOURCE, "rule_type": str(row["rule_type"]),
                                                            "cidr": str(row["ip_or_cidr"])})
    print("deleted")
    return 0


def _reopen(db: Database) -> int:
    with db.transaction() as conn:
        cursor = conn.execute("UPDATE admin_ip_rules SET is_active = 0 WHERE rule_type = 'allow' AND is_active = 1")
        disabled = int(cursor.rowcount)
        record_audit_event(conn, action="breakglass.ip_rules.reopen", user_agent=_CLI_AGENT,
                           metadata={**_BREAK_GLASS_SOURCE, "disabled_allow_rules": disabled})
    print(f"allow_rules_disabled={disabled}")
    return 0


def _clear(db: Database, confirm: str | None) -> int:
    if confirm is None and sys.stdin.isatty():
        confirm = input(f"Type {IP_RULES_CLEAR_PHRASE} to delete every admin IP rule: ").strip()
    if confirm != IP_RULES_CLEAR_PHRASE:
        print(f"refused: pass --confirm {IP_RULES_CLEAR_PHRASE} to delete every admin IP rule")
        return 2
    with db.transaction() as conn:
        cursor = conn.execute("DELETE FROM admin_ip_rules")
        deleted = int(cursor.rowcount)
        record_audit_event(conn, action="breakglass.ip_rules.clear", user_agent=_CLI_AGENT,
                           metadata={**_BREAK_GLASS_SOURCE, "deleted": deleted})
    print(f"deleted={deleted}")
    return 0


def main() -> int:
    parser = _build_parser()
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
    elif args.command == "bootstrap-admin":
        try:
            password = _read_password(args.password_stdin)
            admin_id = bootstrap_first_admin(db, args.username, password)
        except AdminBootstrapError as exc:
            print(f"refused: {exc}")
            return 1
        except ValueError as exc:
            print(f"error: {exc}")
            return 2
        print(f"admin_user_id={admin_id}")
    elif args.command in {"disable-admin", "enable-admin", "revoke-admin-sessions"}:
        try:
            if args.command == "revoke-admin-sessions":
                print(f"revoked={revoke_admin_user_sessions(db, args.username)}")
            else:
                active = args.command == "enable-admin"
                if set_admin_user_active(db, args.username, active=active):
                    print("enabled" if active else "disabled")
                else:
                    print("not_found")
                    return 1
        except ValueError:
            print("error: invalid username")
            return 2
    elif args.command == "ip-rules":
        if args.ip_command == "list":
            return _print_ip_rules(db)
        if args.ip_command == "disable":
            return _disable_rule(db, args.rule_id)
        if args.ip_command == "delete":
            return _delete_rule(db, args.rule_id)
        if args.ip_command == "reopen":
            return _reopen(db)
        if args.ip_command == "clear":
            return _clear(db, args.confirm)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
