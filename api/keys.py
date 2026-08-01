"""Command-line administration for API keys and usage.

    python -m api.keys issue --owner "Acme Bank" --quota 10000
    python -m api.keys list
    python -m api.keys rotate --id 3
    python -m api.keys revoke --id 3
    python -m api.keys usage --days 30
    python -m api.keys prune --days 90

Deliberately a CLI and not an HTTP admin endpoint. Key issuance is the
most dangerous operation this system has — an endpoint that mints
credentials is worth more to an attacker than any single key, and it
would need its own authentication, its own audit trail and its own
rate limiting to be safe. None of that is needed while issuing a key
means having a shell on the box. When self-service becomes a product
requirement, it should be built as one, not bolted on here.
"""

import argparse
import sys
from pathlib import Path

# Make the project root importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import keystore  # noqa: E402


def _issue(args: argparse.Namespace) -> int:
    issued = keystore.issue(args.owner, args.label, args.quota, args.db)
    print(f"Key #{issued.record.id} issued to {issued.record.owner}")
    if issued.record.monthly_quota:
        print(f"Monthly quota: {issued.record.monthly_quota} calls")
    else:
        print("Monthly quota: unlimited")
    print()
    print("  " + issued.secret)
    print()
    # Said plainly, because the alternative is a support ticket later.
    print("This is the only time the key is shown. It is stored hashed and")
    print("cannot be recovered — if it is lost, rotate it.")
    return 0


def _list(args: argparse.Namespace) -> int:
    keys = keystore.list_keys(args.db)
    if not keys:
        print("No keys issued yet.")
        return 0
    print(f"{'ID':>4}  {'KEY':<18} {'OWNER':<22} {'QUOTA':>8}  STATUS")
    for key in keys:
        quota = str(key.monthly_quota) if key.monthly_quota else "unlimited"
        status = "active" if key.active else f"revoked {key.revoked_at[:10]}"
        if key.rotated_to:
            status += f" -> #{key.rotated_to}"
        print(
            f"{key.id:>4}  {key.display:<18} {key.owner[:22]:<22} "
            f"{quota:>8}  {status}"
        )
    return 0


def _revoke(args: argparse.Namespace) -> int:
    if keystore.revoke(args.id, args.db):
        print(f"Key #{args.id} revoked. It stops working immediately.")
        return 0
    print(f"Key #{args.id} was not found, or was already revoked.")
    return 1


def _rotate(args: argparse.Namespace) -> int:
    issued = keystore.rotate(args.id, args.db)
    if issued is None:
        print(f"Key #{args.id} was not found.")
        return 1
    print(f"Key #{args.id} revoked and replaced by #{issued.record.id}.")
    print(f"Owner: {issued.record.owner}")
    print()
    print("  " + issued.secret)
    print()
    print("The old key stopped working now. Update the client before it")
    print("next calls, and note that this secret is shown only once.")
    return 0


def _usage(args: argparse.Namespace) -> int:
    rows = keystore.usage_summary(args.id, args.days, args.db)
    if not rows:
        print("No keys to report on.")
        return 0
    print(f"Usage over the last {args.days} days")
    print(f"{'ID':>4}  {'OWNER':<22} {'CALLS':>7} {'OK':>7} {'DANGER':>7} {'AVG MS':>7}  QUOTA USED")
    for row in rows:
        used = keystore.usage_this_month(row["key_id"], path=args.db)
        quota = row["monthly_quota"]
        share = f"{used}/{quota}" if quota else f"{used}/unlimited"
        print(
            f"{row['key_id']:>4}  {row['owner'][:22]:<22} {row['calls']:>7} "
            f"{row['successful']:>7} {row['dangerous']:>7} {row['avg_ms']:>7}  {share}"
        )
    return 0


def _prune(args: argparse.Namespace) -> int:
    removed = keystore.prune_usage(args.days, args.db)
    print(f"Removed {removed} usage rows older than {args.days} days.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", default=None, help="database file (default: $TUMAR_DB_PATH)"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    issue = commands.add_parser("issue", help="create a new key")
    issue.add_argument("--owner", required=True, help="who the key belongs to")
    issue.add_argument("--label", default="", help="what it is used for")
    issue.add_argument(
        "--quota", type=int, default=0, help="monthly call limit (0 = unlimited)"
    )
    issue.set_defaults(handler=_issue)

    listing = commands.add_parser("list", help="show every key")
    listing.set_defaults(handler=_list)

    revoke = commands.add_parser("revoke", help="disable a key now")
    revoke.add_argument("--id", type=int, required=True)
    revoke.set_defaults(handler=_revoke)

    rotate = commands.add_parser("rotate", help="replace a key")
    rotate.add_argument("--id", type=int, required=True)
    rotate.set_defaults(handler=_rotate)

    usage = commands.add_parser("usage", help="report calls per key")
    usage.add_argument("--id", type=int, default=None)
    usage.add_argument("--days", type=int, default=30)
    usage.set_defaults(handler=_usage)

    prune = commands.add_parser("prune", help="delete old usage rows")
    prune.add_argument("--days", type=int, default=90)
    prune.set_defaults(handler=_prune)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
