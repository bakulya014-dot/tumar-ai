"""Command-line tools for the contributed corpus.

    python -m api.corpus stats
    python -m api.corpus review --limit 20
    python -m api.corpus label --id 4 --as scam
    python -m api.corpus export --out evals/corpus/messages_contributed.jsonl
    python -m api.corpus withdraw --key-id 3

This is where production traffic becomes measurement. Exported rows
arrive UNLABELLED on purpose: a human decides whether each one is a
scam, because a corpus labelled by the system it measures would only
confirm what that system already believes, and the evaluation would
stop meaning anything.
"""

import argparse
import json
import sys
from pathlib import Path

# Make the project root importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import corpus_store  # noqa: E402


def _stats(args: argparse.Namespace) -> int:
    figures = corpus_store.stats(args.db)
    print(f"Contributed samples: {figures['total']}")
    print(f"  awaiting a label:  {figures['unlabelled']}")
    print(f"  contributors:      {figures['contributors']}")
    for language, count in figures["by_language"].items():
        print(f"  {language}: {count}")
    if figures["unlabelled"]:
        print()
        print("Label them with: python -m api.corpus review")
    return 0


def _review(args: argparse.Namespace) -> int:
    rows = corpus_store.export(args.limit, unlabelled_only=True, path=args.db)
    if not rows:
        print("Nothing awaiting a label.")
        return 0
    for row in rows:
        identifier = row["id"].removeprefix("contrib-")
        print(f"\n--- #{identifier}  [{row['language']}]  engine said: {row['engine_verdict']}")
        print(row["text"][:500])
    print()
    print("Label with: python -m api.corpus label --id N --as scam|legitimate")
    return 0


def _label(args: argparse.Namespace) -> int:
    if corpus_store.set_label(args.id, getattr(args, "as"), args.db):
        print(f"Sample #{args.id} labelled '{getattr(args, 'as')}'.")
        return 0
    print(f"Sample #{args.id} was not found.")
    return 1


def _export(args: argparse.Namespace) -> int:
    rows = corpus_store.export(args.limit, args.unlabelled, args.db)
    if not rows:
        print("Nothing to export.")
        return 0

    unlabelled = [row for row in rows if row["label"] == "UNLABELLED"]
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote {len(rows)} samples to {args.out}")
    else:
        print("\n".join(lines))

    if unlabelled:
        print()
        print(
            f"{len(unlabelled)} of these are UNLABELLED. Label them before "
            "adding the file to evals/corpus/, or the harness will be "
            "measuring against guesses."
        )
    return 0


def _withdraw(args: argparse.Namespace) -> int:
    deleted = corpus_store.withdraw(args.key_id, args.db)
    print(f"Deleted {deleted} contributed sample(s) for key #{args.key_id}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=None, help="database file")
    commands = parser.add_subparsers(dest="command", required=True)

    stats = commands.add_parser("stats", help="how much has been contributed")
    stats.set_defaults(handler=_stats)

    review = commands.add_parser("review", help="show samples awaiting a label")
    review.add_argument("--limit", type=int, default=20)
    review.set_defaults(handler=_review)

    label = commands.add_parser("label", help="record a human judgement")
    label.add_argument("--id", type=int, required=True)
    label.add_argument(
        "--as", required=True, choices=["scam", "legitimate"], dest="as"
    )
    label.set_defaults(handler=_label)

    export = commands.add_parser("export", help="write corpus-shaped JSONL")
    export.add_argument("--out", default="", help="file to write (default: stdout)")
    export.add_argument("--limit", type=int, default=0)
    export.add_argument(
        "--unlabelled", action="store_true", help="only rows without a label"
    )
    export.set_defaults(handler=_export)

    withdraw = commands.add_parser(
        "withdraw", help="delete every sample from one key"
    )
    withdraw.add_argument("--key-id", type=int, required=True)
    withdraw.set_defaults(handler=_withdraw)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
