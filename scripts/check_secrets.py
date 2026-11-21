"""Fail if a tracked file contains something shaped like a real credential.

    python scripts/check_secrets.py

Runs in CI on every push. Prints the file, line number and which kind of
secret matched, never the value itself, so the CI log cannot leak it.

Patterns cover the credentials this project actually uses: Google OAuth
client secrets, Google API keys (both formats), Telegram bot tokens,
Anthropic/OpenAI-style keys and private key blocks. Test fixtures build
fake tokens at runtime, so they never match a literal pattern here.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PATTERNS = {
    "Google OAuth client secret": re.compile(r"GOCSPX-[A-Za-z0-9_-]{20,}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Google API key (AQ. format)": re.compile(r"AQ\.[A-Za-z0-9_-]{40,}"),
    "Telegram bot token": re.compile(r"(?<![0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    "Anthropic API key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "OpenAI-style API key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{32,}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".mp4", ".ico", ".db"}


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode("utf-8")
    return [ROOT / name for name in out.split("\0") if name]


def scan(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(lines, start=1):
            for kind, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{number}: {kind}")
    return findings


def main() -> int:
    findings = scan(tracked_files())
    if findings:
        print("Possible credentials in tracked files (values not shown):")
        print("\n".join(f"  {f}" for f in findings))
        print("Remove them, rotate the credential, and keep it in secrets only.")
        return 1
    print(f"No credential patterns found in {len(tracked_files())} tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
