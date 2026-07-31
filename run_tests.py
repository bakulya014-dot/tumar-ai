"""Run every offline test suite, and report a single pass/fail.

The suites are plain scripts rather than a pytest package, so this
gives continuous integration (and a developer in a hurry) one command
with one exit code:

    python run_tests.py

Nothing here reaches the network or needs an API key: every suite is
offline by design, so the check stays fast and free on every push.
"""

import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent / "tests"


def main() -> int:
    suites = sorted(TESTS_DIR.glob("test_*.py"))
    if not suites:
        print("No test suites found.")
        return 1

    failed: list[str] = []
    for suite in suites:
        result = subprocess.run(
            [sys.executable, str(suite)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        status = "PASS" if result.returncode == 0 else "FAIL"
        print(f"[{status}] {suite.name}")
        if result.returncode != 0:
            failed.append(suite.name)
            # Only failures print their output, so a green run stays
            # readable and a red one shows exactly what broke.
            print((result.stdout or "").rstrip())
            print((result.stderr or "").rstrip())

    print()
    if failed:
        print(f"{len(failed)} of {len(suites)} suites FAILED: {', '.join(failed)}")
        return 1
    print(f"All {len(suites)} suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
