"""Run the test suites and the offline evaluation, and render the REAL
output into docs/evaluation-results.html (plus a .txt copy).

Nothing is summarised by hand: the page shows the exact console output
of `python run_tests.py`, `python evals/runner.py` and
`python evals/image_scanner/evaluation.py`, with the time and commit.
The AI-mode evaluation is not run here — it costs provider tokens and
is a deliberate, separate step (`python evals/runner.py --ai`).

    python scripts/render_evaluation_report.py
"""

from __future__ import annotations

import html
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def run(args: list[str]) -> tuple[str, int, float]:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, *args], cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8"
    )
    elapsed = time.perf_counter() - started
    return (proc.stdout + proc.stderr), proc.returncode, elapsed


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def main() -> int:
    sections = []
    for title, args in (
        ("Automated test suites — python run_tests.py", ["run_tests.py"]),
        ("Offline evaluation (deterministic layer) — python evals/runner.py", ["evals/runner.py"]),
        ("Image-scanner evaluation framework — python evals/image_scanner/evaluation.py", ["evals/image_scanner/evaluation.py"]),
    ):
        output, code, seconds = run(args)
        # Never publish local absolute paths (they contain the user name).
        for form in {str(ROOT), ROOT.as_posix()}:
            output = output.replace(form, "<repo>")
        # Keep the summary lines; the per-test chatter of run_tests is long.
        if args[0] == "run_tests.py":
            output = "\n".join(line for line in output.splitlines() if line.startswith(("[", "All", " ")) or "suites" in line)
        sections.append((title, output.strip(), code, seconds))

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    commit = git("rev-parse", "--short", "HEAD")
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    dirty = bool(git("status", "--porcelain"))

    text = [f"Tumar.AI test and evaluation output — {stamp} — {branch}@{commit}{' (+uncommitted changes)' if dirty else ''}"]
    blocks = []
    for title, output, code, seconds in sections:
        text += ["", "=" * 72, title, f"exit code {code}, {seconds:.1f} s", "=" * 72, output]
        badge = "pass" if code == 0 else "fail"
        blocks.append(
            f"<section><h2>{html.escape(title)}</h2>"
            f"<p class='meta'><span class='{badge}'>exit code {code}</span> · {seconds:.1f} s</p>"
            f"<pre>{html.escape(output)}</pre></section>"
        )

    DOCS.mkdir(exist_ok=True)
    (DOCS / "evaluation-results.txt").write_text("\n".join(text) + "\n", encoding="utf-8")
    (DOCS / "evaluation-results.html").write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tumar.AI test results</title>
<style>
:root {{ --bg:#070D1A; --raise:#0C1424; --ink:#E8EEF9; --muted:#93A3BC; --cyan:#22D3EE; --ok:#34D399; --bad:#F87171; --line:#1B2740; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 Inter,Segoe UI,system-ui,sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:28px 16px 48px; }}
h1 {{ margin:0 0 4px; font-size:26px; }} h2 {{ font-size:17px; margin:0 0 6px; color:var(--cyan); }}
.meta {{ color:var(--muted); margin:0 0 10px; font-size:13px; }}
section {{ background:var(--raise); border:1px solid var(--line); border-radius:14px; padding:18px; margin-top:18px; }}
pre {{ margin:0; white-space:pre-wrap; font:12.5px/1.45 Consolas,ui-monospace,monospace; color:#D6E2F5; }}
.pass {{ color:var(--ok); font-weight:700; }} .fail {{ color:var(--bad); font-weight:700; }}
</style></head><body><main>
<h1>Tumar.AI — test &amp; evaluation output</h1>
<p class="meta">Generated {stamp} by scripts/render_evaluation_report.py · branch {html.escape(branch)} @ {html.escape(commit)}{' with uncommitted changes' if dirty else ''} ·
verbatim console output, nothing edited · AI-mode evaluation not included (costs provider tokens; run separately)</p>
{''.join(blocks)}
</main></body></html>
""", encoding="utf-8")
    print("wrote docs/evaluation-results.html and .txt")
    return 0 if all(code == 0 for _, _, code, _ in sections) else 1


if __name__ == "__main__":
    sys.exit(main())
