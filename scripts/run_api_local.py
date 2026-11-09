"""Run the REST API locally with the same keys the Streamlit app uses.

The API reads its configuration from the environment only. For local
development and demos this helper copies the provider keys from
.streamlit/secrets.toml into the environment (without printing them),
uses a local throwaway database, sets a development API key if none is
configured, and starts uvicorn.

    python scripts/run_api_local.py --port 8000

Production deployments set real environment variables instead; this
script is a convenience, not a deployment method.
"""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_PROVIDER_KEYS = ("GEMINI_API_KEY", "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    secrets_file = ROOT / ".streamlit" / "secrets.toml"
    if secrets_file.exists():
        secrets = tomllib.loads(secrets_file.read_text(encoding="utf-8"))
        for name in _PROVIDER_KEYS:
            if not os.environ.get(name) and secrets.get(name):
                os.environ[name] = str(secrets[name])
    os.environ.setdefault("TUMAR_DB_PATH", str(ROOT / "tumar-local.db"))
    if not os.environ.get("TUMAR_API_KEYS"):
        os.environ["TUMAR_API_KEYS"] = "local-dev-key"
        print("TUMAR_API_KEYS not set; using the development key 'local-dev-key'")
    print("AI provider key configured:", bool(os.environ.get("GEMINI_API_KEY")))

    sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)
    import uvicorn

    uvicorn.run("api.main:app", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
