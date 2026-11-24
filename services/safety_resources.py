"""Official safety resources shown in Settings & Safety: configurable, verified only.

Entries live in config/safety_resources.json, not in code, so they can
be corrected without touching the app. An entry is shown ONLY when
"verified" is true: a wrong phone number or a look-alike link on a
safety page would be worse than no link at all. Verifying means a
person checked the address on the organisation's own official site and
recorded the date in "checked_on".

Every entry is presented as an external link with no claim of
affiliation: Tumar.AI is not partnered with any bank or agency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

CONFIG = Path(__file__).resolve().parent.parent / "config" / "safety_resources.json"


@dataclass(frozen=True)
class Resource:
    id: str
    name: str
    url: str
    kind: str  # "bank" | "government" | "reporting"
    checked_on: str

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def description_key(self) -> str:
        return f"settings.resource.{self.id}"


def _valid(entry: dict) -> bool:
    url = str(entry.get("url", ""))
    return (
        entry.get("verified") is True
        and url.startswith("https://")
        and bool(entry.get("checked_on"))
        and all(entry.get(field) for field in ("id", "name", "kind"))
    )


def verified(path: Path = CONFIG) -> list[Resource]:
    """Verified entries only; a missing or broken file shows nothing rather than failing."""
    try:
        entries = json.loads(path.read_text(encoding="utf-8")).get("resources", [])
    except (OSError, ValueError):
        return []
    return [
        Resource(e["id"], e["name"], e["url"], e["kind"], e["checked_on"])
        for e in entries
        if isinstance(e, dict) and _valid(e)
    ]
