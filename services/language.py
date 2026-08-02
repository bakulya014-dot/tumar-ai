"""Detect which language a sample is written in.

Needed because the language a report is *written in* and the language
a sample *is in* are different things. A user reading the interface in
English can paste a Russian scam, and recording that sample as English
would quietly corrupt the corpus — the per-language accuracy figures
the evaluation harness reports would then be measuring the wrong
thing.

Script-based rather than statistical: the three languages this product
serves are cleanly separable by alphabet, and Kazakh is identifiable by
letters that exist in no other Cyrillic alphabet. That is enough to
label a corpus correctly, and it is explainable, instant and offline.
"""

import re

# Letters unique to the Kazakh Cyrillic alphabet.
_KAZAKH_LETTERS = set("әғқңөұүһі")

# The Cyrillic block, minus the Kazakh-specific letters above.
_CYRILLIC_START, _CYRILLIC_END = "Ѐ", "ӿ"

DEFAULT = "en"

# URLs are ignored when judging language: they are Latin by
# convention, so a lone link in a Kazakh message would otherwise drag
# the whole sample into "English".
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)


def detect(text: str, fallback: str = DEFAULT) -> str:
    """Return "kk", "ru" or "en" for a sample.

    Kazakh is checked first: Kazakh text is mostly shared Cyrillic
    with a handful of distinctive letters, so looking for those is
    what separates it from Russian.
    """
    lowered = _URL.sub(" ", text).lower()
    if any(char in _KAZAKH_LETTERS for char in lowered):
        return "kk"
    if any(_CYRILLIC_START <= char <= _CYRILLIC_END for char in lowered):
        return "ru"
    if any(char.isalpha() for char in lowered):
        return "en"
    # Nothing but a link or digits. Nothing to go on, so keep whatever
    # the caller believed rather than inventing a fact.
    return fallback
