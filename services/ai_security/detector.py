"""Rules-only findings for the AI Security Check.

Runs every pattern family over the pasted text, keeps a short excerpt of
what matched (the evidence the user sees), and weighs each finding by
the context the user chose. No AI, no network: this layer always runs,
and the AI layer can add to it but never remove from it.

Context rules (all documented, all tested):

- "prompt" (the user pasted an AI prompt or system instruction to
  review): role-setting lines such as "You are an assistant" and
  mentions of "system prompt" are normal there, so those generic
  injection phrases are not counted. Override phrases still are.
- "log" (security logs, analyst evidence): the same families run. Mild
  closing wording ("this activity is expected") stays weak here, on
  purpose: analysts write exactly that when closing real tickets, and
  the rules cannot tell an analyst's note from an injected one.
  Instructions to act ("mark this alert as a false positive", "do not
  escalate") are strong in every context.
- "memory" (agent memory, knowledge-base snippets): standing-rule
  wording is strong even in its milder forms ("from now on, always…").
- "tool" (tool descriptions, connector manifests, permission configs):
  the static permission review in services/ai_security/posture.py runs.

Combinations:

- A bank-details change on its own is ordinary business. Together with
  pressure to skip verification, an executive's authority or urgency,
  it is the classic supplier/CEO fraud pattern: a separate STRONG
  finding, "ais_payment_redirect".
- Hidden text on its own may be formatting. Next to any other finding
  it is strong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from services.ai_security import CONTEXTS, DEFAULT_CONTEXT, patterns, posture
from services.heuristics import scan_message
from services.image_scanner.classifier import injection_phrases

EXCERPT_CHARS = 90
MAX_EXCERPTS_PER_CODE = 3

# Generic injection phrases that are ordinary inside a prompt the user is reviewing.
_NORMAL_IN_PROMPTS = re.compile(
    r"^(?:you are|ты|сен)\b|system prompt|system message|developer message|системн|жүйелік",
    re.IGNORECASE,
)

_COMPILED = [(family, *family.compiled()) for family in patterns.FAMILIES]


@dataclass(frozen=True)
class Finding:
    code: str
    strong: bool
    excerpts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Detection:
    context: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    @property
    def strong(self) -> bool:
        return any(f.strong for f in self.findings)

    @property
    def verdict(self) -> str:
        """What the rules alone support: danger, caution or safe."""
        if self.strong:
            return "danger"
        return "caution" if self.findings else "safe"

    @property
    def score(self) -> int:
        """Rules-only risk, 0-100: strong findings start at 75, weak ones top out at 60."""
        strong = sum(f.strong for f in self.findings)
        weak = len(self.findings) - strong
        if strong:
            return min(100, 75 + 5 * (strong - 1) + 2 * weak)
        if weak:
            return min(60, 30 + 10 * (weak - 1))
        return 5


def excerpt(text: str) -> str:
    """One line, trimmed, invisible characters shown as a middle dot."""
    flat = " ".join(patterns.INVISIBLE_CHARS.sub("·", text).split())
    return flat if len(flat) <= EXCERPT_CHARS else flat[: EXCERPT_CHARS - 1] + "…"


def _matches(pattern: re.Pattern | None, text: str) -> list[str]:
    if pattern is None:
        return []
    found: list[str] = []
    for match in pattern.finditer(text):
        snippet = excerpt(match.group())
        if snippet and snippet not in found:
            found.append(snippet)
        if len(found) == MAX_EXCERPTS_PER_CODE:
            break
    return found


def _hidden_text(text: str) -> list[str]:
    hits: list[str] = []
    invisible = len(patterns.INVISIBLE_CHARS.findall(text)) + len(patterns.TAG_CHARS.findall(text))
    if invisible:
        hits.append(f"U+200B ×{invisible}")  # code points, the same in every language
    hits += [excerpt(m.group()) for m in patterns.HIDING_MARKUP.finditer(text)][:2]
    return hits


def detect(text: str, context: str = DEFAULT_CONTEXT, task: str = "") -> Detection:
    """Run every family over `text`, weighted for `context`."""
    if context not in CONTEXTS:
        context = DEFAULT_CONTEXT
    findings: dict[str, Finding] = {}

    def add(code: str, strong: bool, excerpts: list[str]) -> None:
        if not excerpts:
            return
        previous = findings.get(code)
        if previous:
            merged = tuple(dict.fromkeys(previous.excerpts + tuple(excerpts)))[:MAX_EXCERPTS_PER_CODE]
            findings[code] = Finding(code, previous.strong or strong, merged)
        else:
            findings[code] = Finding(code, strong, tuple(excerpts[:MAX_EXCERPTS_PER_CODE]))

    # Generic injection phrases, shared with the screenshot scanner.
    generic = [excerpt(p) for p in injection_phrases(text)]
    if context == "prompt":
        generic = [p for p in generic if not _NORMAL_IN_PROMPTS.search(p)]
    add("ais_direct_injection", True, generic)

    for family, strong, weak in _COMPILED:
        add(family.code, True, _matches(strong, text))
        promote = context == "memory" and family.code == "ais_memory_poisoning"
        add(family.code, promote, _matches(weak, text))

    urgency = scan_message(text).urgency_matches
    add("urgency", False, [excerpt(u) for u in urgency])

    if context == "tool":
        for finding in posture.review(text, task):
            add(finding.code, finding.strong, list(finding.excerpts))

    if "ais_payment_change" in findings and findings.keys() & {
        "ais_verification_bypass", "ais_authority_claim", "urgency",
    }:
        add("ais_payment_redirect", True, list(findings["ais_payment_change"].excerpts))

    hidden = _hidden_text(text)
    if hidden:
        add("ais_hidden_text", bool(findings) or bool(patterns.TAG_CHARS.search(text)), hidden)

    return Detection(context=context, findings=tuple(findings.values()))
