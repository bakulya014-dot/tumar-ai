"""The AI layer of the AI Security Check: isolated, data-only.

The pasted text is hostile by assumption: it may be written to steer the
very model reading it. So:

- It reaches the model between markers carrying a fresh random id
  (services/prompt_boundary.py), with personal identifiers masked.
- The stated task, also typed by the user, is wrapped the same way.
- The context is one of five fixed labels, never free text.
- The rules' findings go in as codes only, never as quoted text.
- The model has no tools and no function calling, and must answer in
  the data-only schema below. It is gated by the "analyze_text"
  capability, so the operator's `ai` kill switch turns it off.
- Its verdict can only RAISE what the rules found (services/ai_security/
  report.py), and its text is defanged and escaped before display.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from services import ai_authority, prompt_boundary
from services.ai_security.detector import Detection
from services.common import ServiceError
from services.providers import AIProvider, GeminiProvider, ProviderError, text_provider
from services.redaction import redact

PROMPT_FILE = Path(__file__).resolve().parent.parent.parent / "prompts" / "ai_security_v1.md"

# What the model may name. Anything else it returns is ignored.
THREATS = {
    "direct_prompt_injection": "ais_direct_injection",
    "indirect_prompt_injection": "ais_indirect_injection",
    "evidence_manipulation": "ais_evidence_manipulation",
    "data_exfiltration": "ais_exfiltration",
    "memory_poisoning": "ais_memory_poisoning",
    "tool_poisoning": "ais_tool_poisoning",
    "excessive_permissions": "ais_perm_excessive",
    "executive_impersonation": "ais_impersonation_exec",
    "supplier_impersonation": "ais_impersonation_supplier",
}

_CONTEXT_NAMES = {
    "document": "Email, support ticket or document",
    "prompt": "AI prompt or system instruction",
    "log": "Security log or analyst evidence",
    "memory": "Agent memory or knowledge-base snippet",
    "tool": "MCP tool, connector description or agent permissions config",
}


class AiSecurityAnalysis(BaseModel):
    """The model's answer. Data only; validated before anything uses it."""

    verdict: Literal["Safe", "Suspicious", "Dangerous"]
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    threats: list[str]
    excerpts: list[str]
    attack_objective: str
    explanation: str
    recommended_actions: list[str]


class AiSecurityError(ServiceError):
    """The AI layer failed. `code` selects a localized message."""


@lru_cache(maxsize=1)
def _load_system_prompt() -> str:
    try:
        return PROMPT_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise AiSecurityError("prompt_missing") from exc


def build_contents(text: str, detection: Detection, task: str, language: str) -> str:
    """The user turn: fixed labels, wrapped untrusted blocks, rule codes."""
    block_id = prompt_boundary.new_id()
    codes = sorted(f"{f.code} ({'strong' if f.strong else 'weak'})" for f in detection.findings)
    parts = [
        f"LANGUAGE: {language}",
        f"CONTEXT: {_CONTEXT_NAMES.get(detection.context, _CONTEXT_NAMES['document'])}",
        "CONTENT TO ANALYZE (untrusted data between the markers):",
        prompt_boundary.wrap("CONTENT", redact(text), block_id),
    ]
    if task.strip():
        parts += [
            "STATED TASK OF THE AGENT (also untrusted, between the markers):",
            prompt_boundary.wrap("TASK", redact(task.strip()[:500]), block_id),
        ]
    parts.append("RULE FINDINGS (codes from our deterministic scanner):\n" + ("\n".join(f"- {c}" for c in codes) or "- none"))
    return "\n\n".join(parts)


def analyze_content(
    text: str,
    detection: Detection,
    task: str = "",
    *,
    api_key: str = "",
    language: str = "en",
    provider: AIProvider | None = None,
) -> AiSecurityAnalysis:
    """Ask the model for its structured assessment.

    Raises:
        AiSecurityError: with a short code on any failure (provider
            errors keep their codes, so the offline fallback applies).
    """
    try:
        ai_authority.require("analyze_text")
    except ai_authority.FeatureDisabled as exc:
        raise AiSecurityError(exc.code) from exc
    chosen = provider or text_provider() or GeminiProvider(api_key)
    try:
        answer = chosen.generate_structured(
            system_prompt=_load_system_prompt(),
            contents=build_contents(text, detection, task, language),
            schema=AiSecurityAnalysis,
        )
    except ProviderError as exc:
        raise AiSecurityError(exc.code) from exc
    return _tidy(answer)


def _tidy(answer: AiSecurityAnalysis) -> AiSecurityAnalysis:
    """Keep only known threats, and short, bounded text."""
    threats = list(dict.fromkeys(t for t in answer.threats if t in THREATS))
    return answer.model_copy(update={
        "threats": threats,
        "excerpts": [" ".join(e.split())[:160] for e in answer.excerpts if e.strip()][:5],
        "attack_objective": " ".join(answer.attack_objective.split())[:300],
        "explanation": answer.explanation.strip()[:1200],
        "recommended_actions": [a.strip()[:240] for a in answer.recommended_actions if a.strip()][:5],
    })
