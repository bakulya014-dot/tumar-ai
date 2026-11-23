"""AI Security Check findings -> one standard TrustReport.

The same schema, renderer, risk card and history as every other check;
nothing here is a second scoring system.

Verdict rules:

- The rules' verdict is a floor. The AI can raise it (it may spot a
  paraphrase the patterns miss) but never lower it. When the AI tried
  to, its explanation and advice are dropped, fixed translated text is
  shown instead, and the event is logged with no content.
- Without the AI (provider failure, kill switch, no key) the report is
  rules-only, labelled "offline" like every other rules-only result,
  and never "safe": no rule matching is not proof of safety.
- Confidence is capped at 90 with the AI and 60 without it: this is
  static analysis of text, and Tumar cannot see what an agent would
  actually do with it.
"""

from __future__ import annotations

from services import telemetry
from services.ai_security.analysis import THREATS, AiSecurityAnalysis
from services.ai_security.detector import Detection
from services.offline_report import OFFLINE_CAP
from services.output_guard import clean_text
from services.trust_report import Evidence, Metric, TrustReport, preview_text

SOURCE = "ai_security"
SUBJECT = "ai_content"
AI_CONFIDENCE_CAP = 90

_RANK = {"safe": 0, "caution": 1, "danger": 2}
_AI_VERDICTS = {"Safe": "safe", "Suspicious": "caution", "Dangerous": "danger"}
_TRUST_CAP = {"safe": 100, "caution": 60, "danger": 25}
_REC_KEYS = ["ais.rec.human_review", "ais.rec.verify", "ais.rec.limit"]


def _rule_evidence(detection: Detection) -> list[Evidence]:
    evidence: list[Evidence] = []
    for finding in detection.findings:
        weight = "strong" if finding.strong else "weak"
        for snippet in finding.excerpts or ("",):
            evidence.append(Evidence(kind="heuristic", code=finding.code, detail=snippet, weight=weight))
    return evidence


def _ai_evidence(ai: AiSecurityAnalysis) -> list[Evidence]:
    """One AI finding per threat, quoting the passage the model pointed at."""
    evidence: list[Evidence] = []
    for index, threat in enumerate(ai.threats):
        quote = ai.excerpts[index] if index < len(ai.excerpts) else (ai.excerpts[0] if ai.excerpts else "—")
        evidence.append(Evidence(kind="ai", code=THREATS[threat], detail=quote, weight="weak"))
    return evidence


def build(
    text: str,
    detection: Detection,
    ai: AiSecurityAnalysis | None,
    *,
    task_given: bool = False,
    offline_reason: str = "",
) -> TrustReport:
    rules = detection.verdict
    metadata = {
        "context": detection.context,
        "task_given": "yes" if task_given else "no",
        "rules_verdict": rules,
    }
    metrics = [Metric(label_key="ais.metric_rules", value=detection.score)]
    reasons = ["ais.reason_static"]
    evidence = _rule_evidence(detection)

    if ai is None:
        verdict = rules if rules != "safe" else "caution"
        metadata |= {"mode": "offline", "offline_reason": offline_reason or "ai_error"}
        return TrustReport(
            source=SOURCE,
            subject_type=SUBJECT,
            subject_preview=preview_text(text),
            verdict=verdict,
            trust_score=min(100 - detection.score, _TRUST_CAP[verdict], OFFLINE_CAP),
            confidence=OFFLINE_CAP,
            metrics=metrics,
            evidence=evidence,
            explanation_key=f"ais.explain.rules_{verdict}",
            recommended_action_keys=list(_REC_KEYS),
            confidence_reason_keys=reasons + ["trust.offline.confidence"],
            analysis_metadata=metadata,
        )

    ai_verdict = _AI_VERDICTS[ai.verdict]
    verdict = max(rules, ai_verdict, key=_RANK.__getitem__)
    overruled = _RANK[ai_verdict] < _RANK[rules]
    metrics.append(Metric(label_key="ais.metric_ai", value=ai.risk_score))
    evidence += _ai_evidence(ai)
    risk = max(detection.score, ai.risk_score)
    confidence = min(ai.confidence, AI_CONFIDENCE_CAP)
    reasons.append("ais.reason_agree" if ai_verdict == rules else "ais.reason_disagree")
    metadata |= {"mode": "full", "ai_verdict": ai_verdict}

    explanation, actions, action_keys = ai.explanation, list(ai.recommended_actions), []
    objective = ai.attack_objective if verdict != "safe" else ""
    explanation_key = ""
    if overruled:
        telemetry.emit("guard", kind=SUBJECT, action="ai_overruled", outcome=rules)
        explanation, actions, objective = "", [], ""
        explanation_key = f"ais.explain.overruled_{rules}"
        action_keys = list(_REC_KEYS)
        metadata["guard"] = "ai_overruled"
    objective = clean_text(objective)
    if objective:
        metadata["attack_objective"] = objective

    return TrustReport(
        source=SOURCE,
        subject_type=SUBJECT,
        subject_preview=preview_text(text),
        verdict=verdict,
        trust_score=min(100 - risk, _TRUST_CAP[verdict]),
        confidence=confidence,
        metrics=metrics,
        evidence=evidence,
        explanation=explanation,
        explanation_key=explanation_key,
        recommended_actions=actions,
        recommended_action_keys=action_keys,
        confidence_reason_keys=reasons,
        analysis_metadata=metadata,
    )
