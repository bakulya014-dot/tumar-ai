"""Evidence-based confidence for a Trust Report.

The AI reports its own confidence, and the product used to render that
number directly on a meter. Measurement showed why that was unwise:
in the evaluation corpus the model claimed ~83% confidence on cases it
got right 40% of the time. Self-assessment is not evidence.

This module derives confidence from things that can be checked:

    does the deterministic scanner agree with the AI?
    how much evidence is there, and how strong?
    do the two layers contradict each other?
    is there enough text to judge at all?

The rules only ever move confidence in the direction the evidence
supports, and the ceiling is set by what the evaluation harness has
actually demonstrated — never by how sure the model sounds.

Every adjustment returns a reason code, so a report can explain why it
is as confident as it is instead of asking to be taken on faith.
"""

from dataclasses import dataclass

from services.heuristics import HeuristicReport

# No verdict from this system claims more than this. Even the
# best-measured band in the harness is not a certainty, and a product
# about trust should not be the one overstating its case.
CEILING = 95

# Floor, so a report never presents itself as pure guesswork while
# still showing a verdict.
FLOOR = 20

# Two layers reaching the same conclusion independently is the
# strongest thing this architecture can offer.
AGREEMENT_BONUS = 8

# The AI called it dangerous and the scanner found nothing at all.
# That can be a subtle scam the patterns miss, or it can be the model
# reading menace into an ordinary message — the evaluation showed both.
# Either way it is weaker evidence than agreement.
LONE_AI_PENALTY = 18

# The scanner found strong signals and the AI still said "safe".
# Contradiction is the case most likely to be wrong.
CONTRADICTION_PENALTY = 25

# A short message carries little to reason about, whatever the model says.
SHORT_TEXT_CHARS = 60
SHORT_TEXT_PENALTY = 15

# A message that is itself security advice ("we will never ask for your
# code") reads as alarming and is not. Where the AI has flagged one,
# say so rather than projecting certainty.
ADVICE_CONFLICT_PENALTY = 12


@dataclass(frozen=True)
class ConfidenceEstimate:
    """A confidence value together with why it is that value."""

    value: int
    reason_keys: list[str]


def estimate(
    ai_confidence: int,
    verdict: str,
    heuristics: HeuristicReport,
    text_length: int,
) -> ConfidenceEstimate:
    """Combine the AI's self-report with checkable evidence.

    Args:
        ai_confidence: what the model claimed, used as a starting
            point rather than an answer.
        verdict: the platform verdict ("safe" / "caution" / "danger").
        heuristics: the deterministic layer's findings.
        text_length: characters of input the verdict was based on.
    """
    score = min(ai_confidence, CEILING)
    reasons: list[str] = []

    flagged = verdict in ("caution", "danger")
    strong = heuristics.strong_signals
    weak = heuristics.weak_signals

    if flagged and strong:
        # Both layers, reasoning differently, reached the same place.
        score += AGREEMENT_BONUS
        reasons.append("confidence.agreement")
    elif flagged and not strong and not weak:
        score -= LONE_AI_PENALTY
        reasons.append("confidence.ai_only")
    elif not flagged and strong:
        score -= CONTRADICTION_PENALTY
        reasons.append("confidence.contradiction")

    if flagged and heuristics.security_advice:
        score -= ADVICE_CONFLICT_PENALTY
        reasons.append("confidence.advice_conflict")

    if text_length < SHORT_TEXT_CHARS:
        score -= SHORT_TEXT_PENALTY
        reasons.append("confidence.short_input")

    if not reasons:
        reasons.append("confidence.routine")

    return ConfidenceEstimate(
        value=max(FLOOR, min(CEILING, score)), reason_keys=reasons
    )
