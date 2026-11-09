"""Risk scoring for an image: documented, grouped, no double counting.

Scale: 0 (no suspicious indicator found) to 100 (several strong,
independent indicators). Risk is NOT confidence — confidence is about
how well the image was read, and is computed separately by
services/confidence from the same evidence.

Signals are grouped so that correlated indicators count once. Within
a group the strongest finding sets the group's contribution; groups
add up and the total is capped at 100.

    group                strongest contribution   why
    ------------------   ----------------------   ---------------------------------
    url                  +50 strong / +15 weak     a look-alike or raw-IP address is
                                                   the clearest sign of phishing; a
                                                   shortener alone merely hides
    otp                  +50 disclosure / +5 entry asking to REVEAL a code is the
                                                   single best predictor in the corpus
    credential           +30                       phrases demanding login data
    injection            +30                       text written for the AI, not the
                                                   reader, only ever appears in scams
    urgency              up to +15                 scaled from the scanner's 0-100
    bait                 +10 financial, +10 manip. common in ordinary mail too
    visual               +10 indicators, +10 otp   what the vision model SAW; its OTP
                                                   observation counts only when the
                                                   text layer did not already score it
    ai_opinion           blended, see below        the text model's own risk_score

The deterministic score above is always computed. When the AI text
layer ran, the final score is the mean of the two: both layers have
been measured by the evaluation harness, neither is allowed to
override the other, and disagreement is surfaced through confidence.

Levels:
    inconclusive  nothing legible and nothing decoded — no basis to judge
    low           0-19     no suspicious indicator identified
    moderate      20-49    weak signals only
    high          50-74    at least one strong signal (a strong URL finding or
                           an OTP disclosure request alone reaches 50)
    critical      75-100   several strong, independent signals
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.heuristics import HeuristicReport
from services.image_scanner.url_extractor import UrlFinding

LEVELS = ("inconclusive", "low", "moderate", "high", "critical")

URL_STRONG = 50
URL_WEAK = 15
OTP_DISCLOSURE = 50
OTP_ENTRY = 5
CREDENTIAL = 30
INJECTION = 30
URGENCY_MAX = 15
FINANCIAL = 10
MANIPULATION = 10
VISUAL_INDICATORS = 10
VISUAL_OTP = 10

# Fewer legible characters than this, with no link and no QR code,
# means there is nothing to score. Better to say so.
MIN_TEXT_FOR_VERDICT = 12


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    deterministic_score: int
    ai_score: int | None
    contributions: tuple[tuple[str, int], ...] = field(default=())

    @property
    def inconclusive(self) -> bool:
        return self.level == "inconclusive"


def level_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "moderate"
    return "low"


def assess(
    heuristics: HeuristicReport | None,
    urls: tuple[UrlFinding, ...],
    text_length: int,
    injection_count: int = 0,
    vision_indicators: int = 0,
    vision_otp: bool = False,
    ai_risk_score: int | None = None,
    anything_read: bool = True,
) -> RiskAssessment:
    """Combine every signal into one documented score."""
    contributions: list[tuple[str, int]] = []

    if urls:
        if any(u.strong for u in urls):
            contributions.append(("url", URL_STRONG))
        elif any(u.suspicious for u in urls):
            contributions.append(("url", URL_WEAK))

    otp_scored = False
    if heuristics is not None:
        if heuristics.otp_signal == "disclosure":
            contributions.append(("otp", OTP_DISCLOSURE))
            otp_scored = True
        elif heuristics.otp_signal == "entry":
            contributions.append(("otp", OTP_ENTRY))
        if heuristics.credential_indicators:
            contributions.append(("credential", CREDENTIAL))
        if heuristics.urgency_score:
            contributions.append(("urgency", round(URGENCY_MAX * heuristics.urgency_score / 100)))
        if heuristics.financial_indicators:
            contributions.append(("financial", FINANCIAL))
        if heuristics.manipulation_indicators:
            contributions.append(("manipulation", MANIPULATION))

    if injection_count:
        contributions.append(("injection", INJECTION))

    if vision_indicators:
        contributions.append(("visual", VISUAL_INDICATORS))
    if vision_otp and not otp_scored:
        contributions.append(("visual_otp", VISUAL_OTP))

    deterministic = min(100, sum(points for _, points in contributions))

    if ai_risk_score is None:
        score = deterministic
    else:
        score = round((deterministic + max(0, min(100, ai_risk_score))) / 2)

    nothing_to_judge = (
        not anything_read
        or (text_length < MIN_TEXT_FOR_VERDICT and not urls and not contributions)
    )
    level = "inconclusive" if nothing_to_judge else level_for(score)

    return RiskAssessment(
        score=score,
        level=level,
        deterministic_score=deterministic,
        ai_score=ai_risk_score,
        contributions=tuple(contributions),
    )
