"""Kazakhstan Threat Map — prototype with SIMULATED data.

There is no real data source behind this yet: Tumar.AI stores no user
checks, and no anonymised aggregate feed exists. The figures below are
illustrative, fixed numbers chosen to show what the view will look like
once aggregate, anonymised category counts exist. The page labels them
as demo data everywhere they appear; they must never be presented as
real statistics.

What would make it real later: count only (region, category, week)
triples from opted-in checks, with small counts suppressed, and never
store the content that was checked.
"""

from __future__ import annotations

from services.trust_report import TrustReport

IS_SIMULATED = True

CATEGORIES = ("phishing", "impersonation", "telegram_fraud", "fake_jobs", "marketplace", "qr_fraud")
REGIONS = (
    "almaty", "astana", "shymkent", "karaganda", "aktobe", "atyrau", "pavlodar", "oskemen",
)

# Simulated weekly report counts per region and category (illustrative only).
_DEMO = {
    "almaty":    (148, 71, 96, 61, 83, 22),
    "astana":    (121, 58, 74, 48, 59, 17),
    "shymkent":  (77, 39, 69, 52, 41, 9),
    "karaganda": (58, 26, 37, 29, 33, 6),
    "aktobe":    (41, 19, 33, 27, 22, 5),
    "atyrau":    (36, 17, 21, 31, 18, 4),
    "pavlodar":  (32, 14, 24, 17, 19, 3),
    "oskemen":   (29, 13, 22, 15, 16, 3),
}


def region_counts() -> dict[str, dict[str, int]]:
    """region -> category -> simulated count."""
    return {r: dict(zip(CATEGORIES, _DEMO[r])) for r in REGIONS}


def national_counts() -> dict[str, int]:
    """category -> simulated national total."""
    return {c: sum(_DEMO[r][i] for r in REGIONS) for i, c in enumerate(CATEGORIES)}


# Keyword cues for matching the user's own last check to a category.
# Deliberately simple and local: nothing is sent or stored.
_CUES = {
    "qr_fraud": ("qr", "qr-код", "qr-кодты", "qr code"),
    "fake_jobs": ("job", "vacancy", "salary", "работа", "вакансия", "заработ", "жұмыс", "жалақы", "лайк"),
    "marketplace": ("olx", "order", "delivery", "parcel", "доставк", "заказ", "посылк", "тапсырыс", "жеткізу", "сәлемдеме"),
    "telegram_fraud": ("telegram", "телеграм", "tg ", "premium", "премиум"),
}


# Checks about the person's own exposure, not about a scam they received:
# a leaked email or a weak password is not "phishing" on the map.
_NOT_SCAMS = {"email", "password"}


def categorize(report: TrustReport) -> str | None:
    """The demo category a risky check most resembles; None for safe results
    and for exposure checks (email breaches, passwords)."""
    if report.verdict == "safe" or report.subject_type in _NOT_SCAMS:
        return None
    text = f" {report.subject_preview.lower()} "
    codes = " ".join(e.code.lower() for e in report.evidence)
    if "qr" in codes:
        return "qr_fraud"
    lookalike = {"url_brand_lookalike", "url_misspelled_domain", "url_homoglyph"}
    if lookalike & {e.code for e in report.evidence} and not {"credential", "otp_disclosure"} & {
        e.code for e in report.evidence
    }:
        return "impersonation"
    for category, cues in _CUES.items():
        if any(cue in text for cue in cues):
            return category
    return "phishing"  # links, code requests, impersonation, credential theft
