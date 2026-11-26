"""Kazakhstan Threat Map — published official statistics on internet fraud.

Every figure here comes from a public report: officially registered
internet-fraud cases (Finprom.kz's summary of registered-crime statistics),
the Ministry of Internal Affairs, the National Bank's Anti-fraud Centre and
the financial regulator (ARDFM). Each block keeps its period and source so
the page can cite it. Nothing here is estimated, simulated or computed from
Tumar.AI users. The one derived number, "other schemes", is the national
total minus the five named schemes, and the page says so.

How to refresh: when a new period is published, replace the numbers and
update AS_OF and the period strings. tests/test_threat_map.py checks that
the totals still add up.
"""

from __future__ import annotations

from dataclasses import dataclass

from services.trust_report import TrustReport

AS_OF = "2026-11-26"  # when these figures were last checked against the sources

# --- Sources (title, publisher, date, URL) ---------------------------------
SOURCES = {
    "finprom": (
        "Calls from \"banks\", phishing and \"online shops\": every fifth crime in Kazakhstan is internet fraud",
        "Finprom.kz", "2026-08-21",
        "https://finprom.kz/ru/article/zvonki-ot-bankov-fishing-i-onlajn-magaziny-kazhdoe-pyatoe-prestuplenie-v-kazahstane-internet-moshennichestvo",
    ),
    "inbusiness": (
        "Internet fraud in Kazakhstan fell 10% in January–July 2026",
        "Inbusiness.kz (citing Finprom.kz)", "2026-08-21",
        "https://inbusiness.kz/ru/last/na-10-snizilos-internet-moshennichestvo-v-kazahstane-za-yanvar-iyul-2026-goda",
    ),
    "nur": (
        "Internet-fraud cases in Kazakhstan grew 55 times",
        "Nur.kz (citing Finprom.kz)", "2026-08-21",
        "https://www.nur.kz/nurfin/personal/2415987-kolichestvo-faktov-internet-moshennichestva-vyroslo-v-55-raz-v-kazahstane/",
    ),
    "mvd": (
        "Cyber fraud in Kazakhstan 2026: Ministry of Internal Affairs and Anti-fraud Centre figures",
        "Central Media 24 (citing the Ministry of Internal Affairs, National Bank, ARDFM)", "2026-11-23",
        "https://centralmedia24.kz/kibermoshennichestvo-kazakhstan-2026-statistika-antifrod-vozvrat-deneg/",
    ),
    "antifraud": (
        "Anti-fraud Centre statistics",
        "National Bank of Kazakhstan — Anti-fraud Centre", "data to 2026-11-01",
        "https://antifraud.kz/ru/statistics",
    ),
}

# --- National picture --------------------------------------------------------
PERIOD = "jan_jul_2026"  # the period the scheme and region figures cover

NATIONAL_TOTAL = 13_100          # registered internet-fraud cases, Jan–Jul 2026
NATIONAL_CHANGE_PCT = -10.3      # vs Jan–Jul 2025
SHARE_OF_ALL_CRIME_PCT = 19.5    # internet fraud / all registered crimes, Jan–Jul 2026
SHARE_OF_ALL_FRAUD_PCT = 57.0    # internet fraud / all fraud, Jan–Jul 2026 (53.7% a year earlier)

YEAR_2025_TOTAL = 28_851         # full-year 2025, a record (23.3% of all crimes)
YEAR_2025_SHARE_PCT = 23.3
YEAR_2018_TOTAL = 517            # 2018 — 2025 is ~55 times higher

NINE_MONTHS_2026_TOTAL = 15_000  # Ministry of Internal Affairs, ~15 thousand, Jan–Sep 2026
NINE_MONTHS_CHANGE_PCT = -20.8

CALLS_BLOCKED_2026 = 187_000_000      # fraudulent calls blocked since Jan 2026 (MVD, Nov 2026)
SITES_BLOCKED_2026 = 33_000           # illegal internet resources blocked (MVD, Nov 2026)
PHISHING_SITES_BLOCKED_2026 = 8_000   # of which phishing sites
ANTIFRAUD_INCIDENTS = 80_871          # Anti-fraud Centre incidents, Jul 2024 – early 2026
FRAUD_LOANS_2025 = 5_100              # fraudulently issued loans in 2025 (ARDFM)
FRAUD_LOANS_2025_BN_TENGE = 4.6

# Registered cases by scheme, Jan–Jul 2026 (the five largest named schemes).
CATEGORIES = ("bank_calls", "phishing", "service_ads", "online_purchases", "online_loans", "other")
_SCHEMES = {
    "bank_calls": 2_900,        # fake SMS and calls "from the bank"
    "phishing": 2_700,          # fake sites, e-mails, links, malicious apps
    "service_ads": 2_600,       # fake ads offering services
    "online_purchases": 1_900,  # pay-first online shopping
    "online_loans": 1_300,      # loans taken out in the victim's name
}


def national_counts() -> dict[str, int]:
    """category -> registered cases, Jan–Jul 2026. "other" = total minus the named five."""
    counts = dict(_SCHEMES)
    counts["other"] = NATIONAL_TOTAL - sum(_SCHEMES.values())
    return counts


# --- By region -----------------------------------------------------------------
@dataclass(frozen=True)
class Region:
    key: str
    cases: int | None        # registered cases Jan–Jul 2026; None when not published
    crime_share: float | None  # internet fraud as % of all crimes in the region


REGIONS = (
    Region("astana", 2_300, 26.5),
    Region("almaty", 1_400, 11.1),
    Region("pavlodar", 1_100, 38.0),
    Region("almaty_region", 1_000, None),
    Region("karaganda", 951, 29.6),
    Region("east_kazakhstan", None, 29.8),
    Region("kostanay", None, 28.5),
    Region("abai", None, 26.0),
    Region("turkestan", None, 11.2),
    Region("shymkent", None, 9.9),
)
TOP5_SHARE_PCT = 50.7  # the five regions with published counts hold 50.7% of all cases

# Anti-fraud Centre: the five most common schemes reported to it (share of reports).
ANTIFRAUD_SCHEMES = (
    ("fake_calls", 17), ("fake_shops", 16), ("fake_investments", 14),
    ("social_messengers", 6), ("credit_fraud", 5),
)


# --- Matching the visitor's own last check to a scheme ---------------------------
# Keyword cues, deliberately simple and local: nothing is sent or stored.
_CUES = (
    ("online_loans", ("loan", "credit", "кредит", "займ", "микрозайм", "несие")),
    ("online_purchases", ("olx", "order", "delivery", "parcel", "доставк", "заказ", "посылк",
                          "тапсырыс", "жеткізу", "сәлемдеме", "предоплат")),
    ("service_ads", ("job", "vacancy", "salary", "работа", "вакансия", "заработ", "жұмыс",
                     "жалақы", "лайк", "услуг", "қызмет")),
    ("other", ("invest", "инвест", "crypto", "крипт", "пирамид", "доход", "табыс")),
    ("bank_calls", ("bank", "банк", "card", "карт", "security service", "служба безопасности",
                    "sms", "смс", "code", "код")),
)

# Checks about the person's own exposure, not about a scam they received:
# a leaked email or a weak password is not a scam scheme on the map. AI Security
# Check results describe attacks on AI tools, not the scam types mapped here.
_NOT_SCAMS = {"email", "password", "ai_content"}


def categorize(report: TrustReport) -> str | None:
    """The official scheme a risky check most resembles; None for safe results
    and for exposure checks (email breaches, passwords, AI content)."""
    if report.verdict == "safe" or report.subject_type in _NOT_SCAMS:
        return None
    codes = {e.code.lower() for e in report.evidence}
    # QR codes and look-alike domains lead to fake sites: phishing.
    if any("qr" in c for c in codes) or codes & {"url_brand_lookalike", "url_misspelled_domain", "url_homoglyph"}:
        return "phishing"
    text = f" {report.subject_preview.lower()} "
    for category, cues in _CUES:
        if any(cue in text for cue in cues):
            return category
    return "phishing"  # links, fake sites, credential theft
