"""Static permission review for an AI agent, tool or connector.

The user pastes what an agent or tool DECLARES: a tool description, a
connector manifest, a list of scopes, a permissions config. This module
reads that text for over-broad powers and compares them with what the
agent is supposed to do, if the user says. It is static configuration
analysis of user-declared text, nothing more: Tumar never connects to
an MCP server or connector, never runs the supplied code, and cannot
see what the agent actually does at runtime.

Findings:

    ais_perm_<scope>       a high-risk power is declared (weak on its own)
    ais_perm_no_approval   actions run without a person approving them
                           (STRONG when combined with any high-risk power:
                           that is the setup where one injected instruction
                           becomes a real payment, message or deletion)
    ais_perm_beyond_task   a declared power the stated task does not need
                           (least privilege; weak)
"""

from __future__ import annotations

import re

_F = re.IGNORECASE | re.UNICODE

# Declared powers. English identifiers dominate real manifests; Russian
# and Kazakh phrasings cover permission descriptions written by people.
SCOPES: dict[str, re.Pattern] = {
    "shell": re.compile(
        r"\b(?:shell|bash|powershell|cmd\.exe|exec(?:ute)?_(?:command|code|shell)|run_(?:command|code|shell|script)|subprocess"
        r"|code[ _-]?execution|execute (?:arbitrary |any )?(?:code|commands?)|terminal access)\b|выполнени\w+ (?:команд|кода)|команда орындау|код орындау",
        _F,
    ),
    "filesystem": re.compile(
        r"\b(?:file[ _-]?system|full[ _-]disk|all files|read_write_all|write_file|delete_file)\b|[\"'](?:/|~/?|\*|c:\\\\?)[\"']"
        r"|\b(?:fs|files):\*|доступ ко всем файлам|барлық файлдар",
        _F,
    ),
    "payments": re.compile(
        r"\b(?:payments?|transfer_funds|send_money|money transfer|wire transfers?|payouts?|billing:write|charge_card|refunds?)\b"
        r"|платеж|платёж|перевод (?:денег|средств)|төлем|ақша аудар",
        _F,
    ),
    "messaging": re.compile(
        r"\b(?:send_(?:email|mail|message|sms)|post_message|chat:write|slack:write|mail\.send|gmail\.send|smtp|send (?:emails?|messages?) on behalf)\b"
        r"|отправк\w+ (?:писем|сообщений)|хат жіберу|хабарлама жіберу",
        _F,
    ),
    "secrets": re.compile(
        r"\b(?:secrets?(?::read)?|credentials?|keychain|vault|api[_ -]?keys?|password(?:s|_manager)?|tokens?:read)\b|парол|учётн\w+ данн|құпиясөз",
        _F,
    ),
    "admin": re.compile(
        r"\b(?:admin(?:istrator)?|superuser|sudo|full[_ -]access|all[_ -]scopes|unrestricted)\b|\*:\*|[\"']\*[\"']|администратор|әкімші",
        _F,
    ),
    "delete": re.compile(
        r"\b(?:delete|remove_\w+|drop|destroy|purge|wipe|truncate)\b|rm -rf|удален|удалять|жою|өшіру",
        _F,
    ),
}

NO_APPROVAL = re.compile(
    r"auto[_ -]?(?:approve|confirm|execute)|without (?:human |user )?(?:approval|confirmation|review)|no (?:human |user )?(?:approval|confirmation)"
    r"|require[sd]?[_ -]?(?:approval|confirmation)\W{0,4}(?:false|no|0|off)|human[_ -]in[_ -]the[_ -]loop\W{0,4}(?:false|no|off|disabled)"
    r"|confirm(?:ation)?\W{0,4}(?:false|off|none|never)|--yolo|dangerously[_ -]skip|без (?:подтверждения|согласования)|растаусыз|келісімсіз",
    _F,
)

HIGH_RISK = frozenset(SCOPES)

# What a stated task implies it needs. A power absent from this list
# for the task the user described is flagged as beyond the task.
TASK_NEEDS: dict[str, re.Pattern] = {
    "messaging": re.compile(r"\b(?:e-?mails?|mail|messages?|reply|respond|notify|send|post|chat|slack|telegram)\b|письм|сообщени|ответ|хат|хабарлама|жауап", _F),
    "payments": re.compile(r"\b(?:pay|payments?|invoices?|billing|refunds?|purchases?|orders?|transfers?)\b|оплат|платеж|платёж|счет|счёт|төле|шот", _F),
    "shell": re.compile(r"\b(?:code|scripts?|build|deploy|tests?|debug|program|devops|commands?)\b|код|скрипт|команд|бағдарлама", _F),
    "filesystem": re.compile(r"\b(?:files?|documents?|folders?|director(?:y|ies)|disk|backups?|organi[sz]e)\b|файл|документ|папк|құжат", _F),
    "secrets": re.compile(r"\b(?:password manager|credentials?|secrets?|vault|key rotation)\b|парол|құпиясөз", _F),
    "delete": re.compile(r"\b(?:delete|clean ?up|remove|archive|purge)\b|удал|очист|жою|тазала", _F),
    "admin": re.compile(r"\b(?:admin|administer|manage users|it support)\b|администр|әкімш", _F),
}


class PostureFinding:
    __slots__ = ("code", "strong", "excerpts")

    def __init__(self, code: str, strong: bool, excerpts: tuple[str, ...]):
        self.code, self.strong, self.excerpts = code, strong, excerpts


def _excerpts(pattern: re.Pattern, text: str) -> tuple[str, ...]:
    from services.ai_security.detector import excerpt

    found: list[str] = []
    for match in pattern.finditer(text):
        snippet = excerpt(match.group())
        if snippet and snippet not in found:
            found.append(snippet)
        if len(found) == 3:
            break
    return tuple(found)


def declared_scopes(text: str) -> dict[str, tuple[str, ...]]:
    """High-risk powers the text declares, with what matched."""
    return {scope: hits for scope, pattern in SCOPES.items() if (hits := _excerpts(pattern, text))}


def review(text: str, task: str = "") -> list[PostureFinding]:
    scopes = declared_scopes(text)
    findings = [PostureFinding(f"ais_perm_{scope}", False, hits) for scope, hits in scopes.items()]
    no_approval = _excerpts(NO_APPROVAL, text)
    if no_approval:
        findings.append(PostureFinding("ais_perm_no_approval", bool(scopes.keys() & HIGH_RISK), no_approval))
    if task.strip():
        beyond = [hits[0] for scope, hits in scopes.items() if not TASK_NEEDS[scope].search(task)]
        if beyond:
            findings.append(PostureFinding("ais_perm_beyond_task", False, tuple(beyond[:3])))
    return findings
