"""Pattern families for the AI Security Check, in English, Russian and Kazakh.

Each family names one threat and is split into STRONG patterns (wording
that only appears when someone is trying to steer an AI or an analyst)
and WEAK ones (wording that also appears in ordinary text, and only
means something next to other findings). The detector decides weight
by context: "do not escalate" is strong in a security log, and so is
"from now on always" in an agent's memory.

Patterns are deliberately conservative. A missed paraphrase is reported
honestly by the evaluation; a false alarm on an ordinary email teaches
people to ignore the tool. Kazakh patterns use verb stems so formal and
informal forms both match (елеме / елемеңіз), and negative imperatives
("жібермеңіз", "do not send") are excluded where a positive verb is
the signal.

The generic injection phrases ("ignore previous instructions", in all
three languages) are shared with the screenshot scanner and live in
services/image_scanner/classifier.py; this module adds the families
that only matter when the reader is an AI system.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_FLAGS = re.IGNORECASE | re.UNICODE | re.MULTILINE


@dataclass(frozen=True)
class Family:
    code: str  # evidence code, i18n: trust.signal.<code>
    strong: tuple[str, ...] = ()
    weak: tuple[str, ...] = ()

    def compiled(self) -> tuple[re.Pattern | None, re.Pattern | None]:
        return _compile(self.strong), _compile(self.weak)


def _compile(patterns: tuple[str, ...]) -> re.Pattern | None:
    if not patterns:
        return None
    return re.compile("|".join(f"(?:{p})" for p in patterns), _FLAGS)


_AI = r"(?:ai|a\.i\.|assistant|llm|language model|chatbot|copilot|agent|model|gpt|chatgpt|claude|gemini)"

DIRECT_INJECTION = Family(
    "ais_direct_injection",
    strong=(
        r"(?:ignore|disregard|forget|override|bypass) (?:all |any |the |of )*(?:previous|prior|above|earlier|existing|your|system)"
        r" (?:security |safety )?(?:instructions|rules|guidelines|policies|prompts?|guardrails)",
        r"(?:you are|act as|enter|switch to) (?:now )?(?:in )?(?:developer|dan|jailbreak|unrestricted|god) mode",
        r"\bnew (?:system )?instructions?\s*:",
        r"\[/?(?:system|inst)\]|<\|?(?:im_start|system)\|?>|^#{2,}\s*(?:system|instructions?)\b",
        r"забудь(?:те)? (?:все )?(?:предыдущие|прошлые|прежние) (?:инструкции|указания|правила)",
        r"новые инструкции\s*:|режим разработчика",
        r"жаңа нұсқаулар\s*:|әзірлеуші режимі",
    ),
)

INDIRECT_INJECTION = Family(
    "ais_indirect_injection",
    strong=(
        rf"\b(?:note|message|instructions?|reminder) (?:to|for) (?:the |any )?{_AI}\b",
        rf"\bif you are an? {_AI}\b|\bif you(?:'re| are) an? automated",
        rf"\b(?:dear|hey|hello|attention),? {_AI}\b",
        rf"\b{_AI}s? (?:reading|processing|summari[sz]ing|reviewing|triaging) this\b",
        r"\bwhen (?:summari[sz]ing|processing|reviewing|reading|triaging) this,? (?:you )?(?:must|should|need to|ignore|do not|don't)",
        r"(?:примечание|сообщение|инструкция|указание|заметка) для (?:ии|ии-ассистента|ассистента|нейросети|модели|бота|агента)",
        r"если ты (?:ии|ассистент|нейросеть|языковая модель|модель|бот|агент)",
        r"(?:ии|нейросеть|ассистент|агент|модель),? (?:который|которая) (?:читает|обрабатывает|анализирует)",
        r"(?:жи|жасанды интеллект|ассистент|бот|агент)[- ]?(?:ге|ға|ке|қа)? ?арналған (?:нұсқау|ескерту|хабарлама)",
        r"егер сен (?:жи|жасанды интеллект|ассистент|бот|агент|модель)",
        r"(?:бұны|мұны|осыны) оқып (?:жатқан|отырған) (?:жи|ассистент|бот|агент|модель)",
    ),
)

EVIDENCE_MANIPULATION = Family(
    "ais_evidence_manipulation",
    strong=(
        r"\b(?:mark|classify|label|tag|flag|close|resolve) (?:this|it|the (?:alert|event|incident|ticket|detection|finding))"
        r" (?:as )?(?:a )?(?:false[- ]positive|benign|resolved|informational|low (?:severity|priority))",
        r"\b(?:do not|don't|never) (?:escalate|alert|notify (?:the )?(?:soc|security|analyst)|open an incident|raise (?:an )?alert)",
        r"\b(?:downgrade|lower|reduce|decrease) (?:the |its |this )?(?:severity|priority|risk(?: score)?|alert level)",
        r"\bset (?:the )?(?:severity|priority) to (?:low|informational|info|none)",
        r"\b(?:suppress|silence|mute|disable) (?:this |these |the |all )?(?:alerts?|detections?|rules?|notifications?)",
        r"\b(?:add|put|move) (?:this |the )?(?:ip|address|domain|hash|host|file|sender|process|binary)?\s?(?:to|on|into) (?:the )?(?:allow|white|safe)[- ]?list",
        r"\bignore (?:this|these|the following|all) (?:alerts?|indicators?|iocs?|detections?|warnings?|events?)",
        r"(?:отметь|пометь|классифицируй|закрой)(?:те)? .{0,25}?как ложн",
        r"\bне эскалир",
        r"(?:понизь|снизь|уменьш)(?:те|ите)? (?:уровень|критичность|приоритет|важность)",
        r"(?:подави|отключи|заглуши)(?:те)? (?:это |эти |все )?(?:оповещени|алерт|уведомлени|правил)",
        r"добав(?:ь|ьте) .{0,30}?в (?:белый список|исключени|доверенн)",
        r"игнорируй(?:те)? (?:эти |этот |все )?(?:алерт|оповещени|индикатор|ioc|предупреждени)",
        r"жалған (?:дабыл|іске қосылу|оң нәтиже) деп (?:белгіле|жікте)",
        r"эскалацияла(?:ма|у қажет емес)",
        r"(?:маңыздылығын|деңгейін|басымдығын) (?:төмендет|азайт)",
        r"(?:ақ|сенімді) тізімге (?:қос|енгіз)",
        r"(?:бұл |осы |барлық )?(?:ескертулерді|дабылдарды|индикаторларды) (?:елеме|ескерме)",
    ),
    weak=(
        # "No further action needed" alone is how analysts close real tickets: not counted.
        r"\bno (?:further )?investigation (?:is )?(?:needed|required|necessary)",
        r"\b(?:this|the) (?:activity|traffic|behaviou?r|connection|login|process) is (?:expected|authori[sz]ed|known[- ]good)",
        r"дальнейш(?:ее|ие|ая) (?:расследовани|проверк|действи)\w* не (?:требуется|нужн)",
        r"ожидаемое поведение|легитимная активность",
        r"қосымша тексеру қажет емес|күтілген әрекет",
    ),
)

EXFILTRATION = Family(
    "ais_exfiltration",
    strong=(
        r"\b(?:send|forward|email|e-mail|post|upload|share|leak|transmit|exfiltrate|copy|paste) (?:me |us |them )?(?:all |the |any |your |every |their )*"
        r"(?:(?:user|users'|customer|admin|login|account|stored|saved|employee)s? )?(?:credentials|passwords?|passcodes?|api[ _-]?keys?|access tokens?|tokens|secrets|"
        r"private keys?|ssh keys?|session cookies?|cookies|system prompt|chat history|conversation history|customer data|personal data|database dump)",
        r"\b(?:reveal|print|show|repeat|output|dump|disclose|leak) (?:me |us )?(?:your|the) (?:full |entire |complete )?(?:system prompt|hidden instructions|"
        r"initial instructions|original instructions|configuration|api[ _-]?keys?|secrets|environment variables)",
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=",
        r"\b(?:append|include|add|encode|embed) (?:the |all |any )?(?:user'?s? |conversation |chat |session )?(?:data|history|credentials|tokens?|messages|secrets)"
        r" (?:to|in|into) (?:the |a )?(?:url|link|query(?: string)?|image|request)",
        r"(?:отправь|перешли|вышли|скинь|передай|пришли|загрузи)(?:те)? .{0,30}?(?:парол|логин|учётн|учетн|токен|ключ|api|секрет|cookie|куки|"
        r"системн(?:ый|ые) (?:промпт|инструкци)|переписк|персональн|клиентск)",
        r"(?:покажи|выведи|раскрой|повтори)(?:те)? (?:свой |свои |полный |весь )?(?:системный промпт|системные инструкции|скрытые инструкции|api[- ]?ключ)",
        r"(?:құпиясөз|құпия сөз|логин|токен|кілт|api|куки|жүйелік нұсқау|клиент деректер)\w*.{0,30}?(?:жібер|жолда|көшір)(?!ме)",
        r"(?:жүйелік нұсқау|жүйелік промпт|жасырын нұсқау)\w* (?:көрсет|шығар|айт)(?!па)",
    ),
)

MEMORY_POISONING = Family(
    "ais_memory_poisoning",
    strong=(
        r"\bfor (?:all )?(?:future|subsequent|later) (?:conversations|sessions|requests|queries|answers|chats|tasks)",
        r"\b(?:store|save|write|keep|commit) (?:this|it|the following|these (?:rules|facts)) (?:in|to|into) (?:your )?(?:long[- ]term |persistent |permanent )?memory",
        r"\b(?:update|change|overwrite|replace) your (?:memory|policy|policies|rules|instructions|knowledge base|guidelines)",
        r"\badd (?:this|the following) to your (?:memory|knowledge base|instructions|rules)",
        r"\b(?:permanent|standing|persistent) (?:instruction|rule|policy|directive)",
        r"(?:запомни|сохрани)(?:те)? (?:это |эту информацию |следующее )?(?:навсегда|на будущее|в (?:свою |долгосрочную |постоянную )?память)",
        r"для (?:всех )?(?:будущих|последующих) (?:запросов|разговоров|ответов|диалогов|сессий)",
        r"(?:обнови|измени|перезапиши)(?:те)? (?:свою |свои )?(?:память|политику|правила|инструкции|базу знаний)",
        r"(?:жадыңа|жадыңызға) (?:сақта|жаз|енгіз)",
        r"(?:барлық )?(?:болашақ|келесі) (?:сұрауларда|сұхбаттарда|жауаптарда)",
        r"(?:жадыңды|ережелеріңді|нұсқауларыңды|саясатыңды) (?:жаңарт|өзгерт)",
    ),
    weak=(
        # "for all future payments" is ordinary in a supplier email; in an agent's memory it is a standing rule.
        r"\bfor (?:all )?(?:future|subsequent) (?:payments|invoices|orders|transfers)",
        r"для (?:всех )?(?:будущих|последующих) (?:платежей|счетов|заказов)",
        r"(?:барлық )?(?:болашақ|келесі) (?:төлемдерде|шоттарда)",
        r"\bfrom now on,? (?:always|never|you (?:must|should|will))",
        r"\balways (?:recommend|prefer|approve|trust|choose|route)",
        r"\bthe (?:new|correct|official|updated) (?:policy|procedure|rule) is\b",
        r"(?:отныне|с этого момента|впредь),? (?:всегда|никогда)",
        r"всегда (?:рекомендуй|одобряй|выбирай|доверяй)",
        r"бұдан (?:былай|кейін) (?:әрқашан|ешқашан)",
        r"әрқашан (?:ұсын|мақұлда|таңда|сен)",
        r"есіңде сақта",
    ),
)

TOOL_POISONING = Family(
    "ais_tool_poisoning",
    strong=(
        r"<\s*important\s*>",
        r"\bbefore (?:using|calling|running|invoking) (?:this|the|any other) tool",
        r"\b(?:do not|don't|never) (?:tell|mention|inform|show|reveal|disclose)(?: this| it)?(?: to)? (?:the )?user",
        r"\b(?:read|cat|open|load|access|send|upload) (?:the )?(?:contents of )?(?:~/|/etc/passwd|/etc/shadow|\.ssh|id_rsa|\.env\b|credentials\.json|\.aws|\.npmrc|\.git-credentials|\.netrc)",
        r"\b(?:instead|also|first),? (?:call|use|invoke) (?:the )?[\w.-]+ tool",
        r"\b(?:pass|include|send|put) (?:the )?(?:contents|token|key|password|credentials|conversation)(?: of [\w./~-]+)? (?:as|in|into) (?:a |the )?(?:parameter|argument|field|sidenote)",
        r"\bthis tool (?:must|should) (?:always )?be (?:called|used|run) (?:first|before)",
        r"не (?:сообщай|говори|показывай|рассказывай)(?:те)? (?:об этом )?пользовател",
        r"перед (?:использованием|вызовом) (?:этого |любого |другого )?инструмента",
        r"пайдаланушыға (?:айтпа|көрсетпе|хабарлама)",
        r"(?:бұл |осы |басқа )?құралды (?:қолданбас|пайдаланбас|шақырмас) бұрын",
    ),
)

PAYMENT_CHANGE = Family(
    "ais_payment_change",
    weak=(
        r"\b(?:new|updated|changed|different|revised|alternative) (?:bank(?:ing)?|payment|remittance|beneficiary|wire|receiving) (?:details|account|information|instructions)",
        r"\b(?:our|the|my) (?:bank(?:ing)? details|bank account|iban|beneficiary|account details|payment details) (?:have|has) (?:changed|been (?:changed|updated))",
        r"\b(?:change|update) (?:of |to )?(?:our |the )?(?:bank(?:ing)? details|bank account|iban|beneficiary|payment details)",
        r"\b(?:pay|transfer|send|wire|remit) (?:the |this |all )?(?:payment|invoice|funds|money|amount|balance)? ?(?:to|into) (?:the |our |this )?(?:new|updated|following|attached|different) (?:account|iban|bank)",
        r"(?:новые|изменились|изменённые|измененные|обновлённые|обновленные|актуальные) (?:банковские |платёжные |платежные )?реквизиты",
        r"(?:смена|изменение|изменились) (?:наших |банковских |платёжных |платежных )?реквизит",
        r"(?:оплатите|переведите|перечислите)(?: оплату| средства| деньги| сумму)? на (?:новый|другой|этот|следующий) (?:счёт|счет|iban)",
        r"жаңа (?:банк(?:тік)? )?(?:реквизит|шот|есепшот)",
        r"реквизит(?:тер|теріміз|теріміздің)? (?:өзгерді|ауысты|жаңартылды)",
    ),
)

VERIFICATION_BYPASS = Family(
    "ais_verification_bypass",
    weak=(
        r"\b(?:do not|don't|no need to|there is no need to|please don't|you don't need to) (?:call|phone|verify|confirm|check with|contact|ring)",
        r"\b(?:skip|bypass|without) (?:the )?(?:usual |normal |standard |second )?(?:verification|approval|callback|call-?back|sign-?off|dual approval|confirmation|checks?)",
        r"\bkeep (?:this|it) (?:confidential|between us|quiet|private|secret)",
        r"\b(?:i am|i'm) (?:in a meeting|travel(?:l)?ing|unavailable|on a flight|boarding)",
        r"\b(?:can't|cannot) (?:talk|take calls|be reached|answer)",
        r"\bне (?:звоните|звони|перезванивайте|проверяйте|подтверждайте)\b",
        r"\bбез (?:проверки|согласования|подтверждения|звонка)\b",
        r"\b(?:строго )?конфиденциально\b|между нами",
        r"\bя (?:сейчас )?на (?:совещании|встрече|переговорах)",
        r"\bне могу (?:говорить|разговаривать|ответить)",
        r"(?:қоңырау шалма|хабарласпа)(?:ңыз|ңдар)?\b",
        r"тексер(?:удің|у) қажет(?:і)? жоқ|тексерусіз|келісімсіз",
        r"(?:құпия|жасырын) (?:ұста|сақта)",
        r"жиналыстамын|кездесудемін|сөйлесе алмаймын",
    ),
)

AUTHORITY_CLAIM = Family(
    "ais_authority_claim",
    weak=(
        r"\b(?:ceo|cfo|coo|managing director|general director|chairman|founder|head of finance|finance director)\b",
        r"(?:генеральн(?:ый|ого) директор|финансов(?:ый|ого) директор|руководител\w+ компании|директор(?:а)? компании)",
        r"(?:бас директор|қаржы директоры|компания басшысы)",
    ),
)

FAMILIES = (
    DIRECT_INJECTION,
    INDIRECT_INJECTION,
    EVIDENCE_MANIPULATION,
    EXFILTRATION,
    MEMORY_POISONING,
    TOOL_POISONING,
    PAYMENT_CHANGE,
    VERIFICATION_BYPASS,
    AUTHORITY_CLAIM,
)

# Hidden or invisible text: rarely innocent next to instructions.
INVISIBLE_CHARS = re.compile("[​‌‍⁠⁢⁣⁤﻿­]")
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")  # invisible "ASCII smuggling"
HIDING_MARKUP = re.compile(
    r"<!--.*?-->|display\s*:\s*none|font-size\s*:\s*0(?:px|pt|em)?\b|visibility\s*:\s*hidden"
    r"|color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b|opacity\s*:\s*0(?:\.0+)?\b",
    _FLAGS | re.DOTALL,
)
