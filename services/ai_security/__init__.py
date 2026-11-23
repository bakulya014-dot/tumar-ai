"""AI Security Check: is this text trying to manipulate an AI, or the people relying on one?

    patterns    EN/RU/KK pattern families, one per threat
    detector    rules-only findings with excerpts, weighted by context
    posture     static review of declared agent/tool permissions
    analysis    the isolated AI layer (data in, structured data out)
    report      findings + AI answer -> one TrustReport

Everything here is static analysis of text the user pasted. Nothing is
executed, no link is opened, no tool or connector is contacted, and the
AI can only describe what it sees.
"""

CONTEXTS = ("document", "prompt", "log", "memory", "tool")
DEFAULT_CONTEXT = "document"
