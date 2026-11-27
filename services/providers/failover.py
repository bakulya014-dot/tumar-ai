"""Second-provider failover: when the primary AI cannot answer, ask a backup.

The primary provider (Gemini by default) already falls back across its
own models. When every one of them is down, overloaded or rejecting the
key, a check used to end as a rules-only "offline" report. With a backup
configured, the same request goes to a second provider first.

Opt-in, like every model choice here: TUMAR_FALLBACK_PROVIDER names the
backup ("deepseek", "openai", "claude"), and it is used only when that
provider is also configured (its key is set). Unset, nothing changes.

The backup returns the same validated schema through the same prompt, so
the Trust Engine, the output guard and the report are unchanged: only
the instrument that gathered the evidence differs, and telemetry records
which one answered.
"""

from __future__ import annotations

from pydantic import BaseModel

from services import telemetry
from services.providers.base import AIProvider, ProviderError, ProviderUnsupported

# Failures where trying the backup cannot help: the caller asked for
# something the provider does not support.
_NO_FAILOVER = {"unsupported_capability"}


class FailoverProvider(AIProvider):
    """Try `primary`; on a provider failure, try `backup` once."""

    def __init__(self, primary: AIProvider, backup: AIProvider):
        self.primary = primary
        self.backup = backup
        self.name = primary.name

    def available(self) -> bool:
        return self.primary.available() or self.backup.available()

    def generate_structured[ModelT: BaseModel](
        self, system_prompt: str, contents: str, schema: type[ModelT]
    ) -> ModelT:
        try:
            return self.primary.generate_structured(system_prompt, contents, schema)
        except ProviderUnsupported:
            raise
        except ProviderError as primary_error:
            if primary_error.code in _NO_FAILOVER or not self.backup.available():
                raise
            telemetry.emit("provider_failover", provider=self.backup.name, error_code=primary_error.code)
            try:
                return self.backup.generate_structured(system_prompt, contents, schema)
            except ProviderError:
                # Report the primary's failure: it is the configured default,
                # and its code is what the incident checklist describes.
                raise primary_error from None
