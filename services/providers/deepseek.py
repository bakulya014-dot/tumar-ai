"""DeepSeek V4 Flash, over its OpenAI-compatible API.

Configuration on top of the shared chat-completions transport. Every
value is read from the environment — a key in source is a key in the
repository, in every clone of it, and in every log that ever prints a
traceback:

    DEEPSEEK_API_KEY    required; absent means the provider is simply
                        unavailable and the platform carries on
    DEEPSEEK_BASE_URL   defaults to the endpoint below
    DEEPSEEK_MODEL      defaults to deepseek-v4-flash
    DEEPSEEK_VISION     "1" once the model is confirmed to read images

Vision defaults OFF. Whether this model accepts images has not been
confirmed here, and declaring a capability we have not seen work would
route screenshots to it and fail where the user is standing. Turning
it on is one environment variable once you have watched it succeed.

What this provider returns is evidence and reasoning — a structured
answer the Trust Engine reads. It never produces a verdict; that has
one home, and it is not here.
"""

import os

from services.providers.openai_compatible import OpenAICompatibleProvider

DEFAULT_BASE_URL = "https://model.inferx.net/endpoints/v1"
DEFAULT_MODEL = "deepseek-v4-flash"


class DeepSeekProvider(OpenAICompatibleProvider):
    """DeepSeek models through the OpenAI-compatible endpoint."""

    name = "deepseek"

    def __init__(
        self,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        vision: bool | None = None,
    ):
        super().__init__(
            # Never a literal default: an unset key must mean
            # "unavailable", not "fall back to someone's key".
            api_key=api_key or os.environ.get("DEEPSEEK_API_KEY", ""),
            base_url=base_url
            or os.environ.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL),
            model=model or os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL),
            vision=(
                vision
                if vision is not None
                else os.environ.get("DEEPSEEK_VISION", "0") == "1"
            ),
        )
