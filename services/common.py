"""Shared building blocks for Tumar.AI services."""


class ServiceError(Exception):
    """Base class for service failures.

    Services are language-independent, so instead of a human sentence
    each error carries a short `code` (e.g. "rate_limited"). The UI
    layer translates the code into the user's language.
    """

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
