"""Send contributed samples to a Tumar.AI API instead of local disk.

The app can run on a host with no durable filesystem — Streamlit
Community Cloud restarts containers and discards whatever was written.
Collecting consented samples into storage that will vanish is worse
than not collecting them: someone agreed to help, and the thing they
agreed to then evaporates. So when the app has no durable disk it
writes to the service that does.

Everything here fails soft. A contribution is a favour the user is
doing us; if our own API is unreachable, the honest response is to
tell them it did not save, never to break the page they came for.
"""

from dataclasses import dataclass

import requests

REQUEST_TIMEOUT_S = 10


@dataclass(frozen=True)
class RemoteCorpus:
    """A Tumar.AI API that owns the contribution database."""

    base_url: str
    api_key: str

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    def submit(
        self,
        content: str,
        kind: str,
        language: str,
        verdict: str,
        confidence: int,
        session_id: str,
    ) -> bool:
        """Offer one sample. Returns whether it was stored.

        `content` must already be redacted by the caller, so that what
        leaves this process is exactly what the user was shown. The
        server redacts again on arrival; a server that trusts a client
        to have cleaned data is not protecting anyone.
        """
        try:
            response = requests.post(
                f"{self.base_url.rstrip('/')}/v1/contributions",
                headers=self._headers,
                json={
                    "content": content,
                    "kind": kind,
                    "language": language,
                    "verdict": verdict,
                    "confidence": confidence,
                    "session_id": session_id,
                },
                timeout=REQUEST_TIMEOUT_S,
            )
        except requests.exceptions.RequestException:
            return False
        if response.status_code != 200:
            return False
        try:
            return bool(response.json().get("stored"))
        except ValueError:
            return False

    def withdraw(self, session_id: str) -> int:
        """Delete everything one session contributed. Returns the count."""
        try:
            response = requests.delete(
                f"{self.base_url.rstrip('/')}/v1/contributions",
                headers=self._headers,
                params={"session_id": session_id},
                timeout=REQUEST_TIMEOUT_S,
            )
        except requests.exceptions.RequestException:
            return 0
        if response.status_code != 200:
            return 0
        try:
            return int(response.json().get("deleted", 0))
        except (ValueError, TypeError):
            return 0
