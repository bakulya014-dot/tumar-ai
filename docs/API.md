# Tumar.AI Trust API — v0.2.0

Server-to-server HTTP API over the Trust Engine. The Streamlit app does
**not** use this API: it calls the engine in-process. The API is for
external integrations; its only built-in client is the opt-in sample
contribution flow (`services/corpus_client.py` → `/v1/contributions`).

Interactive docs: `GET /docs` on a running server.
Run locally: `python scripts/run_api_local.py --port 8000`
(production: set environment variables and run `uvicorn api.main:app`; see `api/README.md`).

## Changes in 0.2.0 (all additive — no field renamed or removed)

| Change | Why | Client impact |
|---|---|---|
| `success` (true/false) and `error` (null on success) on every response | one predictable envelope | none; new fields only |
| 422 / 404 / 405 now use the platform error shape | FastAPI's default `{"detail": ...}` echoed submitted content back | clients reading `detail` must read `error.code` / `error.fields` |
| Authentication checked before configuration | an anonymous caller learned whether the AI key was set | unauthenticated calls now always get 401 |
| Email lookups work without an AI key | the breach lookup never needed the AI provider | fewer 503s |
| `/v1/health` adds `checks` | see dependencies at a glance | new field only |
| `/v1/analyzers` no longer lists `image` | the API accepts text only | list now matches what is accepted |
| `X-Request-ID` header on error responses too | correlate any failure with logs | none |

## Authentication

`Authorization: Bearer <key>` or `X-API-Key: <key>`. Keys are issued
with `python -m api.keys issue ...` and stored hashed. `TUMAR_API_KEYS`
(comma-separated) holds development keys.

## Response envelope

Success:
```json
{
  "success": true,
  "error": null,
  "request_id": "7c1e0b2f9a4d4e11",
  "detected_kind": "message",
  "report": { "...": "TrustReport, see below" },
  "contributed": false
}
```

Failure (every status, every endpoint):
```json
{
  "success": false,
  "request_id": "60e1bfbf8a384aad",
  "error": { "code": "content_too_large", "message": "The submitted content is too large.", "fields": [] }
}
```
`message` is a generic, safe sentence. `code` is the stable,
localizable identifier. `fields` lists invalid request fields on 422
— never their values.

## Endpoints

### `GET /v1/health` — no authentication
```json
{"status":"ok","version":"0.2.0","checks":{"ai_provider":"configured","database":"ok","ocr":"unavailable"}}
```
`status` is `ok` when an AI key is configured, `unconfigured` otherwise.
`ai_provider: configured` means a key is present — **the provider is
not called by the health check**, so it does not prove the provider is
reachable.

### `GET /v1/analyzers` — no authentication
```json
{"analyzers":[{"kind":"email","auto_detected":true},{"kind":"url","auto_detected":true},{"kind":"message","auto_detected":true}]}
```

### `POST /v1/analyze` — key required
Request:
```json
{"content": "СРОЧНО! Ваша карта Kaspi заблокирована. Перейдите http://kaspi-secure-verify.xyz/unlock и назовите код из СМС", "language": "ru"}
```
| Field | Type | Rules |
|---|---|---|
| `content` | string | required, 1–5000 characters (`TUMAR_MAX_CONTENT`) |
| `kind` | `message` \| `url` \| `email` | optional; skips auto-detection. `password` is refused by design |
| `language` | two letters | `en` (default), `ru`, `kk` — language of the explanation |
| `contribute` | bool | default false; opt-in storage of a redacted sample (issued keys only) |

Response `report` (TrustReport, abridged from a real run):
```json
{
  "source": "scam_analyzer", "subject_type": "message",
  "verdict": "danger", "trust_score": 0, "confidence": 95,
  "evidence": [
    {"kind": "heuristic", "code": "otp_disclosure", "detail": "назовите код", "weight": "strong"},
    {"kind": "heuristic", "code": "url_brand_lookalike", "detail": "http://kaspi-secure-verify.xyz/unlock", "weight": "strong"},
    {"kind": "ai", "code": "red_flag", "detail": "...", "weight": "weak"}
  ],
  "explanation": "...", "recommended_actions": ["..."]
}
```

**Evidence provenance** — every evidence item says who found it:

| `kind` | Meaning | Verified? |
|---|---|---|
| `heuristic` | deterministic local rule matched (pattern, URL structure) | yes — reproducible, offline |
| `external` | a third-party database returned it (breach lookup) | yes — by that database |
| `ai` | a language model's assessment | **no** — an opinion, weighed by the confidence model |

When a provider is unavailable the API returns an error (below). It
never returns a verdict it could not compute, and never presents an AI
opinion or a missing lookup as a verified finding.

### `/v1/contributions` — issued keys only
`POST` stores an already-analysed, redacted sample; `GET` returns what
is held for a session; `DELETE` withdraws it. See `api/README.md`.

## Status codes

| HTTP | `error.code` | Meaning | Retry? |
|---|---|---|---|
| 400 | `unsupported_input`, `invalid_url`, `invalid_email` | input cannot be analysed as given | no |
| 401 | `unauthorized` | missing or invalid key | no |
| 404 / 405 | `not_found` / `method_not_allowed` | wrong path or method | no |
| 413 | `content_too_large` | over the length limit; rejected before any AI call | no |
| 422 | `invalid_request` | schema violation; see `error.fields` | no |
| 429 | `rate_limited`, `quota_exceeded` | per-key window or monthly quota; `Retry-After` set | later |
| 502 | `malformed` or unknown upstream code | provider answered outside the schema | yes |
| 503 | `not_configured`, `credentials`, `unavailable`, `model_unavailable` | AI analysis not possible right now | later |
| 504 | `timeout`, `unreachable` | provider did not respond in time | yes |
| 500 | `internal_error` | bug; logged with the request id | report it |

These mappings are pinned by `tests/test_api_contract.py`, which runs
the real analyzers and replaces only the network call.

## Timeouts and latency

AI-backed analyses (`message`, `url`) take seconds, not milliseconds:
measured on 2026-11-09 against Gemini from a laptop in Kazakhstan,
single requests took **5.6–16.5 s**; an email lookup took **1.8 s**;
rejected requests return in under 0.5 s. Clients should use a timeout
of at least 60 s and show progress. These are seven single
measurements, not a benchmark.
