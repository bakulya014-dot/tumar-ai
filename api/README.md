# Tumar.AI Trust API

The Trust Engine over HTTP. The engine, the analyzers and the report
schema are used unchanged — this layer adds only what a network
boundary needs: authentication, rate limiting, input limits, error
translation and logging. No detection logic lives here, so nothing can
drift from the behaviour the evaluation harness measures.

## Running it

```bash
pip install -r requirements-api.txt
export GEMINI_API_KEY=...          # the AI provider key
export TUMAR_API_KEYS=key1,key2    # keys allowed to call this API
uvicorn api.main:app --port 8000
```

Interactive documentation: `http://localhost:8000/docs`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TUMAR_DB_PATH` | `tumar.db` | Issued keys and usage records. |
| `TUMAR_API_KEYS` | — | Bootstrap keys for development. Real customers get issued keys instead. |
| `GEMINI_API_KEY` | — | AI provider key. Empty also means refuse. |
| `TUMAR_RATE_LIMIT` | 60 | Requests per key per window. |
| `TUMAR_RATE_WINDOW` | 60 | Window length in seconds. |
| `TUMAR_MAX_CONTENT` | 5000 | Longest accepted input. |
| `TUMAR_ALLOWED_ORIGINS` | none | Browser origins for CORS. Empty is correct for server-to-server. |
| `TUMAR_LOG_LEVEL` | INFO | Logging verbosity. |

## Key management

Keys are issued from the command line, never over HTTP:

```bash
python -m api.keys issue --owner "Acme Bank" --label production --quota 10000
python -m api.keys list
python -m api.keys rotate --id 3     # replaces it; the old key dies now
python -m api.keys revoke --id 3
python -m api.keys usage --days 30
python -m api.keys prune --days 90
```

Issuance is the most dangerous operation this system has — an endpoint
that mints credentials is worth more to an attacker than any single
key. It stays behind a shell until self-service is a product
requirement, at which point it should be built as one.

**Keys are stored hashed.** Only a SHA-256 digest is kept, plus a short
prefix so a key is recognizable in a listing without being usable. The
secret is printed once at issue time and cannot be recovered; if it is
lost, rotate it. A leaked database is therefore not a set of working
credentials.

**Rotation revokes immediately.** That is the right default for a key
that might be compromised. Where overlap is wanted for a planned
migration, issue a second key first and revoke the old one when the
client has moved.

## Metering and quotas

Every call is recorded: which key, when, which endpoint, the kind of
subject, the verdict, the status and the duration. **There is no column
for the content** — the privacy promise is enforced by the shape of the
table rather than by remembering to be careful at each call site.

`--quota` sets a monthly allowance; `0` means unlimited. Only
successful analyses count toward it. Charging for a call that failed
because our provider was down would be indefensible, and counting
rejected requests would let one misconfigured client lock itself out.
A key over its allowance receives `429` with code `quota_exceeded`,
refused before any AI call is made.

Usage rows are operational, not archival: `prune` drops old ones, since
keeping per-request records forever grows without bound and widens the
blast radius of a breach for no benefit once the month is billed.

## Contributing samples (opt-in)

Everything else in this platform is built on not keeping what people
send. This is the one path that keeps anything, and every restriction
on it is enforced in code rather than promised here.

```json
{"content": "…", "contribute": true}
```

- **Opt-in per request.** `contribute` defaults to `false`. There is no
  account setting that quietly turns it on for traffic sent before
  anyone thought about it.
- **Redacted before storage.** Emails, phone numbers, card numbers,
  IBANs and one-time codes are stripped. URLs survive intact — a
  scam's infrastructure is the most valuable part of a sample, and the
  rule is to redact what identifies the *person* while keeping what
  identifies the *attack*. A sample that still looks identifying after
  redaction is dropped rather than stored.
- **Asking is not the same as it happening.** The response returns
  `contributed`, which is `false` if the sample was refused.
- **Issued keys only.** A bootstrap key has no record, so nobody could
  withdraw the sample later; contributions from one are refused.
- **Consent is versioned.** Each row records the terms it was collected
  under, so changing the terms cannot retroactively cover what came
  before.

```bash
GET    /v1/contributions   # read back exactly what we hold, redacted
DELETE /v1/contributions   # delete all of it, immediately
```

Withdrawal is self-service and really deletes the rows — a promise to
delete that leaves the data in place is not a promise. Samples already
exported into the reviewed corpus have left this store and are not
covered, which the response says plainly rather than implying a reach
we do not have.

### From contributions to measurement

```bash
python -m api.corpus stats
python -m api.corpus review --limit 20
python -m api.corpus label --id 4 --as scam
python -m api.corpus export --out evals/corpus/messages_contributed.jsonl
```

Exports arrive **unlabelled**. A human decides whether each sample is a
scam, because a corpus labelled by the system it measures would only
confirm what that system already believes and the evaluation would
stop meaning anything. Once labelled, the file drops into
`evals/corpus/` and the harness picks it up automatically.

## Endpoints

`POST /v1/analyze` — analyze one subject.

```bash
curl -X POST http://localhost:8000/v1/analyze \
  -H "Authorization: Bearer key1" \
  -H "Content-Type: application/json" \
  -d '{"content": "URGENT! Confirm your card at http://kaspi-verify.xyz", "language": "en"}'
```

```json
{
  "request_id": "9f3c1a…",
  "detected_kind": "message",
  "report": {
    "verdict": "danger",
    "trust_score": 5,
    "confidence": 95,
    "confidence_reason_keys": ["confidence.agreement"],
    "evidence": [{"kind": "heuristic", "code": "otp_disclosure", "weight": "strong", "detail": "…"}],
    "metrics": [...],
    "recommended_actions": [...]
  }
}
```

Omit `kind` to let the engine detect the input; pass `"message"`,
`"url"` or `"email"` to route directly.

`GET /v1/analyzers` — what this deployment can analyze, read from the
live registry, so a newly registered analyzer appears without a code
change here.

`GET /v1/health` — liveness. Unauthenticated, and reports
`unconfigured` rather than pretending to be healthy when it cannot
serve.

## Localization

Reports carry translation keys where the producing module was
deterministic (`"breach.rec_enable_mfa"`, `"confidence.agreement"`) and
free text where the AI wrote it, in the language you request. Services
have never returned prose in a fixed language and the API inherits
that: clients localize keys themselves rather than receiving responses
frozen into English.

## Deliberate limitations

**Passwords cannot be analyzed over HTTP.** The Password Health check
works because the password never travels — only five characters of a
hash leave the process. An endpoint accepting raw passwords would
invite customers to transmit and log them across their own
infrastructure, destroying that guarantee no matter how carefully we
behave at our end. The engine the API builds excludes that analyzer
entirely, so it is structurally impossible rather than merely
undocumented. If demand appears, the right shape is an endpoint taking
a hash prefix.

**Rate limiting is per process.** Running several replicas multiplies
the effective limit. A shared store is the fix when that day comes;
until then a simple limiter that works beats a distributed one that
is not needed.

**Errors are deliberately vague to callers.** A failure returns a short
code a client can localize and a generic sentence — never a provider
name, a key, or a stack trace. The detail goes to our logs, addressed
by the `X-Request-ID` returned on every response.

## What is logged

Request id, path, status, duration, caller fingerprint, analyzer kind,
verdict and confidence. **Never** the content, the API key, or the
report's `subject_preview` — which for a message contains the message.
Callers appear as a truncated hash of their key: enough to group their
traffic, useless to anyone reading the log.
