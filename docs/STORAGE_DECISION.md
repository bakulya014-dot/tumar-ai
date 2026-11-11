# Storage decision note (MVP)

**Status:** decision record, 2026-11-11. No migration is part of this
change.
**Decision:** stay on SQLite, one file per process that needs one, on a
persistent disk. Revisit when one of the triggers in section 5 is met.

## 1. What is stored today

| Data | Where | Written by | Contains |
|---|---|---|---|
| Registered users | `users.db` (`TUMAR_USERS_DB`) | Website, on Google sign-in | Email, display name, language, first/last seen, sign-in count. No passwords, tokens or analysis content. |
| Bot group registry | `telegram_bot/broadcast.db` (`TUMAR_BROADCAST_DB`) | Bot, when added to or removed from a group | Chat id, title, chat type. |
| API keys and usage | `tumar.db` (`TUMAR_DB_PATH`) | REST API (not deployed) | Key **hash** (never the key), owner, quota; per-request endpoint, kind, verdict, status, duration. No request content. |
| Contributed samples | `tumar.db`, `contributions` table | REST API / website, only with explicit consent | Redacted text (max 2,000 chars), language, verdict, consent version, optional review label. |
| Session reports | Browser session memory (`report_store.py`) | Website | The last reports of one visitor. Gone when the tab closes; never on disk. |
| Daily quotas | Process memory (`services/quota.py`) | Website, bot | Hashed identity → count for today. Reset on restart and at 00:00 UTC. |
| Telemetry | stderr log lines (`services/telemetry.py`) | All | Kinds, outcomes, codes, timings, tokens. No content or identities (enforced in code). Retention is whatever the host keeps for logs. |
| Held-out / tuning corpora | Git (`evals/`) | Developers | Labelled examples, no personal data. |

Not stored anywhere: passwords checked by Password Health (hashed in
memory; only the first 5 characters of the SHA-1 hash are sent to the
breach database), images (validated,
read, discarded), messages and URLs checked without a contribution,
API keys in plain text, bot tokens.

## 2. What the MVP should store

Only what a feature needs, and only after it exists:

- **Keep as is:** users, bot group registry, API key hashes and usage,
  consented redacted contributions.
- **Add only with the feature:** analysis history for signed-in users
  ("Trust Timeline"). If built, store the report *summary* (kind,
  verdict, score, time, a short redacted preview) keyed to the user,
  with a user-visible delete, and a fixed retention (for example 90
  days). Never the full input.
- **Optional:** quota counters in SQLite, so limits survive restarts.
  Only worth it once restarts are frequent enough to be abused.

## 3. What must never be stored

- Passwords, one-time codes, card numbers, IIN/ЖСН numbers, bot tokens
  or API keys in plain text.
- Full message text, screenshots or URLs a user checked, unless they
  explicitly contributed them (then: redacted, consent version recorded,
  deletable).
- Raw IP addresses or Telegram user ids joined to content.
- Model prompts and answers in logs.

## 4. Is SQLite enough?

**Yes, for a single instance of each process**, which is the current
deployment (one Streamlit app, one bot worker, the API not deployed):

- The write rates are tiny: a sign-in, a group join, a consented
  sample. SQLite handles thousands of writes per second on one disk.
- One file per concern, so the website, the bot and the API never
  compete for the same lock.
- Backups are a file copy (use `sqlite3 <db> ".backup <file>"` while
  running).

**Requirement: a persistent disk.** This is the real constraint, not
SQLite. Streamlit Community Cloud and most container platforms give
an ephemeral filesystem that is wiped on every deploy or restart:

- `users.db` and `broadcast.db` are then silently empty after each
  deploy (the bot reaches no groups; sign-up history is lost).
- Fix: mount a persistent volume and point `TUMAR_USERS_DB`,
  `TUMAR_BROADCAST_DB` and `TUMAR_DB_PATH` into it. Where the host has
  no volumes (Streamlit Community Cloud), accept the loss for the
  website's users table during the pilot, or move that one table to a
  managed database (section 5).

SQLite is the wrong choice when two machines must write the same data
(it is a local file), or when many processes write the same file under
heavy concurrency.

## 5. When PostgreSQL becomes justified

Move to a managed PostgreSQL when **any** of these is true, not before:

1. **More than one instance must share data:** the website or API
   scaled to two or more replicas, or a separate admin service reading
   live user or contribution data.
2. **The host has no persistent disk** and the data matters (for
   example, users on Streamlit Community Cloud that an institutional
   pilot depends on).
3. **Analysis history** for signed-in users is built and has to be
   queried across users (reporting, review queues for contributions).
4. **Compliance asks for it:** managed backups, point-in-time recovery,
   access audit, encryption at rest with key management, data residency.

The migration is small: four tables with plain types. Keep the stores
behind their current modules (`user_store`, `TargetRegistry`,
`keystore`, `corpus_store`) so callers do not change.

## 6. When Redis becomes justified

Not now. Redis earns its place when:

- quotas or rate limits must be shared between **several** instances
  (in-memory counters stop being correct the moment there are two);
- the bot moves to webhooks behind several replicas and needs shared
  deduplication or FSM state;
- a measured hot path (the same URL checked many times a minute) needs
  a shared cache. Telemetry from PR #5 will show whether that is true.

With one instance per process, in-process memory already does all of
this.

## 7. Cost categories (estimates only)

These are rough categories for planning, **not quotes**. Prices change;
verify on each provider's current pricing page before deciding.

| Option | What it is | Rough category |
|---|---|---|
| SQLite on the app host | A file | Free; needs a persistent volume |
| Persistent volume (1–5 GB) | Disk attached to a container host | Typically a few USD/month or included in a paid plan |
| Small VPS running everything | 1–2 vCPU, 1–2 GB RAM, own disk | Typically single-digit to low double-digit USD/month |
| Managed PostgreSQL, free/hobby tier | Small shared instance | Free to low single-digit USD/month, with limits (pausing, storage caps) |
| Managed PostgreSQL, small production | Dedicated small instance with backups | Typically tens of USD/month |
| Managed Redis | Small instance | Free tiers exist; small paid tiers typically a few to tens of USD/month |
| Kazakhstan-hosted (data residency) | Local cloud providers | Varies; get a quote if residency becomes a requirement |

## 8. Recommendation

1. Keep SQLite. Put every `.db` file on a persistent volume wherever the
   host offers one, using the existing environment variables.
2. Do not add PostgreSQL or Redis until a trigger in section 5 or 6
   is met; record which one when that happens.
3. Before building analysis history, write its retention and deletion
   rules first (section 2).
