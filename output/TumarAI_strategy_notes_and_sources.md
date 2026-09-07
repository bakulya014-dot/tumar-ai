# Tumar.AI — investor strategy notes

## The strategy taken from Bloomin

Bloomin’s strongest investor habits are now applied to Tumar.AI:

1. Name a specific initial customer instead of saying “everyone online.”
2. Show the product early and use the demo as evidence.
3. Separate the free distribution wedge from the paid buyer.
4. Replace broad market claims with a measurable pilot funnel.
5. Use an appendix for technical depth instead of slowing the main pitch.
6. End with a concrete ask: pilot partner, data access, and measurement support.

## Mission and market justification

Tumar.AI exists because online fraud increasingly succeeds through social engineering: the attacker manipulates a person into taking an action. Traditional defenses remain necessary, but they are not designed to explain a suspicious conversation in Kazakh, Russian, or English at the exact moment of hesitation.

The market entry is Kazakhstan because the founder has local context, the language gap is real, and banks and telecom operators already carry the cost of fraud, customer support, and loss of trust. The regional expansion is Central Asia, where similar communication channels and scam playbooks recur.

## Streamlit’s role in the product

Streamlit Community Cloud is a practical MVP host because it turns the current Python app into a public, shareable product quickly. Streamlit documents GitHub-based deployment, a public `streamlit.app` subdomain, secrets configuration, dependency files, app updates, and sharing controls:

- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy
- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/file-organization
- https://docs.streamlit.io/deploy/streamlit-community-cloud/share-your-app

The important investor framing is: Streamlit is the front door and learning surface, not the final infrastructure boundary. It lets Tumar.AI validate the workflow with users before investing in a larger backend.

## PostgreSQL roadmap

PostgreSQL should be introduced when Tumar.AI needs durable, auditable product data—not as an excuse to store everything.

Recommended first schema areas:

- `users` and optional authentication records
- `consents` for contribution and data-retention choices
- `analysis_reports` with structured verdicts and timestamps
- `analysis_events` for latency, provider, and outcome measurement
- `rate_limits` and partner usage metering
- `corpus_samples` containing only redacted, consented examples
- `breach_snapshots` for normalized external results and refresh timestamps

Do not store raw passwords. Do not retain raw messages by default. Keep the database useful for measurement, reliability, abuse prevention, and consented learning—not for indiscriminate surveillance.

## Why XposedOrNot is used

XposedOrNot is used for the email-breach module because it provides a purpose-built REST API that checks whether an email address appears in known breach data and returns structured JSON. The documented endpoint is:

`https://api.xposedornot.com/v1/check-email/{email}`

Its documentation describes standard HTTP responses, a no-breach response, breach names, detailed breach analytics, and published rate limits:

- https://xposedornot.com/api_doc

The product goal is not to claim that an email is “safe forever.” The goal is to replace a guess with a grounded exposure signal:

> “This address appears in these known breach records; here are the protective actions to take.”

XposedOrNot is therefore an evidence provider, not the whole Trust Engine. The Trust Engine combines that external evidence with local heuristics and explainable recommendations.

## Builder principles used in the deck

These are operating principles, not celebrity endorsements:

- **Sam Altman / YC:** make something people want; a few users who love the product are more valuable than many users who only tolerate it. Applied here: prove repeat use and correct intervention before scaling the feature list. Source: https://blog.samaltman.com/startup-advice
- **Dario Amodei / Anthropic:** treat safety as an engineering and governance problem, not a marketing adjective. Applied here: use deterministic evidence, confidence calibration, conservative actions, and explicit privacy boundaries. Background sources: https://www.anthropic.com/news/uk-ai-safety-summit and https://arxiv.org/abs/1606.06565
- **Demis Hassabis / Google DeepMind:** advanced AI should be developed responsibly for broad human benefit. Applied here: localized access, explainability, and a product that helps ordinary people rather than only technical users. Source: https://deepmind.google/about/
- **Andrej Karpathy:** keep the system understandable and build the product around the real workflow, not around model novelty. Applied here: a small Trust Engine interface, structured reports, interchangeable providers, and a short path from user input to action. Background: https://karpathy.github.io/

The deck should never imply that these people endorse Tumar.AI. Their public principles are used as design constraints for the company.

## Video and animation QR strategy

The app QR in the deck points to:

`https://tumar-ai.streamlit.app/`

The two local MP4 files are presenter assets, not public web destinations. A scan QR for the videos should only be generated after uploading them to a public URL such as a YouTube unlisted video, a public Drive file, or the Tumar.AI website. Until then, a video QR would be misleading or unusable for judges.
