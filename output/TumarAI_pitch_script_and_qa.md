# Tumar.AI — 5–10 minute pitch script

## Slide 1 — Protect people before they click (35–45 sec)

“At 23:41, a message arrives: ‘Unusual login from Almaty. Confirm your identity now.’ Most people are not asking for a cybersecurity lecture. They are asking one urgent question: can I trust this?

Tumar.AI is a multilingual cybersecurity assistant that helps people decide before they click, reply, or share. It is a digital amulet for the moment of doubt—built in Kazakhstan, for the way people here actually communicate.”

Pause after “before they click.” Point to the symbol, then move to the problem.

## Slide 2 — Scams are designed for hesitation (40–50 sec)

“Online fraud is not just a technical problem. It is a decision problem. The message uses a familiar sender, a real fear, and a one-tap link.

Kazakhstan is seeing serious growth in online fraud and major financial losses. The exact numbers on this slide should be verified against the final source before presenting. The important point is that the attack reaches ordinary people through ordinary conversations.”

Transition: “But the tools people have today were built for a different moment.”

## Slide 3 — Existing defenses miss the conversational layer (35–45 sec)

“Antivirus protects files and downloads. Spam filters protect inboxes. Awareness campaigns build general knowledge. None of them is standing next to the person when the message arrives.

That is the gap Tumar.AI is built to fill: trusted decision support at the moment of doubt.”

## Slide 4 — One assistant, any suspicious input (45–55 sec)

“The experience is deliberately simple. The user pastes or forwards something suspicious. Tumar.AI looks for signals, explains what is risky, and gives one clear next action.

The important product decision is consistency: whether the input is a message, a link, an image, a password, or an email address, the user gets the same kind of answer—what happened, how confident we are, and what to do next.”

Gesture left to right across the flow.

## Slide 5 — The product is already usable (60–75 sec)

“This is the working MVP. On the left is the multilingual home experience. In the middle, Password Health checks a password without sending it to the AI layer. On the right, Email Breach Checker checks an address against known public breach data.

In the live demo, I will show one suspicious message, then one result. I will stop at the recommended action because the value is not the number on the screen—the value is helping a person make a safer decision.”

Do not spend time describing every module. Show one clean live flow.

## Slide 6 — Why Tumar.AI is different (40–50 sec)

“Tumar.AI is not trying to replace antivirus or bank security. It occupies a different layer: the conversation between the attacker and the person.

It works in the moment of doubt, speaks Kazakh as well as Russian and English, explains the verdict, uses real breach lookups where appropriate, and keeps the product privacy-first. The result is not ‘trust us.’ It is ‘here is why, and here is what you should do.’”

## Slide 7 — Distribution before monetisation (45–55 sec)

“The consumer product is the wedge, not the final business model. The free web app and Telegram bot build trust and distribution where scams already arrive.

The next step is a measured pilot with a bank or telecom operator. Those institutions already carry the cost of fraud losses, support calls, and customer distrust. Tumar.AI can become an API and embedded protection layer priced around protected customers or usage.”

Do not claim consumer revenue until there is evidence.

## Slide 8 — Founder (40–50 sec)

“I started Tumar.AI because the problem is local and personal: people in Kazakhstan receive suspicious messages in languages that generic security tools often do not explain well.

I am building the product, the detection pipeline, and the trust layer end to end. That matters at MVP stage: we are not presenting an idea waiting for a technical team. We are presenting a working product that can now be measured, improved, and deployed through partners.”

Replace the photo frame with a professional founder portrait before presenting.

## Slide 9 — The next proof point is measured prevention (40–50 sec)

“The next milestone is not another collection of features. It is evidence.

We want one bank or telecom pilot where we can measure how many suspicious interactions are correctly identified, how many users take the recommended action, and whether support burden or fraud losses improve.

Our ask is simple: a pilot partner, access to real-world scam patterns, and expert feedback on the measurement design.”

## Slide 10 — Every phone should carry a digital amulet (25–35 sec)

“Every Kazakh family once carried a tumar for protection. Every phone should carry one now.

Tumar.AI is live, multilingual, and ready for its first measured institutional pilot. Scan the code to try it.”

Stop. Smile. Let the judges ask the first question.

Estimated total: approximately 7–8 minutes with a short live demo.

# Difficult investor and judge questions

## 1. Why is this a company and not just an AI feature?

The company is the trust and distribution layer around the feature. Tumar.AI can serve consumers directly, but the larger opportunity is embedding explainable scam protection into banks, telecoms, messengers, and institutional channels that already carry the fraud cost.

## 2. What prevents Google, Kaspi, or a bank from building this?

They can build parts of it. Our advantage is focus: multilingual conversational safety, local scam patterns, a provider-agnostic Trust Engine, and feedback loops from real usage. The goal is to become the specialized layer partners integrate rather than rebuild.

## 3. Why do users need Tumar.AI if they can ask ChatGPT?

ChatGPT is general-purpose. Tumar.AI is designed around a repeatable safety workflow: deterministic signals, breach checks where appropriate, a calibrated trust report, localized recommendations, and privacy constraints. It is a product, not only a prompt.

## 4. How accurate is the detector?

We should not claim a single accuracy number until it is measured on a representative, multilingual corpus. We track scam recall, false-positive rate on legitimate messages, language performance, and confidence calibration. The next step is validating those metrics with partner data.

## 5. What happens when the AI is wrong?

The product explains evidence instead of presenting an unexplained binary decision. We also avoid absolute safety claims, show confidence, keep deterministic checks visible, and recommend conservative actions such as not opening a link or calling the institution directly.

## 6. Could a false positive damage trust?

Yes. That is why legitimate hard negatives—real bank alerts, real one-time-code messages, and urgent work messages—must be part of evaluation. A detector that flags everything is not useful.

## 7. Does Tumar.AI inspect the actual webpage behind a URL?

The current MVP performs address-level analysis and AI reasoning; it does not yet claim full webpage or redirect-chain inspection. Real-time link defense is a roadmap milestone and should be described honestly.

## 8. Does DeepSeek cross-check Gemini?

Not automatically in the current implementation. Gemini is the default text provider, while DeepSeek is an optional alternative provider. Cross-validation could become a future measured feature, but it should not be presented as current functionality.

## 9. What data do you store?

The current app keeps reports in the browser session and does not write them to disk. Email checks send the address to the breach provider. Passwords are never sent to the AI layer; only a short hash prefix is used for the k-anonymity lookup.

## 10. How do you make money?

The likely near-term revenue is B2B: bank and telecom pilots, protected-customer pricing, and institutional API licensing. The consumer app is primarily distribution and trust-building until we have evidence for a consumer pricing model.

## 11. Why would a bank pay for this?

Because banks already pay indirectly through fraud losses, support operations, reimbursement pressure, and customer churn. A pilot must prove value using measurable outcomes such as prevented transfers, reduced support contacts, or improved intervention rates.

## 12. What is the first ideal customer profile?

A Kazakhstan bank or telecom operator with a large consumer base, an active fraud-prevention team, and a measurable customer-support or scam-intervention channel. The first deal should be narrow enough to measure within weeks.

## 13. How will you acquire consumers?

Through Telegram, referrals, local educational content, bank and telecom distribution, and moments of high relevance after scam campaigns. The strongest long-term channel is institutional embedding because it places protection inside an existing trusted workflow.

## 14. Why start in Kazakhstan?

The problem is acute, the languages are underserved, and the founder has local context. Kazakhstan is a focused beachhead where we can learn quickly before expanding into Central Asia with related languages and scam playbooks.

## 15. How big is the market?

The honest first market is not “everyone with a phone.” It is the regional fraud-prevention and digital-trust spend of banks, telecoms, government programs, and large consumer platforms. We should size it from partner budgets and protected-customer volumes rather than inflate a global AI-security TAM.

## 16. What is proprietary here?

The early moat is not a secret model. It is the combination of localized data, evaluation infrastructure, workflow design, provider-agnostic orchestration, and distribution partnerships. Over time, consented redacted examples and measured outcomes can improve the detection layer.

## 17. How do you get enough training data?

Start with public scam patterns, synthetic hard negatives, expert-reviewed examples, and opt-in redacted contributions. For production learning, partner channels can provide patterns without requiring the company to retain sensitive user content.

## 18. How do you protect user privacy?

Minimize what is sent, avoid storing session content on disk, never send passwords to AI, use k-anonymity for password breach lookup, mask outputs, and make any contribution opt-in and redacted.

## 19. Could users misuse it to test stolen credentials?

The password workflow is intentionally limited to health guidance and does not expose credentials or support bulk checking. API access should rate-limit, authenticate, and exclude password analysis from remote endpoints.

## 20. Why support three languages at MVP stage?

Language is part of the product problem, not a later translation layer. A safety recommendation is only useful if the user understands it under pressure. English, Russian, and Kazakh are the initial focus; expansion follows usage data.

## 21. What is the most important product metric?

For the MVP: correct intervention rate—whether users take the recommended safe action after a high-risk verdict. For a partner pilot: prevented-loss proxy metrics, false-positive rate, repeat usage, and support-call reduction.

## 22. What is the current traction?

The current evidence is a functional MVP and public app. We should present usage, retention, pilot conversations, or user outcomes only when documented. The next traction milestone is a measured pilot, not vanity downloads.

## 23. What is the biggest technical risk?

Overconfidence: a model can sound certain while being wrong. We address this with deterministic evidence, structured outputs, calibration evaluation, conservative recommendations, and clear separation between observed facts and model reasoning.

## 24. What is the biggest business risk?

Consumers may use the product but not pay directly. That is why the business model prioritizes institutional distribution and pilots, while the consumer product creates proof, brand, and demand.

## 25. Why will this become large beyond Kazakhstan?

The threat patterns and distribution channels repeat across Central Asia. The platform architecture is reusable; the localized language and partner integrations are the expansion work. Kazakhstan is the learning market, not the total destination.

## 26. What would make you change direction?

If users do not return after the first check, or if pilots cannot show measurable intervention value, we would narrow the product to the highest-value workflow—likely institutional scam triage or messenger-integrated protection.

## 27. Why is the founder the right person?

The founder is close to the local problem, has already shipped the MVP, understands the product and technical stack, and can iterate quickly. The next proof is not credentials; it is converting that context into measured partner outcomes.

## 28. What do you need from investors or judges now?

The highest-value help is introductions to a Kazakhstan bank, telecom, university, or government digital-safety program willing to run a narrowly scoped pilot and share outcome feedback.

## 29. What would you do with funding?

Priorities would be: pilot integration, evaluation and data governance, reliability and observability, Telegram and mobile distribution, and one or two hires focused on partnerships and applied security engineering.

## 30. What does winning look like in 12 months?

One or more institutional pilots, documented intervention metrics, a repeatable integration path, stronger multilingual evaluation results, and a clear conversion from free consumer usage into paid institutional protection.
