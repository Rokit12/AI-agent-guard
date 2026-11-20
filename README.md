# Agent Shield

Security monitoring for AI agents that move money. Agent Shield scans an agent's code, probes its prompt-injection guard, watches its payments as they happen, audits who can make it act, detects AI-driven intrusions (the ARTEX pattern in the FBI's November 2026 warning) in identity, cloud and network logs, and detects ransomware in the folders it depends on. Every finding becomes one alert with a severity, what was seen, and what to do. Alerts appear live on a dashboard, and high and critical ones are emailed to the support team.

The first target is [Airwallex Agent Desk](https://github.com/Rokit12/airwallex), the 15-agent finance desk built for the Agentic Banking Hackathon. Agent Shield is a separate project: it reads Agent Desk's code and audit logs, and changes nothing in it.

## Demo video

[![Agent Shield 3-minute demo](docs/demo/poster.jpg)](docs/demo/Agent-Shield-Pitch.mp4)

**[Watch the 3-minute demo (MP4, 1080p)](docs/demo/Agent-Shield-Pitch.mp4)**: a pitch walkthrough of the dashboard scanning Airwallex Agent Desk, then catching an unlogged transfer, ransomware and an AI-driven cloud intrusion in a sandbox.

## Run it

```sh
npm install
npm run serve          # dashboard on http://localhost:4600
```

The dashboard opens with a plain status line ("All clear", "N things to fix today" or "N problems need you now") and the first thing to do. Below it:

- **Run a scan**: one button per check.
  - **Agent code**: the code scanner and access audit.
  - **Website**: a passive check of a site's HTTPS, security headers, cookies, exposed files and CORS. It defaults to the Agent Desk console; other sites need the "I own this site" box ticked.
  - **This computer**: open ports, root, Node.js version, SSH and secret file permissions.
  - **Software packages**: npm audit of the agent's dependencies, one alert per advisory.
  - **Cloud & sign-in logs**: re-reads all CloudTrail and egress logs.
  - **AI model red-team**: promptfoo; enabled when a model key is set.
- **Always watching**: payments, files, sign-ins and outbound traffic, with the last activity for each.
- **Alerts**, grouped by area. Open one to see what happened, what to do and the evidence, then mark it as handled.
- **Practice drills**: ransomware, payment attack and ARTEX intrusion. They run only inside `sandbox/`.

Everything is clickable:
- The **Act now / Today / This week** counts filter the alerts.
- **Scan everything** runs every scan at once and shows progress.
- Each scan card's **View N alerts** shows only what that scan found.
- The monitor tiles open their area's alerts.
- A **live activity** list records alerts, scans, drills and handled items as they happen.
- Alerts have **Copy details**, and **Mark all shown as handled** asks for a second tap before acting.

Keyboard: `/` search, `j`/`k` move, `o` open, `e` mark handled, `c` copy, `Esc` clear filters, `?` help.

It has light and dark themes. On phones, the header collapses to icons, the filters scroll sideways, alerts stack and buttons are full-size tap targets. It was tested at iPhone 13, Pixel 5 and iPad Mini sizes with no sideways overflow.

| Command | What it does |
|---|---|
| `npm run serve` | Scan, start the live monitors and the dashboard |
| `npm run scan` | Print the findings; exits 1 if anything high or critical is open (use it in CI) |
| `npm run probe` | Run the prompt-injection probes, attack by attack |
| `npm run simulate:ransomware` | Encrypt 40 fake statements in `sandbox/watched` |
| `npm run simulate:finance` | Write an attacked agent run log to `sandbox/runs` |
| `npm run simulate:artex` | Write an ARTEX-style intrusion as CloudTrail and egress logs to `sandbox/cloud` |
| `npm run stratus -- list` | Stratus Red Team coverage map |
| `npm test` | Detector, integration, method, OWASP and gap tests (52) |

Settings (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `TARGET_DIR` | `../airwallex` | Agent codebase to scan |
| `TARGET_GUARD` | `src/core/untrusted.ts#screenUntrusted` | The target's injection guard, `file#export` |
| `TARGET_RUNS` | `$TARGET_DIR/runs` | Folder of the agent's JSONL audit logs to follow |
| `WATCH_DIR` | `sandbox/watched` | Folder to watch for ransomware |
| `CLOUDTRAIL_DIR` | `logs/cloudtrail` | CloudTrail files (`{"Records": […]}`, `.json.gz` as delivered to S3, or `.jsonl`) |
| `EGRESS_DIR` | `logs/egress` | Outbound traffic: proxy/firewall `.jsonl` with `host`, or Route 53 Resolver query logs with `query_name` |
| `WEBSITE_URL` | the Agent Desk console | Default site for the Website scan |
| `SCAN_ALLOWED_HOSTS` | none | Comma-separated extra hosts the Website scan may check without the ownership box |
| `CLOUDTRAIL_LIVE` | off | `1` polls CloudTrail LookupEvents every 60 s with the AWS credentials present |
| `ALERT_EMAIL_TO` | `security-team@example.com` | Support team address |
| `SMTP_URL` | none | `smtp://user:pass@host:587`; without it, emails are saved to `outbox/` as `.eml` files |
| `ALERT_EMAIL_MIN` | `high` | Lowest severity that is emailed |
| `AIRWALLEX_WEBHOOK_SECRET` | none | Turns on signed Airwallex transfer webhooks and reconciliation |
| `RECON_GRACE_MS` | `60000` | How long a webhook waits for the matching log line |
| `PROMPT_GUARD_URL`, `PROMPT_GUARD_TOKEN`, `PROMPT_GUARD_THRESHOLD` | none, none, `0.5` | Prompt Guard 2 endpoint |
| `FALCO_DIR` | `logs/falco` | Folder of Falco JSON alerts |
| `SLACK_WEBHOOK_URL`, `PAGERDUTY_ROUTING_KEY`, `SNS_TOPIC_ARN` | none | Extra alert channels |
| `NOTIFY_MIN` | `high` | Lowest severity sent to those channels |
| `SHIELD_TOKEN` | none | If set, every API call and the dashboard need this token |
| `HOST`, `PORT` | `127.0.0.1`, `4600` | Where the dashboard listens |

## The detectors

**1. AI-agent code scanner** (`src/detectors/code-scan.ts`). Flags money-moving calls with no approval gate or no idempotency key, outside text sent to a model without a data fence, model output used as a paid amount, card numbers reaching a model, secrets in code or in git, TLS checks turned off, and `eval`.

**2. LLM prompt-injection probes** (`src/detectors/llm-probes.ts`). Twenty documents, in the spirit of garak: sixteen attacks and four ordinary business texts. The attacks include direct overrides, fake approvals, payment redirection, urgency, zero-width characters, spaced letters, look-alike letters, base64, HTML comments, JSON fields, Swahili, French and Spanish. They run against the target's guard function, so the check is free and gives the same answer every time. The report shows the catch rate per attack family, the false alarms, and the catch rate after text normalisation.

**3. Finance-flow monitor** (`src/detectors/finance-flow.ts`). Follows the agent's audit log as it is written and checks every payment against what came before it. It catches:
- the same request paid twice, or the same amount paid twice to the same counterparty,
- a payment above what a person approved, or with no approval at all,
- money sent to an account created right after the agent read planted instructions,
- an approval recorded by the agent itself,
- bursts of payouts.

**4. Access-control audit** (`src/detectors/access-control.ts`). Reads the infrastructure code and HTTP handlers for:
- IAM roles granted on `*`,
- public buckets,
- unauthenticated endpoints,
- CORS open to any site,
- routes that act without checking the caller,
- an approver taken from the request instead of a verified login,
- approval code that lets the proposer approve its own action.

**5. AI-driven intrusion detector** (`src/detectors/identity.ts`), built on how ARTEX-style frameworks behave according to the FBI FLASH and the Microsoft, Google/Mandiant, CrowdStrike and CSA reports. They chain attack steps at machine speed and are noisy while doing it, so their traces are in identity and network logs. Each signal is one alert that grows as the attack does:

| Signal | Rule | What it catches |
|---|---|---|
| Thin password spray | `ID-SPRAY` | Failed sign-ins across many accounts, spread across sources to dodge lockouts (Cognito and console) |
| A sign-in that works mid-spray | `ID-SPRAY-SUCCESS` | The account that fell, from an address that was spraying |
| Permission probing | `ID-PERMISSION-PROBE` | Bursts of access-denied errors from one identity |
| Enumeration | `ID-ENUMERATION` | Many different List/Describe/Get calls in minutes |
| Machine speed | `ID-MACHINE-SPEED` | 40 or more calls in 20 seconds from one identity (ARTEX runs in 2 to 25 second bursts) |
| Persistence | `ID-PERSISTENCE` | New access keys, users, admin policies, app clients, Cognito users, Lambda code |
| Role hopping | `ID-ROLE-CHAIN` | One identity assuming many roles |
| Secrets harvesting | `ID-SECRETS-BURST` | Many secrets read at once |
| Covering tracks | `ID-LOG-TAMPER` | CloudTrail stopped, logs or detectors deleted |
| Data opened up | `ID-SNAPSHOT-SHARE` | Snapshots shared to other accounts, buckets made public |
| Exfiltration | `NET-WEBHOOK-EXFIL` | Traffic to webhook.site, requestbin, ngrok, paste and tunnel services |
| Unapproved AI | `NET-UNAPPROVED-AI` | Calls to model APIs not on the approved list (DeepSeek, GLM, Grok, OpenRouter and others) |

Changes by the deploy pipeline (CDK, CloudFormation) are expected and ignored. The ARTEX drill plays a full intrusion: spray, one account falling, probing, role hopping, secrets harvesting, a new admin user, logging stopped, a snapshot shared, and output sent to webhook.site.

**6. Ransomware detector** (`src/detectors/ransomware.ts`). Watches a folder and scores each 10-second window for the signs of an attack:
- files rewritten as random bytes (Shannon entropy of 7.5 bits per byte or more, where they were text before),
- known ransomware extensions,
- ransom-note filenames and wording,
- bursts of changes,
- backups deleted in bulk.

One incident is one alert that updates as it grows, so 40 encrypted files send one email, not forty.

## Red-teaming the live model: promptfoo and garak

The probes above test the guard function. To test the model itself, Agent Shield drives two established tools at the target's real document-reading prompt: the same system prompt Agent Desk uses, with outside text fenced in `<document>` tags.

**promptfoo** (`redteam/promptfooconfig.yaml`) runs 12 finance documents with planted instructions: direct overrides, payment redirection, fake approvals, role changes, HTML comments, JSON fields, base64, Swahili, French and zero-width tricks, plus one ordinary remittance as a control. A test fails if the model:
- returns anything but JSON,
- changes the invoice amount,
- copies the attacker's account,
- adds action fields such as `approved`,
- or misses that the document asks for a different account.

```sh
ANTHROPIC_API_KEY=… AGENT_MODEL=… npm run redteam   # live model, uses API credit
npm run redteam:dry                                  # offline mock model, to check the pipeline
```

On the dashboard, **Run model red-team** does the same. The results become alerts:
- **Obeying the attacker** keeps the test's severity (critical for payment redirection).
- **Only missing the "different account" signal** is low.

**garak** (NVIDIA) brings hundreds of probes. Agent Shield serves the agent's prompt as an HTTP endpoint for it and imports garak's report:

```sh
pip install garak
npm run garak:endpoint                               # agent prompt on http://127.0.0.1:4610/generate
python -m garak -t rest -G redteam/garak-rest.json \
  --probes latentinjection,encoding.InjectBase64 --report_prefix agent-desk
cp ~/.local/share/garak/garak_runs/agent-desk.report.jsonl state/garak/   # imported automatically
npm run garak:import -- state/garak/agent-desk.report.jsonl              # or print it
```

A garak probe that gets through 50% of the time or more is critical for injection-type probes and high for others.

## Modern vulnerability-detection methods

Methods Google, CISA, OWASP and the open-source security community use now, each run as a scan button:

| Method | Where it comes from | What Agent Shield does | Result on Agent Desk |
|---|---|---|---|
| **Fuzzing** (`src/detectors/fuzz.ts`) | Google OSS-Fuzz, property-based testing (fast-check) | About 3,000 generated inputs, with a fixed seed so every run can be replayed, against the agent's injection guard. It looks for crashes, catastrophic regexes (ReDoS, over 100 ms) and simple rewrites of caught attacks that slip through. | No crashes, no ReDoS, **44 of 88 rewrites bypass the guard**. Agent Shield's normaliser, now strengthened, closes all 162 of its rewrites. |
| **Supply-chain integrity** (`src/detectors/supply-chain.ts`) | SLSA, Sigstore, npm provenance | Verifies npm's ECDSA registry signature on every production package, checks lockfile hashes against the registry, reads SLSA build provenance and its source repository, flags install scripts (the Shai-Hulud worm path) and builds a CycloneDX SBOM (`GET /api/sbom`). | 222 of 222 signatures verified, lockfile hashes match, 47 packages with provenance, no install scripts, SBOM of 196 components |
| **Secrets in git history** (`src/detectors/secrets-history.ts`) | gitleaks and TruffleHog approach | Every added line in every commit, with provider patterns (AWS, Airwallex, GitHub, Slack, Stripe, Google, wallet keys) plus an entropy check. It reports the commit and whether the secret is still present, and never shows the value. | 37 commits, no secrets |
| **Risk-based prioritisation** (`src/integrations/vuln-intel.ts`) | CISA KEV, FIRST EPSS v4, Google OSV | Advisories in CISA's Known Exploited list become critical; EPSS of 10% or more raises one to at least high. | KEV catalog 2026.11.13 (1,781 CVEs) loaded; osv.dev is blocked in the test environment, so no advisory could be matched to a CVE |
| **OSV-Scanner** (`src/integrations/osv-scanner.ts`) | Google | Runs `osv-scanner scan source -r` when installed and merges its findings | Parser tested; binary not installable in the test environment |
| **Framework mapping** (`src/frameworks.ts`) | OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026, OWASP Top 10:2025, MITRE ATT&CK and ATLAS | Every alert carries its references; the dashboard shows coverage | LLM Top 10: 10 of 10; Agentic Top 10: 10 of 10 |

Not built in: AI vulnerability hunting such as Google's Big Sleep and CodeMender (no public API), and Google's Tsunami network scanner (heavy, and active scanning is out of scope).

## OWASP tools

| OWASP project | How Agent Shield uses it | Turn it on | Tested here |
|---|---|---|---|
| **Secure Headers Project** | The Website scan compares the site with the project's own lists of 13 headers to send and 88 to remove, fetched daily from the project's repository (a built-in list is used offline). It also flags the legacy `X-XSS-Protection` filter, which OWASP's HTTP Headers Cheat Sheet says to turn off. | Always on | Live: the console sends `Server: AmazonS3` and `X-XSS-Protection: 1; mode=block`, and is missing 6 recommended headers |
| **ZAP** (Zed Attack Proxy) | Reads ZAP's Traditional JSON reports dropped in `state/zap/`. With `ZAP_API_URL` it drives a ZAP daemon itself: a spider plus the passive scan only, never an active attack. Each website rule carries its matching ZAP rule id (for example `WEB-NO-CSP` is ZAP 10038), and a ZAP alert that matches an open Agent Shield alert counts as a confirmation, not a duplicate. | `zap-baseline.py -t <site> -J report.json`, or `ZAP_API_URL`, `ZAP_API_KEY` | Report import live; daemon flow with a stand-in |
| **Dependency-Check** | Imports its JSON report from `state/dependency-check/`; with `DEPENDENCY_CHECK=1` it runs the CLI during the Software packages scan. CVE ids feed the KEV and EPSS ranking. | Install the CLI (Java); `NVD_API_KEY` recommended | Parser tested; the CLI needs the NVD feed, which the test environment blocks |
| **CycloneDX** | The Supply chain scan's SBOM is CycloneDX 1.5 (`GET /api/sbom`) | Always on | Live: 196 components |
| **Dependency-Track** | Uploads that SBOM after every Supply chain scan (`POST /api/v1/bom`, project created automatically), so Dependency-Track keeps watching the components for new advisories | `DTRACK_URL`, `DTRACK_API_KEY`, optional `DTRACK_PROJECT`, `DTRACK_VERSION` | With a stand-in server |
| **DefectDojo** | Exports every open alert in DefectDojo's Generic Findings Import format (`GET /api/export/defectdojo`), with file and line, CVE ids, KEV and EPSS, and framework tags. "Send to DefectDojo" pushes it to `/api/v2/import-scan/`. | `DEFECTDOJO_URL`, `DEFECTDOJO_TOKEN`, optional `DEFECTDOJO_PRODUCT`, `DEFECTDOJO_ENGAGEMENT` | Export live; push with a stand-in server |
| **Top 10 lists** | Every alert is tagged with OWASP Top 10:2025, OWASP LLM Top 10 2025 and OWASP Agentic Top 10 2026 ids (see above) | Always on | Live |

## On-demand scans

The dashboard's scan buttons call `POST /api/scan/:kind` (`code`, `website`, `system`, `deps`, `cloud`, `model`).
- **Website** (`src/detectors/web-scan.ts`) sends a handful of ordinary GET requests and reads the responses; it never attacks the site. It checks:
  - HTTP→HTTPS redirect, HSTS, certificate expiry
  - Content-Security-Policy, framing, nosniff, Referrer-Policy, Permissions-Policy
  - server version leaks and cookie flags
  - nine sensitive paths (`/.env`, `/.git/config` and others), aware of single-page-app fallbacks
  - public source maps and CORS that reflects any origin
- **This computer** (`src/detectors/system-scan.ts`) reads `/proc/net/tcp` for services open to the network, and checks:
  - root, Node.js end of life, `sshd_config`
  - permissions on `.env` and key files
  - world-writable watched folders
- **Software packages** runs `npm audit --omit=dev` in the target. It follows each vulnerable package back to its advisory, so one bug carried by six packages is one alert.

## Connected tools

Agent Shield drives or listens to six established tools. Each one closes a gap its own detectors leave. The dashboard's **Connected tools** panel shows which are on.

| Tool | What it adds | Turn it on | Tested here |
|---|---|---|---|
| **Semgrep taint mode** (`rules/semgrep/agent-money.yml`) | Follows data across a function: model output or email text into a payment's amount or payee, and secrets into logs. If an approval call sits just before the payment, the finding is lowered to low. | `pip install semgrep`; it runs with the Agent code scan | Yes: Semgrep 1.185 on Agent Desk |
| **Airwallex transfer webhooks** (`src/detectors/reconcile.ts`) | Checks Airwallex's record of money leaving against the agent's log. A transfer the agent never logged, or one with a different amount or payee, is critical. Signatures (HMAC-SHA256 of `x-timestamp` + body) are verified, and replays older than 5 minutes are refused. | `AIRWALLEX_WEBHOOK_SECRET`; point transfer webhooks at `POST /api/webhooks/airwallex` | Signed and forged requests locally |
| **Llama Prompt Guard 2** (`src/integrations/prompt-guard.ts`) | A model-based injection classifier, run on the same 20 probes as the regex guard so the two can be compared | `PROMPT_GUARD_URL` (any Hugging Face text-classification endpoint) or `python scripts/prompt-guard-server.py` | Parser only; the model is gated and needs a download |
| **Falco** (`integrations/falco/agent-shield-rules.yaml`) | Names the process, user and container behind ransomware renames, ransom notes, backup deletion and unexpected writers | Load the rules; send JSON alerts to `POST /api/ingest/falco` or into `logs/falco/` | Falco's JSON format via the drill and API; rules not loaded into a live Falco |
| **Stratus Red Team** (`src/integrations/stratus.ts`) | Maps 27 AWS attack techniques to the rule that should fire. All 27 are detected in replay. | `npm run stratus -- list`; `npm run stratus -- <technique>` in a sandbox account | Replay of all 27; live detonation needs AWS credentials |
| **Slack, PagerDuty, Amazon SNS** (`src/notify/channels.ts`) | Alerts go beyond email; "Mark as handled" acknowledges the PagerDuty incident | `SLACK_WEBHOOK_URL`, `PAGERDUTY_ROUTING_KEY`, `SNS_TOPIC_ARN`, `NOTIFY_MIN` | Slack against a local stand-in; PagerDuty and SNS in unit tests |

Stratus replay found and fixed four detection bugs:
- Lambda's versioned CloudTrail event names (`UpdateFunctionCode20150331v2`) were not matched.
- AMI sharing was not caught.
- Bucket policies granting a foreign AWS account were not caught.
- Bulk secret reads through `BatchGetSecretValue` and SSM SecureString were not counted.

It also added two rules: `ID-S3-MASS-DELETE` (cloud ransomware) and `ID-NO-MFA-LOGIN`.

New drills: **Unlogged payment** sends three signed webhooks (one matching, one altered, one never logged) through the real verifier. **Stratus cloud attacks** writes the replay into `sandbox/cloud`.

**Containers.** The `Dockerfile` runs Agent Shield as an unprivileged user, ready for Amazon ECS on Fargate.

## Alerts

Every detector returns plain findings, and `src/alerts.ts` turns them into alerts:
- An alert's identity is its rule plus its place, so a repeat is never a new alert.
- An incident that grows updates its alert in place.
- Everything is kept in an append-only log, `state/alerts.jsonl`.
- Acknowledging an alert records who did it and when.

The dashboard receives alerts over Server-Sent Events as they happen. It shows a toast for high and critical alerts, flashes the screen red and plays a short tone for critical ones, and sends a desktop notification once you enable it. Emails batch bursts: a critical alert goes out within 2 seconds, and high alerts are grouped into one email every 30 seconds.

## What it found in Agent Desk

- **Access control: all checks pass.** IAM permissions are scoped to model ARNs, the bucket blocks public access, CORS allows only the console's origin, and the approver comes from the Cognito login.
- **Code: no secrets, no unguarded or non-idempotent payments, and no `eval`.** Card numbers are removed before the model reads kit 14's email.
- **Website (the console): one medium issue.** It has no Content-Security-Policy; the other 8 checks pass.
- **Dependencies: 10 known vulnerabilities (8 high).** These include a Zod memory-exhaustion advisory in Zod and the 6 x402/Metal packages that bundle it (one alert), and a body-parser denial of service.
- **Prompt-injection guard: catches 8 of 16 attacks with no false alarms.** It misses obfuscated, base64-encoded and non-English instructions, and one polite payment redirection. Adding the normaliser in `llm-probes.ts` raises that to 15 of 16. Agent Desk's code never acts on document text, so these misses are gaps in warning, not in safety: the guard would stay quiet, but the agent still would not pay.

## Limits, and how each is now covered

Agent Shield is a first line of detection, not a replacement for a security team. Each original limit now has a solution built in:

| Limit | Solution built in | What it adds | Still needs |
|---|---|---|---|
| **The code scanner uses patterns,** so it can miss logic a person would catch. | **Semgrep taint analysis** (`rules/semgrep/agent-money.yml`) and **guard fuzzing** (`src/detectors/fuzz.ts`) | Semgrep follows data across a function: email text or model output into a payment's amount or payee, and secrets into logs. Fuzzing throws about 3,000 generated inputs at the guard. On Agent Desk, Semgrep found 1 real flow (approved by a person) and fuzzing found 44 of 88 rewritten attacks slip past. | GitHub CodeQL, for data flow across files |
| **The probes test a guard function,** not a live model. | **promptfoo** and **garak** red-teaming, and **Llama Prompt Guard 2** (`src/integrations/`) | promptfoo sends 12 planted-instruction documents through the same prompt the agent uses, and fails a test if the model obeys. garak adds hundreds of probes. Prompt Guard 2 is a second, model-based screen run on the same probes. | A model API key (`AGENT_MODEL` plus the provider key); Prompt Guard 2 needs Meta's licence accepted on Hugging Face |
| **The ransomware detector sees file activity in one folder,** not processes. | **Falco** rules and ingest (`integrations/falco/`, `POST /api/ingest/falco`), **mass-deletion detection in S3** (`ID-S3-MASS-DELETE`) and the **Object Lock check** (`ACC-NO-IMMUTABLE-BACKUP`) | Falco watches system calls, so each alert names the process, user and container doing the encryption, with a kill-and-isolate fix. CloudTrail catches ransomware that wipes S3. The Object Lock check makes sure backups cannot be encrypted too. | Falco running on the agent's Linux host (eBPF), and S3 data events on in the trail |
| **The finance monitor sees what the agent logs,** so an unlogged payment is invisible. | **Airwallex transfer webhooks** with reconciliation (`src/detectors/reconcile.ts`, `POST /api/webhooks/airwallex`) | Every transfer Airwallex reports is matched against the agent's log by transfer id, request id, or amount and payee. A transfer the agent never logged, or one with a different amount or payee, is critical within seconds. Signatures are verified and replays refused. | `AIRWALLEX_WEBHOOK_SECRET`, and the endpoint registered in the Airwallex web app |

### Gaps closed

The former gaps now have rules:

| Gap | Rule | What it catches |
|---|---|---|
| Stratus: lifecycle rule on the trail bucket | `ID-LOG-LIFECYCLE` | An expiration of 7 days or less on a log bucket. Critical for buckets learned from CreateTrail or UpdateTrail, or set in `CLOUDTRAIL_BUCKETS` |
| Stratus: DNS log deletion | `ID-LOG-TAMPER` | `DeleteResolverQueryLogConfig` and `DisassociateResolverQueryLogConfig` |
| Stratus: S3 ransomware with client-side encryption | `ID-S3-SSEC-ENCRYPT` | Objects rewritten with customer-provided keys (SSE-C), the 2025 Codefinger technique |
| Stratus: Bedrock model use | `ID-LLMJACKING` | Model calls or model-access probes from anyone except the agent's runtime (`MODEL_CALLERS`) |
| Stratus: discovery from an instance | `ID-INSTANCE-RECON` | A server's credentials making 8 or more kinds of lookup in minutes (stolen from instance metadata) |
| LLM07 System Prompt Leakage | `LLM-SYSPROMPT-*` | Secrets, internal addresses, account numbers or approval rules in system prompts |
| LLM08 Vector and Embedding Weaknesses | `LLM-VECTOR-*` | Retrieval without a tenant filter; untrusted documents embedded unscreened |
| LLM04 Data Poisoning, ASI06 Memory Poisoning | `LLM-CONTEXT-*`, `LLM-TRAINING-POISONED` | Planted instructions in prompt, knowledge, memory (`MEMORY_DIRS`) and training files; uncommitted changes to them |
| LLM09 Misinformation | `LLM-UNVALIDATED-OUTPUT`, `LLM-MISINFO` | Model output accepted with no validator; runs where many model answers fail validation |
| ASI07 Insecure Inter-Agent Communication | `AGENT-X402-NO-LIMIT`, `AGENT-MCP-*`, `AGENT-A2A-NO-AUTH` | x402 payments with no payee or price guard; MCP servers over HTTP, without credentials or unpinned; A2A agent cards without auth |

On Agent Desk, these checks found one low-severity issue. Kit 12's clearing buyer calls `payFetch` without a guard, so the seller's offer sets the price and payee. The clearing deposit caps the total loss. Everything else passed:
- both system prompts are clean
- no vector store is in use
- no memory or training files
- every model extraction is validated

Coverage on the dashboard: Stratus 27 of 27, OWASP LLM Top 10 10 of 10, OWASP Agentic Top 10 10 of 10.

# AI-agent-guard
