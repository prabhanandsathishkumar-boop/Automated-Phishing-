# Automated Phishing Investigation Bot

Python analysis service + n8n workflow that triages user-reported phishing end to end:
a report lands in the abuse mailbox, the message is parsed and scored, indicators are
enriched against threat intel, and the SOC gets a verdict, an IOC list and a written
report — with the reporter answered automatically.

The Python service does the thinking. n8n does the plumbing (mailbox polling, Slack,
ticketing, replies, logging), so you can rewire the response without touching detection
logic.

```
 report in                    decide                      respond
┌──────────────┐   ┌────────────────────────────┐   ┌──────────────────────┐
│ Gmail / IMAP │   │  phishbot  (FastAPI)       │   │ Slack #soc-alerts    │
│ trigger      │──▶│  ├─ MIME + header parsing  │──▶│ ticket (Jira/TheHive)│
│ or           │   │  ├─ IOC extraction         │   │ reply to reporter    │
│ POST webhook │   │  ├─ 40 detection rules     │   │ case log (Sheets/PG) │
└──────────────┘   │  ├─ VT / AbuseIPDB /       │   └──────────────────────┘
                   │  │   urlscan enrichment    │
                   │  └─ score → verdict        │      routed by n8n Switch
                   └────────────────────────────┘      malicious/suspicious/benign
```

---

## What it actually checks

| Family | Examples |
| --- | --- |
| `AUTH` | SPF fail/softfail, DKIM fail or absent, DMARC fail, **internal domain spoofed from outside** |
| `SND` | Reply-To and Return-Path mismatch, display-name brand impersonation, exec titles from free mailboxes, disposable senders, lookalike sender domains, fake `Re:` threads |
| `URL` | Anchor text vs href mismatch, shorteners, IP-literal links, brand lookalike hosts, punycode/confusables, credential-flow paths, high-abuse TLDs, `user@host` tricks, open redirects, `javascript:` URIs |
| `BODY` | Urgency, credential requests, payment-fraud/BEC language, threats, secrecy requests, in-body login **forms**, hidden text and tracking pixels, script/iframe/meta-refresh, image-only bodies, QR-code phishing |
| `ATT` | Executables, macro-capable Office files, archives and ISO/IMG, password-protected archives, double extensions and RTL-override filenames, HTML attachments |
| `HDR` | PHPMailer-style bulk senders, stripped Received chains |
| `INTEL` | VirusTotal / AbuseIPDB / urlscan.io hits on any extracted indicator |
| `DNS` | Sender domain does not resolve, has no MX, publishes no SPF (opt-in) |

`GET /api/v1/rules` returns the live catalog of the 40 static rules with their severities
and weights. `INTEL` and `DNS` findings are produced by the enrichment stage at analysis
time, so they are not in that catalog.

Scores are **damped per family** — ten urgency keywords are one signal, not ten — then
mapped to a verdict by two thresholds you control. Every finding carries its evidence,
so a human can check the machine's work.

### Bulk mail

Legitimate marketing mail trips three rules by construction: the envelope sender belongs
to the ESP (`SND-002`), links are rewritten for click tracking (`URL-001`), and there is a
tracking pixel and a hidden preheader (`BODY-008`). Together that scored **44/100 —
"suspicious"** on a real government newsletter, which means alerting on every newsletter
a person receives, which means the alerts get muted.

So those three stand down for mail relayed through a known provider — but **only when the
message authenticates**: DMARC pass, or SPF and DKIM both passing. Anyone can relay
through SES; nobody can make DMARC pass for a domain they do not own. Phishing sent
through an ESP fails that check and is scored normally, and the click-tracking concession
is applied per link, so a phishing URL sitting alongside tracked ones is still reported.

---

## Quick start

### Local

```bash
python -m venv .venv
.venv/Scripts/activate          # Windows;  source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
cp .env.example .env            # optional: add API keys, set your internal domains

uvicorn phishbot.api.main:app --reload --port 8000
```

Triage a message from the command line — no server needed:

```bash
python -m phishbot.cli tests/fixtures/credential_phish.eml
python -m phishbot.cli report.eml --markdown --no-enrich
cat report.eml | python -m phishbot.cli -            # exit 0 benign / 1 suspicious / 2 malicious
python -m phishbot.cli --rules x                     # print the rule catalog
```

### Docker (service + n8n together)

```bash
cp .env.example .env            # set PHISHBOT_API_KEY at minimum
docker compose up -d
```

- phishbot → `http://127.0.0.1:8000` (docs at `/docs`)
- n8n → `http://localhost:5678`, reaching the API as `http://phishbot:8000`

Then import `n8n/phishing-investigation-workflow.json` — see [`n8n/README.md`](n8n/README.md).

---

## API

All endpoints require `X-API-Key` when `PHISHBOT_API_KEY` is set (`/healthz` never does).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/analyze` | Analyze a message (JSON body) |
| `POST` | `/api/v1/analyze/eml` | Analyze an uploaded `.eml` (multipart) |
| `GET` | `/api/v1/rules` | Rule catalog |
| `GET` | `/healthz` | Status, configured providers, thresholds |

**Request** — give it the raw message when you can; headers are where the authentication
evidence lives:

```json
{
  "raw_email": "Return-Path: <...>\r\nFrom: ...",
  "reported_by": "alice@example.com",
  "ticket_id": "SOC-1234",
  "enrich": true
}
```

`raw_email_b64` (base64) works too, or fall back to discrete fields — `subject`, `from`,
`to`, `body_text`, `body_html`, `headers` — when your mail node only gives you those.
Header-derived rules are weaker in that mode.

**Response** (abridged):

```json
{
  "verdict": "malicious",
  "score": 100,
  "confidence": 0.92,
  "summary": "Malicious (100/100). Strongest signal: Sender domain is a lookalike of a known brand plus 15 other findings.",
  "sender": "no-reply@micros0ft-security.com",
  "findings": [
    {
      "rule_id": "SND-006",
      "title": "Sender domain is a lookalike of a known brand",
      "severity": "critical",
      "score": 35,
      "description": "Sender domain impersonates microsoft.com (edit distance 1 from 'microsoft').",
      "evidence": ["from_domain=micros0ft-security.com"],
      "mitre": ["T1583.001"]
    }
  ],
  "indicators": [
    { "type": "url", "value": "https://micros0ft-security.com/owa/login/verify",
      "defanged": "hxxps://micros0ft-security[.]com/owa/login/verify" }
  ],
  "recommended_actions": ["Quarantine or purge the message from all mailboxes that received it.", "..."],
  "report_markdown": "# 🔴 Phishing analysis: MALICIOUS ..."
}
```

Add `?format=` to reshape it: `n8n` (flat, expression-friendly), `slack` (Block Kit),
`markdown` (the report as `text/markdown`), or the default `full`.

```bash
curl -X POST http://localhost:8000/api/v1/analyze/eml?format=n8n \
  -H "X-API-Key: $PHISHBOT_API_KEY" \
  -F file=@report.eml -F reported_by=alice@example.com
```

---

## Configuration

Everything is environment-driven (`.env` is read automatically). See `.env.example`.

| Variable | Default | Notes |
| --- | --- | --- |
| `PHISHBOT_API_KEY` | _(empty)_ | Shared secret for `X-API-Key`. Empty = open endpoint |
| `PHISHBOT_SUSPICIOUS_THRESHOLD` | `30` | Score at which a message becomes `suspicious` |
| `PHISHBOT_MALICIOUS_THRESHOLD` | `65` | Score at which it becomes `malicious` |
| `PHISHBOT_INTERNAL_DOMAINS` | _(empty)_ | Your domains. Unauthenticated mail claiming them scores +40 |
| `PHISHBOT_ENRICHMENT_ENABLED` | `true` | Master switch for all outbound intel lookups |
| `PHISHBOT_ENRICHMENT_TIMEOUT` | `8.0` | Per-request timeout, seconds |
| `PHISHBOT_MAX_INDICATORS_PER_PROVIDER` | `10` | Free-tier quota guard |
| `PHISHBOT_CACHE_TTL` | `3600` | In-process TTL cache for intel results |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `URLSCAN_API_KEY` | _(empty)_ | Each optional; missing keys are skipped silently |
| `PHISHBOT_DNS_ENABLED` | `false` | MX/SPF/DMARC record checks on the sender domain |

Tune the thresholds against your own corpus before trusting auto-response. Start with
`malicious` alerting only, watch the case log for a couple of weeks, then automate
quarantine.

---

## Tests

```bash
python -m pytest -q          # 83 tests: parsing, config, IOC extraction, rules, scoring, API
```

Fixtures in `tests/fixtures/` cover a benign newsletter, a Microsoft credential-harvest
page, a BEC wire-transfer request and a double-extension malware delivery. The benign
fixture is the important one: it asserts that a legitimate message stays quiet.

---

## Design notes

- **Fails soft, never silent.** A dead intel provider, an expired quota or a timeout
  never blocks a verdict; it lands in `errors[]` and lowers `confidence`.
- **Offline by default in tests.** Rules are pure functions over a parsed message, so
  the detection logic is testable without a network.
- **Defanged output.** Every indicator ships as `hxxps://evil[.]example`, safe to paste
  into a ticket or Slack.
- **No auto-detonation.** urlscan is queried, never submitted — submitting a scan is
  public and tips off the attacker. Sandboxing stays a deliberate analyst action.
- **Confidence is separate from score.** A header-stripped forward can still look bad,
  but you will see `confidence: 0.5` next to it.

### Known limits

- Static analysis only: links are not fetched, attachments are not detonated. A benign
  landing page that turns malicious after delivery will not be caught on re-scan.
- Brand and TLD lists are curated, not exhaustive — extend `phishbot/util/domains.py`
  with the brands your users actually get targeted with.
- Forwarded reports lose the original headers unless the reporter forwards **as an
  attachment**; teach that in the report button and the auth rules keep working.
- `.msg` (Outlook) files are not parsed natively — export to `.eml` first.

---

## Layout

```
phishbot/
  api/          FastAPI app, auth, response shaping
  analysis/     rules.py (the detections), engine.py (pipeline), scoring.py (verdict)
  parsing/      email_parser.py, headers.py, html_tools.py, ioc.py
  enrichment/   virustotal.py, abuseipdb.py, urlscan.py, dns_checks.py, runner.py
  reporting/    markdown / text / Slack Block Kit rendering
  cli.py        stand-alone triage
n8n/            importable workflow + integration guide
tests/          suite and .eml fixtures
```

Adding a rule is one decorated function in `phishbot/analysis/rules.py`:

```python
@rule("URL-011", "Link to a file-sharing site", Severity.MEDIUM, 12)
def filesharing(ctx: RuleContext) -> Iterator[Finding]:
    hits = [h for h in ctx.link_hosts if registrable_domain(h) in FILE_SHARING_HOSTS]
    if hits:
        yield _finding("URL-011", "Payload staged on a consumer file-sharing service.", hits)
```

It is picked up by the registry, the catalog endpoint and the scorer automatically.

---

## Security

This service parses hostile input by design. Keep it on an internal network, keep
`PHISHBOT_API_KEY` set, run it as the non-root user the Dockerfile creates, and do not
mount a mail spool into the container. Attachments are hashed, never executed or
written to disk.

MIT licensed.
