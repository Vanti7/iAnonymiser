# iAnonymiser

**Sanitize your logs and configs before sharing them with AI — 100% local.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Fvanti7%2Fianonymiser-blue?logo=docker)](https://github.com/Vanti7/iAnonymiser/pkgs/container/ianonymiser)
[![CI](https://github.com/Vanti7/iAnonymiser/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanti7/iAnonymiser/actions/workflows/ci.yml)

> 📋 See [CHANGELOG.md](CHANGELOG.md) for release history · 🇫🇷 [Version française](docs/README.fr.md)

![demo](./docs/demo.gif)

---

## Problem

Pasting a raw log, Ansible playbook output, or `.env` file into ChatGPT/Claude to debug an issue also sends every internal IP, hostname, username, and API key it contains to a third-party service. Most of the time nobody checks first.

**iAnonymiser** detects and replaces that sensitive data with stable placeholders (`[IP_001]`, `[EMAIL_001]`, `[HOST_001]`...) locally, before the text ever leaves your machine. Once the LLM responds, you feed its answer back through iAnonymiser to restore the original values — the LLM never saw them.

## Killer feature: reversible mapping

Anonymization is one-way in most tools. iAnonymiser keeps an in-memory mapping table so the process can run in reverse:

```bash
# 1. Anonymize the log before sending it to an LLM
curl -s -X POST http://localhost:5000/anonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "Connection from 192.168.1.42 user=jdupont@company.com\nServer: prod-web-03.internal.corp\nAPI key: sk-proj-AbCdEf1234567890"}' \
  | jq -r .anonymized_text

# → Connection from [IP_001] user=[EMAIL_001]
# → Server: [HOST_001]
# → API key: [KEY_001]

# 2. Paste the anonymized text into any LLM, get a response back like:
#    "The issue is on [HOST_001], likely a firewall rule blocking [IP_001]."

# 3. De-anonymize the LLM's answer to restore the real values
curl -s -X POST http://localhost:5000/deanonymize \
  -H "Content-Type: application/json" \
  -d '{"text": "The issue is on [HOST_001], likely a firewall rule blocking [IP_001]."}' \
  | jq -r .original_text

# → The issue is on prod-web-03.internal.corp, likely a firewall rule blocking 192.168.1.42.
```

Same value always maps to the same placeholder within a session, so an LLM can reason about relationships between entities (e.g. "these two hosts share the same subnet") without ever seeing real data.

---

## Quick start

```bash
docker run -d --name ianonymiser -p 5000:5000 ghcr.io/vanti7/ianonymiser:latest
```

Open [http://localhost:5000](http://localhost:5000), or use the API directly as shown above.

### Docker Compose

```bash
git clone https://github.com/Vanti7/iAnonymiser
cd iAnonymiser
docker-compose up -d
```

### Pull a specific version

```bash
docker pull ghcr.io/vanti7/ianonymiser:latest
docker pull ghcr.io/vanti7/ianonymiser:v3.2.0
```

### Local install (without Docker)

```bash
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows

# Minimal (core anonymization only)
pip install flask gunicorn
python app.py

# Full (with detection enhancers)
pip install -r requirements.txt
python -m spacy download en_core_web_sm fr_core_news_sm
```

---

## Presets

Each preset enables a curated set of detection patterns for a given log type.

| Preset | Use case | Patterns enabled |
|---|---|---|
| `default` | General purpose | IPs, emails, URLs, UUIDs, tokens, usernames, server names |
| `ansible` | Ansible / SSH / infrastructure logs | IPs, hostnames, paths, usernames, server names |
| `apache` | Apache/Nginx access & error logs | IPs, URLs, hostnames, usernames |
| `kubernetes` | Kubernetes & Docker logs | IPs, pod/namespace names, hostnames, server names |
| `aws` | AWS CloudWatch logs | ARNs, EC2/SG/VPC IDs, access keys |
| `database` | SQL logs | IPs, connection strings, hostnames |
| `security` | Paranoid mode | Every pattern enabled |
| `minimal` | IPs and emails only | IPs, emails |

```bash
curl -s -X POST http://localhost:5000/load-preset \
  -H "Content-Type: application/json" -d '{"preset": "kubernetes"}'
```

You can also define custom presets as JSON files in `presets/` — see `presets/preset.json.example`.

---

## Detection coverage

| Category | Types |
|---|---|
| Network | IPv4, IPv6 (all forms), MAC addresses |
| Identity | Emails, usernames, phone numbers (FR/US/intl) |
| Infrastructure | Hostnames, URLs, Windows/Unix paths, server names |
| Credentials | UUIDs, API keys, JWTs, private keys, connection strings |
| Finance | Credit cards (Luhn-validated), IBAN, SSN (FR/US) |
| Other | Dates, custom regex patterns |

### Enhancers (optional, disabled by default except tldextract)

| Enhancer | Backing library | Adds |
|---|---|---|
| `presidio` | Microsoft Presidio (spaCy NER) | Person names, organizations, locations |
| `tldextract` | Public Suffix List | Accurate TLD/domain parsing (`co.uk`, new gTLDs...) |
| `llm_guard` | LLM Guard | Secret/PII scanners tuned for LLM prompts |

```bash
curl -s -X POST http://localhost:5000/enhancers/presidio \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "config": {"confidence_threshold": 0.7, "languages": ["en"]}}'
```

Enhancers degrade gracefully: if their dependency isn't installed, they simply report as unavailable instead of failing.

---

## API reference

| Method | Route | Description |
|---|---|---|
| `POST` | `/preview` | Highlight detections without replacing them |
| `POST` | `/anonymize` | Anonymize text, returns mappings + stats |
| `POST` | `/deanonymize` | Restore original values from placeholders |
| `POST` | `/reset` | Clear the current mapping table |
| `POST` | `/load-preset` | Load a named preset |
| `GET` | `/presets` | List available presets |
| `POST` | `/upload` | Anonymize an uploaded file |
| `GET` | `/export-mappings?format=json\|text` | Export the mapping table |
| `POST` | `/import-mappings` | Re-import a previously exported mapping table |
| `GET` | `/enhancers` | List enhancers and their status |
| `POST` | `/enhancers/<name>` | Configure/toggle an enhancer |
| `POST` | `/enhancers/enable-all` | Enable all available enhancers |
| `POST` | `/enhancers/disable-all` | Disable all enhancers |

### Python usage

```python
from core import Anonymizer

anon = Anonymizer()
anon.load_preset("kubernetes")
anon.add_preserve_value("localhost")
anon.add_custom_pattern(r"SRV-[A-Z0-9]+", "SERVER")

result = anon.anonymize(my_text)
print(result.anonymized_text)

original = anon.deanonymize(llm_response)
```

---

## Architecture

```
ianonymiser/
├── app.py                      # Flask entry point
├── core/                       # Anonymization engine
│   ├── models.py               # Enums (PatternType) and dataclasses
│   └── anonymizer.py           # Anonymizer class
├── enhancers/                  # Optional detection enhancers
│   ├── presidio_enhancer.py    # Microsoft Presidio (NER)
│   ├── tldextract_enhancer.py  # Domain/TLD extraction
│   └── llm_guard_enhancer.py   # LLM Guard (secrets/PII)
├── patterns/                   # Regex patterns and highlight colors
├── presets/                    # JSON preset definitions + loader
├── api/                        # Flask API blueprint
├── config/                     # App configuration
└── templates/index.html        # Web UI
```

---

## Security notes

- All processing happens locally; no data is sent to a third-party service by the anonymization engine itself.
- The Docker image runs as a non-root user and ships with a health check.
- The API has no built-in authentication — treat it like any other exposed service and put it behind a reverse proxy / VPN / auth layer if reachable outside your LAN.
- The bundled web UI loads fonts from Google Fonts (network request, no log content sent). Self-host the fonts if you need a fully air-gapped deployment.
- See [`docker-compose.demo.yml`](docker-compose.demo.yml) for a hardened configuration (payload size cap, no disk persistence, per-request isolation) intended for running a public demo instance.

---

## Contributing

Issues and PRs are welcome.

## License

MIT — see [LICENSE](LICENSE).
