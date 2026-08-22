# omnisectester-core

Python scanning engine behind the [omnisectester](https://github.com/iAMv1/omnisectester) CLI.
**v0.1.0 is stdlib-only** — zero pip dependencies, runs on any Python ≥ 3.10.

## Bridge contract

The Node CLI spawns:

```
cli.py <command> --json [--kebab-flag value ...]
```

- Exactly **one JSON object** on stdout
- Exit `0` success / `1` failure (error JSON on stdout either way)
- Unknown flags ignored (forward-compatible)

## Capabilities (measured)

| Command | What it does | Verified by |
|---|---|---|
| `scan web <url>` | 7 security-header audit · TLS protocol/cert inspection · sensitive-path probe (`/.env`, `/.git/config`, backups...) · reflected-XSS marker probe · form discovery · rate-limited | 10/10 unit tests on a local HTTP fixture + end-to-end through the Node bridge |
| `threat-model <target>` | STRIDE table (6 rows) from observable facts, adversary profiles | contract test |
| `engage <target>` | scan → threat-model → report chain in one call | e2e via Node bridge |
| `report <result.json>` | markdown / HTML / JSON rendering | contract test |
| `sbom <dir>` | requirements.txt + package.json → CycloneDX 1.5 JSON | contract test |
| `continuous` | stub until scheduler host exists | documented |

Every finding: `{id, title, severity, evidence, remediation, cwe}`, deterministic severity-desc ordering.

## Tests

```bash
py -m unittest discover -s tests -v     # Windows
python3 -m unittest discover -s tests   # Linux/macOS
```

Tests spin a local HTTP fixture on `127.0.0.1` — no external network calls.

## Roadmap

- v0.2: OSV vulnerability enrichment for SBOM · mobile/cloud/AI/firmware engines
- Passive crawl before active probes · authenticated scanning hooks
