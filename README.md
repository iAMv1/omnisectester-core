# omnisectester-core

Python scanning engine behind the [omnisectester](https://github.com/iAMv1/omnisectester) CLI.
**Stdlib-only** — zero pip dependencies, runs on any Python ≥ 3.10.

## Bridge contract

The Node CLI spawns:

```
cli.py <command> --json [--kebab-flag value ...]
```

- Exactly **one JSON object** on stdout
- Exit `0` success / `1` failure / `2` findings met `--fail-on`
- Unknown flags parsed generically (forward-compatible)

## Capabilities (measured)

| Command | What it does |
|---|---|
| `scan web <url>` | header audit · TLS/cert inspection · content-signature path probe · reflected XSS (GET+POST) with curl PoCs · open redirect · form discovery · rate-limited crawl agent |
| `scan ai <endpoint>` | prompt-injection battery (OWASP LLM01 classes) |
| `scan extension <crx>` | browser-extension static analysis (permissions, eval, CSP, update_url, keys) |
| `scan supply-chain / cicd` | dependency + workflow poisoning checks |
| `scan mobile <apk>` | Android static analysis (permissions, debuggable, backup, signing) |
| `scan desktop <exe>` | PE metadata/signing/debug artifacts |
| `scan cloud <dir>` | offline IaC/config misconfiguration audit |
| `redteam <target>` | 12-phase kill-chain simulation mapped to MITRE ATT&CK (`--authorization` required) |
| `postexploit <evidence>` | evidence-based assessment → ATT&CK mapping |
| `threat-model <target>` | STRIDE from observable facts + adversary profiles |
| `engage <target>` | scan → threat-model → report chain in one call |
| `report <result.json>` | md / html / json / sarif / junit / attack-layer / pdf rendering |
| `sbom <dir> --vulns` | CycloneDX 1.5 + OSV.dev matching |
| `continuous --targets` | scheduled diffing against stored state |

Every finding: `{id, title, severity, evidence, remediation, cwe}` plus
auto-mapped PCI DSS / NIST 800-53 / SOC 2 / ISO 27001 controls and a
SHA-256 chain-of-custody manifest per scan. Severity escalates through
CVSS (NVD), EPSS (FIRST.org), CISA KEV and a deterministic SSVC decision.

Auth flags flow end-to-end: `--auth bearer|basic|cookie|header`,
`--auth-token`, `--login-url`, `--login-data` (session cookies adopted).
False positives are suppressed with `--suppress H001,P002`.

## False-positive discipline

Detection quality is benchmarked against deliberately vulnerable apps and
regressions are locked as fixture tests. Measured fixes so far: SPA
catch-all shells, hydration-script echoes, JSON/plain-text reflections.
Numbers and history live in the main repo README:
https://github.com/iAMv1/omnisectester#known-shortcomings--what-were-working-on-next

## Tests

```bash
py -m unittest discover -s tests -v     # Windows
python3 -m unittest discover -s tests   # Linux/macOS
```

77 tests. Tests spin a local HTTP fixture on `127.0.0.1` — no external
network calls required for the suite itself.

## Roadmap

- Authenticated crawl depth: map the app behind the login (credentials
  already flow end-to-end)
- DVWA + WebGoat benchmark matrix (deferred on Docker availability)
- Calibrated confidence labels for heuristic findings
- Scan baselines/diffing beyond the `continuous` state file
