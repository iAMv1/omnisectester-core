"""Render findings into markdown + HTML reports (no template deps)."""

import html
import json
import os
import time

SEV_COLOR = {"critical": "#d32f2f", "high": "#ef6c00", "medium": "#f9a825",
             "low": "#0288d1", "info": "#757575"}


def to_markdown(result: dict) -> str:
    lines = [f"# OmniSec Report - {result.get('target', 'n/a')}",
             f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}_", ""]
    stats = result.get("stats", {})
    if stats:
        lines += ["## Summary", "",
                  f"- Findings: **{stats.get('total', 0)}** "
                  f"(critical: {stats.get('critical', 0)}, high: {stats.get('high', 0)})",
                  f"- Requests sent: {stats.get('requests', 'n/a')}", ""]
    threats = result.get("threats")
    if threats:
        lines += ["## Threat Model (STRIDE)", "",
                  "| Category | Threat | Mitigation | Relevance |",
                  "|---|---|---|---|"]
        for t in threats:
            lines.append(f"| {t['category']} | {t['threat']} | {t['mitigation']} | {t['relevance']} |")
        lines.append("")
    findings = result.get("findings") or []
    if findings:
        lines += ["## Findings", ""]
        for f in findings:
            lines += [f"### [{f['severity'].upper()}] {f['title']} (`{f['id']}`, {f['cwe']})",
                      "", f"**Evidence:** {f['evidence']}", "",
                      f"**Remediation:** {f['remediation']}", ""]
    return "\n".join(lines)


def to_html(result: dict) -> str:
    rows = []
    for f in result.get("findings") or []:
        color = SEV_COLOR.get(f["severity"], "#757575")
        poc = ""
        if f.get("poc"):
            poc = (f"<div style='margin-top:6px;background:#111;color:#0f0;"
                   f"padding:8px;font-family:monospace;font-size:12px;'>"
                   f"$ {html.escape(f['poc'])}</div>")
        rows.append(
            f"<tr><td><span style='color:{color};font-weight:bold'>"
            f"{html.escape(f['severity'].upper())}</span></td>"
            f"<td>{html.escape(f['id'])}</td>"
            f"<td>{html.escape(f['title'])}<br><small>{html.escape(f['evidence'])}</small>{poc}</td>"
            f"<td>{html.escape(f['remediation'])}</td></tr>")
    body = ("\n".join(rows)) or "<tr><td colspan=4>No findings</td></tr>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>OmniSec Report - {html.escape(result.get('target', ''))}</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}</style>
</head><body><h1>OmniSec Report - {html.escape(result.get('target', ''))}</h1>
<table><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Remediation</th></tr>
{body}</table></body></html>"""


SEV_TO_SARIF = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(result: dict) -> str:
    """GitHub code scanning-compatible SARIF 2.1.0."""
    target = result.get("target", "")
    rules, results = [], []
    seen_rules = set()
    for f in result.get("findings") or []:
        if f["id"] not in seen_rules:
            seen_rules.add(f["id"])
            rules.append({
                "id": f"OMNI/{f['id']}",
                "shortDescription": {"text": f["title"]},
                "defaultConfiguration": {"level": SEV_TO_SARIF.get(f["severity"], "note")},
                "properties": {"cwe": f.get("cwe"), "security-severity": f["severity"]},
            })
        results.append({
            "ruleId": f"OMNI/{f['id']}",
            "level": SEV_TO_SARIF.get(f["severity"], "note"),
            "message": {"text": f"{f['evidence']} | Fix: {f['remediation']}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": target},
                "region": {"startLine": 1}}}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
                    "name": "omnisectester-core",
                    "informationUri": "https://github.com/iAMv1/omnisectester",
                    "rules": rules}},
                  "results": results}],
    })


def write_reports(result: dict, output_dir: str, formats: list) -> list:
    """Write report files; returns list of written paths."""
    os.makedirs(output_dir, exist_ok=True)
    stem = f"omnisec-report-{time.strftime('%Y%m%d-%H%M%S')}"
    written = []
    for fmt in formats:
        path = os.path.join(output_dir, f"{stem}.{fmt}")
        if fmt == "json":
            content = json.dumps(result, indent=2)
        elif fmt == "md":
            content = to_markdown(result)
        elif fmt == "html":
            content = to_html(result)
        elif fmt == "sarif":
            content = to_sarif(result)
        else:
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(path)
    return written
