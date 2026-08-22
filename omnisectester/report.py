"""Render findings into reports: markdown, HTML, JSON, SARIF 2.1.0,
JUnit XML, ATT&CK Navigator layer, and dependency-free PDF."""

import html
import json
import os
import textwrap
import time
from xml.sax.saxutils import escape as _xescape

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


SUPPORTED_FORMATS = ["json", "md", "html", "sarif", "junit", "attack_nav", "pdf"]


def junit_xml(result: dict) -> str:
    """JUnit XML: one testcase per finding (failure element); a passing
    'no-findings' case keeps suites valid when clean."""
    findings = result.get("findings") or []
    failures = len(findings)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<testsuites tests="{failures + 1}" failures="{failures}">',
             f'  <testsuite name="omnisectester" target="'
             f'{_xescape(result.get("target", ""))}" tests="{failures + 1}" '
             f'failures="{failures}">']
    if not findings:
        lines.append('    <testcase classname="omnisectester" '
                     'name="no findings at/above threshold"/>')
    for f in findings:
        msg = _xescape(f"[{f['severity'].upper()}] {f['title']} ({f['cwe']})")
        text = _xescape(f"{f['evidence']}\nFix: {f['remediation']}")
        poc = (f"\nPoC: {_xescape(f['poc'])}") if f.get("poc") else ""
        lines.append(f'    <testcase classname="omnisectester.{f["id"]}" '
                     f'name="{msg}">'
                     f'<failure message="{msg}">{text}{poc}</failure>'
                     f'</testcase>')
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines)


def attack_navigator(result: dict) -> str:
    """MITRE ATT&CK Navigator layer JSON derived from finding phases."""
    from .killchain import FINDING_PHASE, PHASES

    mitre_by_phase = {p["n"]: p["mitre"] for p in PHASES}
    score_by_sev = {"critical": 100, "high": 75, "medium": 50,
                    "low": 25, "info": 10}
    techniques = {}
    for f in result.get("findings") or []:
        phase = FINDING_PHASE.get(f["id"])
        if not phase:
            continue
        mitre = mitre_by_phase.get(phase, "")
        technique = mitre.split("/")[1] if "/" in mitre else ""
        if not technique:
            continue
        score = score_by_sev.get(f["severity"], 10)
        entry = techniques.setdefault(technique, {
            "techniqueID": technique, "score": 0,
            "comment": "", "enabled": True})
        entry["score"] = max(entry["score"], score)
        entry["comment"] = (entry["comment"] + " " + f["id"]).strip()[:200]
    return json.dumps({
        "name": f"OmniSec - {result.get('target', '')}",
        "versions": {"layer": "4.5", "navigator": "5.0", "attack": "16"},
        "domain": "enterprise-attack",
        "description": f"Generated by omnisectester-core from {result.get('command')} run",
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8cff8c"],
                     "minValue": 0, "maxValue": 100},
        "layout": {"layout": "side"},
        "techniques": list(techniques.values()),
    }, indent=2)


def pdf_minimal(result: dict) -> str:
    """Dependency-free single-font PDF. Valid enough for Acrobat/Chrome/
    Edge print preview; plain-text layout with severity prefixes."""

    def esc(s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [f"OmniSec Report - {result.get('target', '')}",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
             ""]
    stats = result.get("stats") or {}
    if stats:
        lines.append(f"Findings: {stats.get('total', 0)} "
                     f"(critical {stats.get('critical', 0)}, "
                     f"high {stats.get('high', 0)}) "
                     f"Requests: {stats.get('requests', '-')}")
        lines.append("")
    for f in result.get("findings") or []:
        lines.append(f"[{f['severity'].upper()}] {f['id']} {f['title']} ({f['cwe']})")
        wrapped = textwrap.wrap(f"Evidence: {f['evidence']}", 88) or [""]
        lines += ["  " + w for w in wrapped]
        wrapped = textwrap.wrap(f"Fix: {f['remediation']}", 88) or [""]
        lines += ["  " + w for w in wrapped]
        if f.get("poc"):
            wrapped = textwrap.wrap(f"PoC: {f['poc']}", 88)
            lines += ["  " + w for w in wrapped]
        lines.append("")

    pages = []
    per_page = 46
    chunks = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [["(empty)"]]
    for chunk in chunks:
        content_lines = ["BT", "/F1 9 Tf", "40 780 Td", "14 TL"]
        for j, line in enumerate(chunk):
            safe = esc(line[:105])
            prefix = "" if j == 0 else "T* "
            content_lines.append(f"{prefix}({safe}) Tj")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("latin-1", errors="replace")
        pages.append(stream)

    n_pages = len(pages)
    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(f"<< /Type /Pages /Kids [{' '.join(str(3 + i * 2 + 1) + ' 0 R' for i in range(n_pages))}] /Count {n_pages} >>".encode())
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for i, chunk in enumerate(pages):
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                    f"/Resources << /Font << /F1 3 0 R >> >> /Contents {4 + i * 2} 0 R >>".encode())
        objs.append(b"<< /Length " + str(len(chunk)).encode() + b" >>\nstream\n"
                    + chunk + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    count = len(objs) + 1
    out += f"xref\n0 {count}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {count} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF").encode()
    return bytes(out).decode("latin-1")





def write_reports(result: dict, output_dir: str, formats: list) -> list:
    """Write report files; returns list of written paths. Unsupported
    formats are surfaced on the result instead of being silently dropped."""
    os.makedirs(output_dir, exist_ok=True)
    stem = f"omnisec-report-{time.strftime('%Y%m%d-%H%M%S')}"
    written = []
    unsupported = []
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
        elif fmt == "junit":
            content = junit_xml(result)
        elif fmt == "attack_nav":
            content = attack_navigator(result)
        elif fmt == "pdf":
            content = pdf_minimal(result)
        else:
            if fmt not in unsupported:
                unsupported.append(fmt)
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(path)
    if unsupported:
        result["unsupported_formats"] = unsupported
        result["supported_formats"] = SUPPORTED_FORMATS
    return written
