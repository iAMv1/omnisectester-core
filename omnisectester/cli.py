"""Bridge contract entrypoint.

Invocation (from Node python-wrapper.js):
    cli.py <command> --json [--kebab-flag value ...]

Guarantees:
- Exactly one JSON object printed to stdout on success; nothing else.
- Exit 0 on success, exit 1 on failure (error JSON on stdout too - the
  bridge reads stderr only for crash text).
- Unknown flags are ignored rather than fatal (forward compatibility).
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Works both as a package module (python -m omnisectester.cli) and as a
# plain script path (how the Node bridge spawns us), where relative
# imports fail for lack of package context.
try:
    from . import report as report_mod
    from . import scanner, sbom, threatmodel
    from .scanner import FAIL_ON_RANK, SEVERITY_ORDER
except ImportError:  # pragma: no cover - script-mode branch
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from omnisectester import report as report_mod  # noqa: E402
    from omnisectester import scanner, sbom, threatmodel  # noqa: E402
    from omnisectester.scanner import FAIL_ON_RANK, SEVERITY_ORDER  # noqa: E402


def _emit(obj: dict) -> None:
    json.dump(obj, sys.stdout)
    sys.stdout.write("\n")


def _parse_opts(unknown: list) -> tuple[dict, list]:
    """Turn unknown kebab-case flags into a dict; return leftover positionals."""
    opts = {}
    positionals = []
    i = 0
    while i < len(unknown):
        token = unknown[i]
        if token.startswith("--"):
            key = token[2:].replace("-", "_")
            if i + 1 < len(unknown) and not unknown[i + 1].startswith("--"):
                opts[key] = _coerce(unknown[i + 1])
                i += 2
            else:
                opts[key] = True
                i += 1
        else:
            positionals.append(token)
            i += 1
    return opts, positionals


def _coerce(value: str):
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value


SEVERITIES = ("critical", "high", "medium", "low", "info")


def _apply_suppress(result: dict, spec) -> None:
    """Drop findings whose rule id is listed in `spec` (comma-separated).

    Recomputes stats so gates/reports reflect the reported set, and records
    what was suppressed for auditability. Runs BEFORE compliance/custody
    attachment so evidence hashes match the final finding list.
    """
    if not spec:
        return
    ids = {s.strip() for s in str(spec).split(",") if s.strip()}
    if not ids or not result.get("ok"):
        return
    findings = result.get("findings", [])
    kept = [f for f in findings if f.get("id") not in ids]
    dropped = len(findings) - len(kept)
    if dropped:
        result["findings"] = kept
        stats = result.setdefault("stats", {})
        stats["total"] = len(kept)
        stats.update({s: sum(1 for f in kept if f.get("severity") == s)
                      for s in SEVERITIES})
    result["suppressed"] = {"ids": sorted(ids), "count": dropped}


def cmd_scan(opts: dict) -> dict:
    platform = opts.get("platform", "web")
    target = opts.get("target") or opts.get("_target") or ""
    rate = float(opts.get("rate_limit", 4))
    fmts = opts.get("format")
    output = opts.get("output", "./reports")
    max_pages = int(opts.get("max_pages", 25))
    fail_on = str(opts.get("fail_on", "none"))

    from omnisectester import compliance as _comp
    from omnisectester import evidence as _evd

    if platform in ("web", "api"):
        from omnisectester import agent
        result = agent.run_agent(target, rate_limit=rate,
                                 max_pages=max_pages,
                                 auth_type=str(opts.get("auth", "none")),
                                 auth_token=opts.get("auth_token"),
                                 include_subdomains=bool(
                                     opts.get("include_subdomains")),
                                 exclude_patterns=opts.get("exclude"),
                                 login_url=opts.get("login_url"),
                                 login_data=opts.get("login_data"))
    elif platform == "ai":
        from omnisectester import llm_scan
        result = llm_scan.run_llm_scan(target, rate_limit=rate,
                                       api_key=opts.get("auth_token"))
    elif platform == "extension":
        from omnisectester import ext_scan
        result = ext_scan.run_ext_scan(target)
    elif platform in ("supply-chain", "cicd"):
        from omnisectester import scm_scan
        result = scm_scan.run_scm_scan(target or ".")
    elif platform == "mobile":
        from omnisectester import apk_scan
        result = apk_scan.run_apk_scan(target)
    elif platform == "desktop":
        from omnisectester import exe_scan
        result = exe_scan.run_exe_scan(target)
    elif platform == "cloud":
        from omnisectester import cloud_scan
        result = cloud_scan.run_cloud_scan(target or ".")
    else:
        result = {"command": "scan", "platform": platform, "target": target,
                  "ok": False,
                  "error": (f"engine for platform '{platform}' not yet "
                            f"implemented"),
                  "findings": []}

    _apply_suppress(result, opts.get("suppress"))

    if result.get("ok"):
        # compliance controls + SHA-256 custody on every successful scan
        _comp.attach(result)
        _evd.attach(result)

    result["gate"] = {"fail_on": fail_on,
                      "triggered": _exit_code(result, fail_on) == 2}

    if result.get("ok") and opts.get("llm"):
        try:
            from omnisectester import llm as llm_mod
            result["llm_analysis"] = llm_mod.analyze(result)
        except Exception as exc:  # noqa: BLE001 - never break the scan
            result["llm_analysis"] = {"ok": False, "error": str(exc)}

    if result.get("ok") and fmts and output:
        result["reports"] = report_mod.write_reports(result, output,
                                                     fmts.split(","))

    return result


def cmd_engage(opts: dict) -> dict:
    target = opts.get("target") or opts.get("_target") or ""
    from omnisectester import agent
    scan_result = agent.run_agent(target, rate_limit=float(opts.get("rate_limit", 4)),
                                  max_pages=int(opts.get("max_pages", 25)))
    # threat model already ran first INSIDE the agent; reuse it
    merged = {
        "command": "engage",
        "target": target,
        "ok": scan_result.get("ok", False),
        "scan": {k: v for k, v in scan_result.items() if k != "threat_model"},
        "threat_model": scan_result.get("threat_model"),
        "stats": scan_result.get("stats", {}),
        "findings": scan_result.get("findings", []),
    }
    if opts.get("format"):
        merged["reports"] = report_mod.write_reports(
            merged, opts.get("output", "./reports"), opts["format"].split(","))
    return merged


def cmd_threat_model(opts: dict) -> dict:
    return threatmodel.build_threat_model(
        opts.get("_target") or opts.get("target") or "",
        adversary=(opts.get("adversary") or "APT29").split(","),
        frameworks=(opts.get("frameworks") or "STRIDE").split(","))


def cmd_report(opts: dict) -> dict:
    input_path = opts.get("_target") or opts.get("input") or ""
    with open(input_path, encoding="utf-8") as fh:
        result = json.load(fh)
    files = report_mod.write_reports(result, opts.get("output", "./reports"),
                                     (opts.get("format") or "md,html").split(","))
    return {"command": "report", "ok": True, "files": files}


def cmd_sbom(opts: dict) -> dict:
    root = opts.get("_target") or opts.get("target") or "."
    result = sbom.generate_sbom(root, include_vulns=bool(opts.get("vulns")))
    if opts.get("vulns") and result.get("ok"):
        # real vulnerability matching via OSV.dev (free, keyless)
        from omnisectester import osv
        all_vulns = []
        errors = []
        for eco in ("pypi", "npm"):
            comps = [c for c in result.get("components", [])
                     if f"/{eco}/" in c.get("purl", "")]
            vulns, errs = osv.enrich_components(comps, eco,
                                                timeout=float(opts.get("timeout", 8)))
            all_vulns += vulns
            errors += errs
        result["vulnerabilities"] = all_vulns
        if errors:
            result.setdefault("metadata", {}).setdefault(
                "properties", []).append({"name": "osvErrors", "value": "; ".join(errors[:5])})
        counts = {}
        for v in all_vulns:
            for alias in v["aliases"] or [v["id"]]:
                counts[alias] = 1
        result["stats"] = {"components": len(result.get("components", [])),
                           "vulnerabilities": len(all_vulns)}
    return result


def cmd_continuous(opts: dict) -> dict:
    """Deterministic continuous mode: scan targets, diff finding-IDs against
    the previous run's state file, report only what's NEW."""
    import json as _json

    targets = [t.strip() for t in (opts.get("targets") or "").split(",") if t.strip()]
    if not targets:
        return {"command": "continuous", "ok": False,
                "error": "no targets given (--targets a,b,c)"}

    state_path = os.path.expanduser(
        opts.get("state", "~/.omnisectester/continuous-state.json"))
    fail_on = str(opts.get("fail_on", "none"))
    max_pages = int(opts.get("max_pages", 25))
    rate = float(opts.get("rate_limit", 4))

    from omnisectester import agent

    try:
        with open(state_path, encoding="utf-8") as fh:
            prev_state = _json.load(fh)
    except Exception:  # noqa: BLE001 - missing/corrupt state starts fresh
        prev_state = {}

    results = []
    all_findings = []
    new_total = 0
    requests_used = 0
    for target in targets:
        scan_result = agent.run_agent(target, rate_limit=rate,
                                      max_pages=max_pages)
        requests_used += scan_result.get("stats", {}).get("requests", 0)
        ids = {f"{f['id']}::{f['title']}" for f in scan_result.get("findings", [])}
        prev_ids = set(prev_state.get(target, []))
        fresh = sorted(ids - prev_ids)
        new_total += len(fresh)
        prev_state[target] = sorted(ids)
        results.append({"target": target,
                        "ok": scan_result.get("ok", False),
                        "total": len(ids), "new": len(fresh),
                        "new_ids": fresh[:10]})
        all_findings += scan_result.get("findings", [])

    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as fh:
        _json.dump(prev_state, fh)

    aggregate = {"ok": True, "findings": all_findings}
    return {
        "command": "continuous", "ok": True,
        "results": results,
        "new_findings": new_total,
        "gate": {"fail_on": fail_on,
                 "triggered": _exit_code(aggregate, fail_on) == 2},
        "stats": {"targets": len(targets), "requests": requests_used},
    }


def cmd_postexploit(opts: dict) -> dict:
    """Run the agent on the target, then map evidence to ATT&CK."""
    from omnisectester import agent as agent_mod
    from omnisectester import postex
    target = opts.get("_target") or opts.get("target") or ""
    scan_result = agent_mod.run_agent(
        target, rate_limit=float(opts.get("rate_limit", 4)),
        max_pages=int(opts.get("max_pages", 25)))
    assessment = postex.analyze(scan_result)
    return {"command": "postexploit", "target": target,
            "ok": scan_result.get("ok", False),
            "scan_summary": scan_result.get("stats"),
            "internal_hosts": scan_result.get("internal_hosts", []),
            **assessment}


def cmd_redteam(opts: dict) -> dict:
    target = opts.get("target") or opts.get("_target") or ""
    if not opts.get("authorization"):
        return {"command": "redteam", "ok": False,
                "error": "authorization reference required (--authorization)"}
    from omnisectester import redteam
    result = redteam.run_redteam(target,
                                 rate_limit=float(opts.get("rate_limit", 4)),
                                 max_pages=int(opts.get("max_pages", 25)),
                                 fail_on=str(opts.get("fail_on", "high")))
    result["gate"] = {"fail_on": str(opts.get("fail_on", "high")),
                      "triggered": _exit_code(result,
                                              str(opts.get("fail_on",
                                                           "high"))) == 2}
    return result


def cmd_taxonomy(opts: dict) -> dict:
    from omnisectester import taxonomy
    cats = taxonomy.flat()
    domain = opts.get("domain")
    if domain:
        cats = [c for c in cats if c["domain"] == domain]
    return {"command": "taxonomy", "ok": True,
            "count": len(cats), "categories": cats}


COMMANDS = {
    "scan": cmd_scan,
    "redteam": cmd_redteam,
    "taxonomy": cmd_taxonomy,
    "engage": cmd_engage,
    "threat-model": cmd_threat_model,
    "report": cmd_report,
    "sbom": cmd_sbom,
    "continuous": cmd_continuous,
    "postexploit": cmd_postexploit,
}


def _exit_code(result: dict, fail_on: str = "none") -> int:
    """0 = clean run; 2 = ran fine but findings met the fail-on threshold;
    1 = the scan itself failed."""
    if not result.get("ok"):
        return 1
    if fail_on not in FAIL_ON_RANK or fail_on == "none":
        return 0
    threshold = FAIL_ON_RANK[fail_on]
    worst = 99
    for f in result.get("findings", []):
        rank = SEVERITY_ORDER.get(f["severity"], 4)
        if rank < worst:
            worst = rank
    has_findings = bool(result.get("findings"))
    return 2 if has_findings and worst <= threshold else 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("--help", "-h", "help"):
        usage = ("usage: omnisectester-core <command> [--json] [flags]\n\n"
                 f"commands: {', '.join(sorted(COMMANDS))}\n"
                 "example: omnisectester-core scan web https://example.test "
                 "--rate-limit 2 --fail-on critical")
        print(usage, file=sys.stderr)
        return 1 if not argv else 0
    command = argv[0]
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--json", action="store_true", default=False)
    known, unknown = parser.parse_known_args(argv[1:])

    handler = COMMANDS.get(command)
    if handler is None:
        _emit({"ok": False, "error": f"unknown command '{command}'",
               "available": sorted(COMMANDS)})
        return 1

    opts, positionals = _parse_opts([a for a in unknown])
    if not getattr(known, "json", False):
        pass  # --json is the default and only output mode in v0.1
    if positionals and not opts.get("_target"):
        opts["_target"] = positionals[-1]

    try:
        result = handler(opts)
        if not isinstance(result, dict) or "ok" not in result:
            result = {"ok": True, "result": result}
        exit_code = _exit_code(result, str(opts.get("fail_on", "none")))
        _emit(result)
        return exit_code
    except Exception as exc:  # noqa: BLE001 - bridge expects JSON errors
        _emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 1


if __name__ == "__main__":
    sys.exit(main())
