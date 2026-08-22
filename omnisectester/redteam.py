"""Red-team kill-chain simulation (deterministic, non-destructive).

Runs the web agent across the 12-phase chain, attaches MITRE-mapped
phases, compliance controls, and an SHA-256 custody manifest.
Requires --authorization like every real engagement gate.
"""

from . import agent, compliance, evidence, killchain


def run_redteam(target: str, rate_limit: float = 4.0, max_pages: int = 25,
                fail_on: str = "high") -> dict:
    result = agent.run_agent(target, rate_limit=rate_limit,
                             max_pages=max_pages)
    result["command"] = "redteam"
    result["kill_chain"] = killchain.build_chain(result)
    compliance.attach(result)
    evidence.attach(result)

    evidenced = [p for p in result["kill_chain"] if p["status"] == "evidenced"]
    result["summary"] = {
        "objectives_total": len(result["kill_chain"]),
        "objectives_evidenced": len(evidenced),
        "phases": [(p["name"], p["finding_count"]) for p in result["kill_chain"]],
        "mitre_covered": sorted({t for p in evidenced
                                 for t in [p["mitre"]]}),
    }
    return result
