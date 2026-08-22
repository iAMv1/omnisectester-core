"""Post-exploitation assessment tests (evidence -> ATT&CK mapping)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_server import FixtureServer  # noqa: E402
from omnisectester import agent  # noqa: E402


class TestPostExploit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()
        cls.result = agent.run_agent(cls.fix.url, rate_limit=50, budget=120)

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def test_internal_hosts_harvested_from_bodies(self):
        hosts = self.result.get("internal_hosts", [])
        self.assertIn("10.0.0.5", hosts, "private IP not harvested from /about")
        self.assertTrue(any("internal" in h or h == "10.0.0.5" for h in hosts))

    def test_env_finding_maps_to_credential_access(self):
        p1 = [f for f in self.result["findings"] if f["id"] == "P001"]
        self.assertTrue(p1)  # precondition: exposed .env found

    def test_postex_module_maps_evidence(self):
        from omnisectester import postex
        fake = {"ok": True,
                "findings": [{"id": "P001", "severity": "critical"}],
                "surface": {"probe_targets": [{"path": "/x", "param": "id"}]},
                "internal_hosts": ["192.168.1.10"]}
        assessment = postex.analyze(fake)
        techniques = {r["technique"] for r in assessment["mitre_rows"]}
        self.assertIn("T1552", techniques)
        self.assertIn("T1046", techniques)
        self.assertGreater(assessment["summary"]["techniques_applicable"], 0)

    def test_assessment_is_planning_artifact_only(self):
        from omnisectester import postex
        res = postex.analyze({"ok": True, "findings": [],
                              "surface": {}, "internal_hosts": []})
        self.assertEqual(res["summary"]["techniques_applicable"], 0)
        self.assertIn("PLANNING", res["assessment"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
