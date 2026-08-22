"""AI/LLM scanner tests: vulnerable chatbot fixture, deterministic verdicts."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_server import FixtureServer  # noqa: E402
from omnisectester import llm_scan  # noqa: E402


class TestLlmScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()
        cls.result = llm_scan.run_llm_scan(cls.fix.url + "/chat",
                                           rate_limit=50, budget=20)

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def test_system_prompt_leak_detected(self):
        pi1 = [f for f in self.result["findings"] if f["id"] == "PI001"]
        self.assertTrue(pi1, "system-prompt leak not detected")
        self.assertIn("curl -s -X POST", pi1[0]["poc"])
        self.assertEqual(pi1[0]["owasp_llm"], "LLM01")

    def test_roleplay_escape_detected(self):
        pi3 = [f for f in self.result["findings"] if f["id"] == "PI003"]
        self.assertTrue(pi3, "DAN-style escape not detected")

    def test_secret_fishing_detected(self):
        pi5 = [f for f in self.result["findings"] if f["id"] == "PI005"]
        self.assertTrue(pi5, "secret fishing not detected")
        self.assertIn("sk-", "".join(pi5[0]["evidence"]))

    def test_findings_sorted_and_shaped(self):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sevs = [order[f["severity"]] for f in self.result["findings"]]
        self.assertEqual(sevs, sorted(sevs))
        for f in self.result["findings"]:
            for key in ("id", "title", "severity", "evidence", "remediation",
                        "cwe", "poc", "family"):
                self.assertIn(key, f)

    def test_budget_respected(self):
        tight = llm_scan.run_llm_scan(self.fix.url + "/chat",
                                      rate_limit=50, budget=3)
        self.assertLessEqual(tight["stats"]["requests"], 3)
        warns = [f for f in tight["findings"] if f["id"] == "W001"]
        self.assertTrue(warns, "budget exhaustion not reported")


if __name__ == "__main__":
    unittest.main(verbosity=2)
