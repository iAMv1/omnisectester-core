"""v0.2 agent tests: discovery, PoC generation, observation-driven TM, OSV mock."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_server import FixtureServer  # noqa: E402
from omnisectester import agent, crawler, osv  # noqa: E402


class TestCrawler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def test_discovers_linked_pages(self):
        surface = crawler.crawl(self.fix.url, max_pages=10, rate_limit=50)
        paths = {p["url"].rsplit("/", 1)[-1] for p in surface["pages"]}
        self.assertIn("search", " ".join(paths))
        self.assertIn("about", " ".join(paths))
        self.assertGreaterEqual(surface["stats"]["pages_crawled"], 3)

    def test_discovers_form_param_without_hardcoding(self):
        surface = crawler.crawl(self.fix.url, max_pages=10, rate_limit=50)
        targets = {(t["path"], t["param"]) for t in surface["probe_targets"]}
        self.assertIn(("/search", "q"), targets,
                      f"agent failed to discover /search?q= from form: {targets}")


class TestAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def test_agent_finds_xss_on_discovered_page_with_poc(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=60)
        x = [f for f in result["findings"] if f["id"] == "X001"]
        self.assertTrue(x, f"no reflection finding on discovered page: "
                           f"{result['surface']}")
        self.assertIn("curl -s", x[0].get("poc", ""), "missing executable PoC")
        self.assertIn("/search?", x[0]["url"], "probe hit wrong endpoint")

    def test_threat_model_ran_first_and_is_observation_driven(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=60)
        tm = result["threat_model"]
        self.assertEqual(tm["threats"][0]["based_on"], "observed surface")
        self.assertGreater(tm["summary"]["high_or_above"], 0)
        # fixture has a form + params -> spoofing/tampering must be high
        rel = {t["category"]: t["relevance"] for t in tm["threats"]}
        self.assertEqual(rel["Spoofing"], "high")

    def test_env_critical_still_found_by_agent(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=60)
        crit = [f for f in result["findings"] if f["severity"] == "critical"]
        self.assertTrue(any(f["id"] == "P001" for f in crit))

    def test_budget_is_respected(self):
        tight = agent.run_agent(self.fix.url, rate_limit=50, budget=5)
        self.assertLessEqual(tight["agent"]["requests_used"], 7)  # small slack
        warns = [f for f in tight["findings"] if f["id"] == "W001"]
        self.assertTrue(warns, "budget exhaustion not reported")


class TestOsv(unittest.TestCase):
    def test_enrich_uses_mocked_response(self):
        fake = [{"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2023-1111"],
                 "summary": "xss in widget"}]
        orig = osv.query_package
        osv.query_package = lambda n, v, e, timeout=8: (fake, None)
        try:
            comps = [{"name": "widget", "version": "1.0.0", "bom-ref": "r1",
                      "purl": "pkg:npm/widget@1.0.0"}]
            vulns, errors = osv.enrich_components(comps, "npm")
            self.assertEqual(len(errors), 0)
            self.assertEqual(vulns[0]["aliases"], ["CVE-2023-1111"])
            self.assertEqual(vulns[0]["affected"][0]["package"], "widget")
        finally:
            osv.query_package = orig

    def test_offline_degrades_gracefully(self):
        orig = osv.query_package
        osv.query_package = lambda n, v, e, timeout=8: ([], "network down")
        try:
            comps = [{"name": "w", "version": "1", "bom-ref": "r",
                      "purl": "pkg:npm/w@1"}]
            vulns, errors = osv.enrich_components(comps, "npm")
            self.assertEqual(vulns, [])
            self.assertIn("network down", errors[0])
        finally:
            osv.query_package = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)
