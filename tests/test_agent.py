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

    def test_post_form_audit_and_reflection(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=80)
        ids = [f["id"] for f in result["findings"]]
        self.assertIn("F001", ids, "missing-CSRF finding absent")
        x2 = [f for f in result["findings"] if f["id"] == "X002"]
        self.assertTrue(x2, "POST reflection probe did not fire")
        self.assertIn("curl -s -X POST", x2[0]["poc"])

    def test_auth_headers_reach_target(self):
        from omnisectester import httpc
        httpc.set_auth("bearer", "tok123")
        try:
            resp = httpc.request(self.fix.url + "/authecho")
            self.assertIn("Bearer tok123", resp.get("body", ""),
                          "auth header did not reach the target")
        finally:
            httpc.set_auth("none")
        resp = httpc.request(self.fix.url + "/authecho")
        self.assertNotIn("Bearer tok123", resp.get("body", ""), "auth not cleared")

    def test_crawler_scope_exclude_and_subdomains(self):
        surface = crawler.crawl(self.fix.url, max_pages=10, rate_limit=50,
                                exclude_patterns=[r"/about"])
        paths = " ".join(p["url"] for p in surface["pages"])
        self.assertNotIn("/about", paths, "excluded path was crawled")
        self.assertIn("/search", paths)
        s2 = crawler.crawl(self.fix.url, max_pages=10, rate_limit=50,
                           include_subdomains=True)
        self.assertGreaterEqual(s2["stats"]["pages_crawled"], 3)

    def test_report_html_contains_poc_block(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=80)
        from omnisectester.report import to_html
        html_out = to_html(result)
        if [f for f in result["findings"] if f.get("poc")]:
            self.assertIn("$ curl", html_out)
            self.assertIn("omni_probe7x", html_out)

    def test_form_login_session_adopted(self):
        from omnisectester import httpc
        httpc.set_auth("none")
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=80,
                                 login_url=self.fix.url + "/setcookie",
                                 login_data="x=1")
        self.assertTrue(result["agent"]["login"]["session_adopted"])
        # session cookie must have authenticated later probes:
        resp = httpc.request(self.fix.url + "/authecho")
        self.assertIn("session=abc123", resp.get("body", ""),
                      "adopted cookie not sent on subsequent requests")

    def test_cookie_flag_findings(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=80)
        ids = {f["id"] for f in result["findings"]}
        for expected in ("C001", "C002", "C003"):
            self.assertIn(expected, ids, f"cookie finding {expected} missing")

    def test_open_redirect_detected_on_discovered_param(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=100)
        r1 = [f for f in result["findings"] if f["id"] == "R001"]
        self.assertTrue(r1, f"open redirect not detected: {result['surface']}")
        self.assertIn("curl -sI", r1[0]["poc"])

    def test_cert_expiry_math(self):
        from omnisectester.scanner import _cert_days_remaining
        days, err = _cert_days_remaining("Mar 12 23:59:59 2099 GMT")
        self.assertIsNone(err)
        self.assertGreater(days, 10000)
        days, err = _cert_days_remaining("garbage-date")
        self.assertIsNone(days)
        self.assertIn("unparseable", err)

    def test_sarif_output_structure(self):
        result = agent.run_agent(self.fix.url, rate_limit=50, budget=80)
        from omnisectester.report import to_sarif
        sarif = json.loads(to_sarif(result))
        self.assertEqual(sarif["version"], "2.1.0")
        runs = sarif["runs"][0]
        self.assertGreaterEqual(len(runs["results"]), 1)
        ids = {r["ruleId"] for r in runs["results"]}
        rule_ids = {r["id"] for r in runs["tool"]["driver"]["rules"]}
        self.assertTrue(ids <= rule_ids, "result references undefined rule")

    def test_budget_is_respected(self):
        tight = agent.run_agent(self.fix.url, rate_limit=50, budget=5)
        self.assertLessEqual(tight["agent"]["requests_used"], 7)  # small slack
        warns = [f for f in tight["findings"] if f["id"] == "W001"]
        self.assertTrue(warns, "budget exhaustion not reported")


class TestOsvBatch(unittest.TestCase):
    def test_batch_mocked_single_roundtrip(self):
        calls = []

        def fake_post(req, timeout=0):
            calls.append(req.full_url)
            payload = json.loads(req.data)
            results = [{"vulns": [{"id": f"OSV-{n}"}]} for n in range(len(payload["queries"]))]
            body = json.dumps({"results": results}).encode()

            class R:
                def read(self):
                    return body

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return None
            return R()

        import urllib.request
        orig = urllib.request.urlopen
        urllib.request.urlopen = fake_post
        try:
            comps = [{"name": f"p{i}", "version": "1.0", "bom-ref": f"r{i}",
                      "purl": f"pkg:npm/p{i}@1.0"} for i in range(5)]
            vulns, errors = osv.enrich_components(comps, "npm", batch=True)
            self.assertEqual(errors, [])
            self.assertGreaterEqual(len(vulns), 5)
            self.assertEqual(len(calls), 1, "batch should be ONE request")
        finally:
            urllib.request.urlopen = orig


class TestOsv(unittest.TestCase):
    def test_enrich_uses_mocked_response(self):
        fake = [{"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2023-1111"],
                 "summary": "xss in widget"}]
        orig = osv.query_package
        osv.query_package = lambda n, v, e, timeout=8: (fake, None)
        try:
            comps = [{"name": "widget", "version": "1.0.0", "bom-ref": "r1",
                      "purl": "pkg:npm/widget@1.0.0"}]
            vulns, errors = osv.enrich_components(comps, "npm", batch=False)
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
            vulns, errors = osv.enrich_components(comps, "npm", batch=False)
            self.assertEqual(vulns, [])
            self.assertIn("network down", errors[0])
        finally:
            osv.query_package = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)

