"""Website deepening probe tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_server import FixtureServer  # noqa: E402
from omnisectester import agent  # noqa: E402


class TestWebDeep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()
        cls.result = agent.run_agent(cls.fix.url, rate_limit=50, budget=150)

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def test_security_txt_missing_reported(self):
        w2 = [f for f in self.result["findings"] if f["id"] == "W002"]
        self.assertTrue(w2, "missing security.txt not reported")

    def test_no_false_trace_finding_on_fixture(self):
        # stdlib http.server rejects TRACE with 501 - must NOT be flagged
        h8 = [f for f in self.result["findings"] if f["id"] == "H008"]
        self.assertFalse(h8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
