"""False-positive regression tests.

Each test pins one measured FP class (Juice Shop benchmark, 2026-08):
  - SPA catch-all shells reported as sensitive-path exposure
  - XSS markers echoed inside inline <script> hydration blobs
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_server import FixtureServer  # noqa: E402

from omnisectester import httpc  # noqa: E402
from omnisectester.scanner import check_xss_reflected, _reflection_confirmed  # noqa: E402


class TestReflectionFP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._srv = FixtureServer()
        cls.base = cls._srv.__enter__().url

    @classmethod
    def tearDownClass(cls):
        cls._srv.__exit__(None, None, None)

    def test_hydration_echo_not_flagged(self):
        """/spa echoes q verbatim inside a script JSON blob - no finding."""
        found = check_xss_reflected(f"{self.base}/spa", httpc.RateLimiter(100))
        self.assertEqual(found, [],
                         "hydration-context reflection must not be XSS-flagged")

    def test_true_reflection_still_flagged(self):
        """Homepage echoes q into markup - finding must still fire."""
        found = check_xss_reflected(self.base, httpc.RateLimiter(100))
        self.assertTrue(any(f["id"] == "X001" for f in found),
                        "genuine markup reflection must keep firing")

    def test_confirmed_semantics(self):
        body_tp = "<html>x<script>omni_probe()</script>y</html>"
        body_fp = ("<html><script>window.S={\"q\":\"<script>"
                   "omni_probe()</script>\"};</script></html>")
        self.assertTrue(_reflection_confirmed(body_tp, "omni_probe"))
        self.assertFalse(_reflection_confirmed(body_fp, "omni_probe"))

    def test_json_content_type_not_flagged(self):
        """httpbin /post class: payload inside JSON body is inert data."""
        body = "{\"form\": {\"custname\": \"<script>omni_probe()</script>\"}}"
        self.assertTrue("omni_probe" in body)  # sanity: marker present
        self.assertFalse(_reflection_confirmed(body, "omni_probe",
                                               "application/json"))
        self.assertFalse(_reflection_confirmed(body, "omni_probe",
                                               "text/plain"))
        self.assertTrue(_reflection_confirmed(body, "omni_probe", "text/html"))

    def test_json_echo_endpoint_not_flagged(self):
        """/apiecho reflects q into a JSON body - no finding."""
        found = check_xss_reflected(f"{self.base}/apiecho",
                                    httpc.RateLimiter(100))
        self.assertEqual(found, [],
                         "JSON-context reflection must not be XSS-flagged")


if __name__ == "__main__":
    unittest.main()
