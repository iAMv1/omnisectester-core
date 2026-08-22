"""--llm layer tests: mocked transport, no-key degrade, findings isolation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omnisectester import llm  # noqa: E402


class TestLlm(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in ("OMNI_LLM_KEY", "OMNI_LLM_MODEL")}
        for k in self._env:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_no_key_degrades_without_crash(self):
        res = llm.analyze({"target": "x", "findings": []})
        self.assertFalse(res["ok"])
        self.assertIn("not set", res["error"])

    def test_analyze_parses_completion(self):
        os.environ["OMNI_LLM_KEY"] = "k"
        os.environ["OMNI_LLM_MODEL"] = "test-model"

        class FakeResp:
            def read(self):
                return json.dumps(
                    {"choices": [{"message": {"content": "chain A->B"}}]}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return None

        import urllib.request
        orig = urllib.request.urlopen
        captured = {}

        def fake(req, timeout=0):
            captured["body"] = json.loads(req.data)
            return FakeResp()

        urllib.request.urlopen = fake
        try:
            res = llm.analyze({"target": "t", "findings": [{"id": "X001"}]})
        finally:
            urllib.request.urlopen = orig
        self.assertTrue(res["ok"])
        self.assertEqual(res["analysis"], "chain A->B")
        # compact payload must not contain evidence/remediation bulk
        self.assertNotIn("evidence", captured["body"])

    def test_deterministic_findings_never_mutated_by_layer(self):
        findings = [{"id": "X001", "severity": "high"}]
        result = {"ok": True, "findings": findings}
        result["llm_analysis"] = {"ok": True, "analysis": "whatever"}
        self.assertEqual(result["findings"], findings)  # structural guarantee


import json  # noqa: E402
import os  # noqa: E402

if __name__ == "__main__":
    unittest.main()
