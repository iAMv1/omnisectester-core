"""Unit tests for --suppress (false-positive suppression by rule id)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omnisectester.cli import _apply_suppress  # noqa: E402


class TestSuppress(unittest.TestCase):
    def test_drops_listed_ids_and_recomputes_stats(self):
        result = {
            "ok": True,
            "findings": [
                {"id": "H001", "severity": "high"},
                {"id": "P001", "severity": "critical"},
            ],
            "stats": {"requests": 5, "total": 2, "critical": 1, "high": 1},
        }
        _apply_suppress(result, "P001")
        self.assertEqual([f["id"] for f in result["findings"]], ["H001"])
        self.assertEqual(result["stats"]["total"], 1)
        self.assertEqual(result["stats"]["critical"], 0)
        self.assertEqual(result["stats"]["high"], 1)
        self.assertEqual(result["suppressed"],
                         {"ids": ["P001"], "count": 1})

    def test_multiple_ids_and_whitespace(self):
        result = {
            "ok": True,
            "findings": [
                {"id": "H001", "severity": "high"},
                {"id": "P002", "severity": "medium"},
                {"id": "I002", "severity": "info"},
            ],
            "stats": {"total": 3},
        }
        _apply_suppress(result, " P002 , I002 ")
        self.assertEqual([f["id"] for f in result["findings"]], ["H001"])
        self.assertEqual(result["suppressed"]["count"], 2)

    def test_noop_when_no_match(self):
        result = {"ok": True,
                  "findings": [{"id": "X001", "severity": "low"}],
                  "stats": {"total": 1}}
        _apply_suppress(result, "P001,H002")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["suppressed"]["count"], 0)

    def test_skipped_for_failed_scans(self):
        result = {"ok": False, "error": "boom", "findings": []}
        _apply_suppress(result, "X001")
        self.assertNotIn("suppressed", result)

    def test_empty_spec_is_noop(self):
        result = {"ok": True, "findings": [{"id": "X001", "severity": "low"}],
                  "stats": {"total": 1}}
        _apply_suppress(result, None)
        _apply_suppress(result, "")
        self.assertEqual(len(result["findings"]), 1)
        self.assertNotIn("suppressed", result)


if __name__ == "__main__":
    unittest.main()
