"""Bridge-contract + scanner tests. Stdlib unittest only; local fixture, no network."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_server import FixtureServer  # noqa: E402
from omnisectester import cli  # noqa: E402
from omnisectester.scanner import scan_web  # noqa: E402


class TestScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def test_scan_finds_missing_headers(self):
        result = scan_web(self.fix.url, rate_limit=50)
        self.assertTrue(result["ok"])
        ids = [f["id"] for f in result["findings"]]
        for expected in ("H001", "H002", "H003", "H004"):
            self.assertIn(expected, ids, f"missing header finding {expected}")

    def test_scan_finds_env_exposure_critical(self):
        result = scan_web(self.fix.url, rate_limit=50)
        crit = [f for f in result["findings"] if f["severity"] == "critical"]
        self.assertTrue(any(f["id"] == "P001" and ".env" in f["evidence"] for f in crit),
                        f"critical .env finding missing: {crit}")

    def test_scan_detects_reflected_xss_marker(self):
        result = scan_web(self.fix.url, rate_limit=50)
        self.assertTrue(any(f["id"] == "X001" for f in result["findings"]),
                        "reflected-XSS probe did not fire")

    def test_findings_sorted_and_shaped(self):
        result = scan_web(self.fix.url, rate_limit=50)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sevs = [order[f["severity"]] for f in result["findings"]]
        self.assertEqual(sevs, sorted(sevs), "findings not severity-sorted")
        for f in result["findings"]:
            self.assertEqual(set(f), {"id", "title", "severity", "evidence", "remediation", "cwe"})

    def test_rate_limiter_spacing_measured(self):
        import time
        from omnisectester.httpc import RateLimiter
        lim = RateLimiter(requests_per_second=20)
        t0 = time.monotonic()
        for _ in range(5):
            lim.wait()
        elapsed = time.monotonic() - t0
        self.assertGreaterEqual(elapsed, 0.15, "rate limiter not spacing requests")


class TestCliContract(unittest.TestCase):
    """Exactly what python-wrapper.js does: spawn cli.py <cmd> --json flags."""

    @classmethod
    def setUpClass(cls):
        cls.fix = FixtureServer()
        cls.fix.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.fix.__exit__(None, None, None)

    def _run(self, argv):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        code = 0
        with redirect_stdout(buf):
            code = cli.main(argv)
        return code, json.loads(buf.getvalue())

    def test_scan_web_json_shape(self):
        code, out = self._run(["scan", "--json", "--platform", "web",
                               "--target", self.fix.url, "--rate-limit", "50"])
        self.assertEqual(code, 0)
        self.assertTrue(out["ok"])
        self.assertGreater(out["stats"]["total"], 3)

    def test_fail_on_gate_exit_codes(self):
        # fixture always yields criticals -> --fail-on critical must exit 2
        code, out = self._run(["scan", "--json", "--platform", "web",
                               "--target", self.fix.url, "--rate-limit", "50",
                               "--fail-on", "critical"])
        self.assertEqual(code, 2, "critical findings should produce exit 2")
        # without the flag: informational success
        code, out = self._run(["scan", "--json", "--platform", "web",
                               "--target", self.fix.url, "--rate-limit", "50"])
        self.assertEqual(code, 0)

    def test_unknown_command_exits_1_with_json(self):
        code, out = self._run(["nope", "--json"])
        self.assertEqual(code, 1)
        self.assertFalse(out["ok"])

    def test_threat_model_stride_rows(self):
        code, out = self._run(["threat-model", "--json", self.fix.url])
        self.assertEqual(code, 0)
        self.assertEqual(len(out["threats"]), 6)
        cats = {t["stride"] for t in out["threats"]}
        self.assertEqual(cats, set("STRIDE"))

    def test_sbom_cyclonedx_from_requirements(self):
        req = Path(self.__class__.__module__ + "_tmp")  # placeholder no-op
        tmpdir = Path(__file__).parent / "_sbomfix"
        tmpdir.mkdir(exist_ok=True)
        (tmpdir / "requirements.txt").write_text("flask==3.0.0\nrequests>=2.31\n# comment\n\n")
        try:
            code, out = self._run(["sbom", "--json", str(tmpdir)])
            self.assertEqual(code, 0)
            names = {c["name"] for c in out["components"]}
            self.assertIn("flask", names)
            self.assertIn("requests", names)
            for comp in out["components"]:
                self.assertTrue(comp["purl"].startswith("pkg:pypi/"))
        finally:
            (tmpdir / "requirements.txt").unlink()
            tmpdir.rmdir()

    def test_report_writes_files_from_result_json(self):
        import tempfile
        scan_code, scan_out = self._run(["scan", "--json", "--platform", "web",
                                         "--target", self.fix.url, "--rate-limit", "50"])
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "result.json"
            src.write_text(json.dumps(scan_out))
            outdir = Path(td) / "reports"
            code, out = self._run(["report", "--json", str(src),
                                   "--output", str(outdir), "--format", "md,html,json"])
            self.assertEqual(code, 0)
            written_exts = {Path(p).suffix.lstrip(".") for p in out["files"]}
            self.assertEqual(written_exts, {"md", "html", "json"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
