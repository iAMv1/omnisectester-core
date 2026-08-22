"""Cloud config auditor tests: synthetic .tf / k8s / credentials fixtures."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omnisectester import cloud_scan  # noqa: E402


class TestCloudScan(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rel, content):
        p = Path(self.root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return str(p)

    def test_public_s3_acl(self):
        self._write("main.tf",
                    'resource "aws_s3_bucket" "logs" {\n  acl = "public-read"\n}')
        result = cloud_scan.run_cloud_scan(self.root)
        self.assertTrue([f for f in result["findings"] if f["id"] == "C001"])

    def test_open_sg_port_22(self):
        self._write("sg.tf", (
            'resource "aws_security_group" "web" {\n'
            '  ingress {\n    from_port = 22\n    to_port = 22\n'
            '    cidr_blocks = "0.0.0.0/0"\n  }\n}'))
        result = cloud_scan.run_cloud_scan(self.root)
        self.assertTrue([f for f in result["findings"] if f["id"] == "C002"])

    def test_privileged_pod(self):
        self._write("pod.yaml", (
            "apiVersion: apps/v1\nkind: Deployment\n"
            "spec:\n  containers:\n  - securityContext:\n"
            "      privileged: true\n"))
        result = cloud_scan.run_cloud_scan(self.root)
        self.assertTrue([f for f in result["findings"] if f["id"] == "C004"])

    def test_clean_tf_zero_findings(self):
        self._write("ok.tf", (
            'resource "aws_s3_bucket" "safe" {\n  acl = "private"\n}\n'))
        result = cloud_scan.run_cloud_scan(self.root)
        self.assertEqual(result["stats"]["total"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
