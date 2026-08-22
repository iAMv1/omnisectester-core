"""APK scanner tests: build a synthetic APK in-memory (zipfile)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omnisectester import apk_scan  # noqa: E402


def make_apk(path, manifest_bytes=None, signed=True):
    import zipfile
    manifest = manifest_bytes or (
        b"\x03\x00" + "android.permission.CAMERA".encode("utf-16-le")
        + b"\x00\x00" + "android:debuggable".encode("utf-16-le")
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n035")
        if signed:
            zf.writestr("META-INF/CERT.RSA", b"---sign---")


class TestApkScan(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _scan(self, **kw):
        path = Path(self.root) / "app.apk"
        make_apk(str(path), **kw)
        return apk_scan.run_apk_scan(str(path)), str(path)

    def test_dangerous_permission_detected(self):
        result, _ = self._scan()
        m1 = [f for f in result["findings"] if f["id"] == "M001"]
        self.assertTrue(m1 and "CAMERA" in m1[0]["title"])

    def test_debuggable_detected(self):
        result, _ = self._scan()
        self.assertTrue([f for f in result["findings"] if f["id"] == "M002"])

    def test_unsigned_apk_flagged(self):
        result, _ = self._scan(signed=False)
        self.assertTrue([f for f in result["findings"] if f["id"] == "M004"])

    def test_signed_apk_no_signature_finding(self):
        result, _ = self._scan()
        self.assertFalse([f for f in result["findings"] if f["id"] == "M004"])

    def test_not_a_zip_fails_gracefully(self):
        bad = Path(self.root) / "bad.apk"
        bad.write_bytes(b"MZ not a zip at all")
        result = apk_scan.run_apk_scan(str(bad))
        self.assertFalse(result["ok"])
        self.assertIn("not a readable", result["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
