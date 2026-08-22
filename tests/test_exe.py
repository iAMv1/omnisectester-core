"""Desktop PE scanner tests: synthetic binaries built in-memory."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from omnisectester import exe_scan  # noqa: E402


def make_pe(extra=b""):
    """Return a minimal MZ+PE blob with a plausible timestamp."""
    dos = bytearray(b"MZ" + b"\x00" * 62)   # 64-byte DOS header
    pe_off = 64
    struct.pack_into("<I", dos, 0x3C, pe_off)
    pe = (b"PE\x00\x00"
          + struct.pack("<HHI", 0x8664, 0, 1700000000)  # Machine/Sections/TS
          + b"\x00" * 64)
    return bytes(dos) + pe + extra


class TestExeScan(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _scan(self, blob):
        path = Path(self.root) / "sample.exe"
        path.write_bytes(blob)
        return exe_scan.run_exe_scan(str(path))

    def test_valid_pe_no_false_e001(self):
        result = self._scan(make_pe(b"\x00" * 32))
        ids = {f["id"] for f in result["findings"]}
        self.assertNotIn("E001", ids)
        self.assertEqual(result["meta"]["compile_year"], 2023)

    def test_non_pe_flagged(self):
        result = self._scan(b"hello world not an exe")
        self.assertTrue([f for f in result["findings"] if f["id"] == "E001"])

    def test_injection_api_cluster_detected(self):
        blob = (b"\x00" * 16 + b"WriteProcessMemory\x00"
                + b"CreateRemoteThreadEx\x00" + b"\x00" * 16)
        result = self._scan(make_pe(blob))
        e3 = [f for f in result["findings"] if f["id"] == "E003"]
        self.assertTrue(e3)
        self.assertIn("WriteProcessMemory", "".join(e3[0]["evidence"]))

    def test_single_suspicious_api_not_cluster(self):
        blob = b"\x00" * 16 + b"WriteProcessMemory\x00" + b"\x00" * 16
        result = self._scan(make_pe(blob))
        self.assertFalse([f for f in result["findings"] if f["id"] == "E003"])

    def test_embedded_url_reported(self):
        blob = b"\x00" * 8 + b"https://telemetry.example.com/beacon\x00" + b"\x00" * 8
        result = self._scan(make_pe(blob))
        e4 = [f for f in result["findings"] if f["id"] == "E004"]
        self.assertTrue(e4 and any("telemetry.example.com" in u
                                   for u in e4[0]["urls"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
