import importlib.util
import sys
from datetime import datetime
from pathlib import Path
import tempfile
import unittest


def load_analyzer_module() -> object:
    root = Path(__file__).resolve().parents[1]
    mod_path = root / "analyzer.py"
    spec = importlib.util.spec_from_file_location("analyzer", str(mod_path))
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # Ensure the module is present in sys.modules so decorators like @dataclass
    # that inspect module globals work correctly during dynamic import.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analyzer = load_analyzer_module()

    def test_parse_line_valid(self):
        line = "Jan 10 12:34:56 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2"
        fa = self.analyzer.parse_line(line, year=2025)
        self.assertIsNotNone(fa)
        self.assertEqual(fa.ip, "203.0.113.5")
        self.assertEqual(fa.user, "root")
        self.assertEqual(fa.host, "myhost")
        self.assertEqual(fa.timestamp, datetime(2025, 1, 10, 12, 34, 56))

    def test_parse_line_invalid(self):
        line = "Jan 10 12:43:00 myhost CRON[999]: (root) CMD (something)"
        self.assertIsNone(self.analyzer.parse_line(line, year=2025))

    def test_parse_log_file_and_summarize(self):
        sample = (
            "Jan 10 12:34:56 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2\n"
            "Jan 10 12:35:01 myhost sshd[2345]: Failed password for invalid user admin from 198.51.100.7 port 51111 ssh2\n"
        )
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tf:
            tf.write(sample)
            tf.flush()
            path = tf.name

        attempts = self.analyzer.parse_log_file(path, year=2025)
        by_ip, by_user = self.analyzer.summarize_attempts(attempts)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(by_ip["203.0.113.5"], 1)
        self.assertEqual(by_user["admin"], 1)

    def test_detect_bursts(self):
        FailedAttempt = self.analyzer.FailedAttempt
        times = [
            datetime(2025, 1, 10, 12, 0, 0),
            datetime(2025, 1, 10, 12, 0, 30),
            datetime(2025, 1, 10, 12, 1, 0),
            datetime(2025, 1, 10, 12, 6, 0),
        ]
        attempts = [FailedAttempt(timestamp=t, ip="1.2.3.4", user="u", host="h", raw_line="") for t in times]
        bursts = self.analyzer.detect_bursts(attempts, min_failures=3, window_minutes=2)
        self.assertIn("1.2.3.4", bursts)
        self.assertEqual(bursts["1.2.3.4"], 3)


if __name__ == "__main__":
    unittest.main()
