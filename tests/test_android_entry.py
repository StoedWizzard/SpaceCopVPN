"""The Android entry point (Chaquopy) must report through a Java-style logger
object and fail loudly when no node is reachable."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from spacecop.tun import android  # noqa: E402


class JavaLikeLogger:
    """Mimics the Kotlin PyLogger: an object with a log(String) method."""
    def __init__(self):
        self.lines = []

    def log(self, line):
        self.lines.append(line)


class TestAndroidEntry(unittest.TestCase):
    def test_logger_object_and_callable(self):
        j = JavaLikeLogger()
        android._call_log(j, "a")
        got = []
        android._call_log(got.append, "b")
        android._call_log(object(), "c")  # neither: ignored, never raises
        self.assertEqual(j.lines, ["a"])
        self.assertEqual(got, ["b"])

    def test_run_engine_without_nodes_raises_and_logs(self):
        j = JavaLikeLogger()
        r, w = os.pipe()
        try:
            with self.assertRaises(RuntimeError):
                android.run_engine(r, ["spacecop://not-a-uri"], "1.1.1.1:53", False, j)
        finally:
            os.close(r)
            os.close(w)
        self.assertTrue(any("not-a-uri" in line for line in j.lines), j.lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
