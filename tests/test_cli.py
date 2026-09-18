import subprocess
import sys
import unittest


class CLITests(unittest.TestCase):
    def test_help(self):
        cp = subprocess.run([sys.executable, "-m", "remix", "--help"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("analyze", cp.stdout)
        self.assertIn("trace", cp.stdout)
        self.assertIn("fn", cp.stdout)
        self.assertIn("refs", cp.stdout)
        self.assertIn("symbols", cp.stdout)
        self.assertIn("strings", cp.stdout)
        self.assertIn("jni", cp.stdout)
        self.assertIn("path", cp.stdout)


if __name__ == "__main__":
    unittest.main()
