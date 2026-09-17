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


if __name__ == "__main__":
    unittest.main()
