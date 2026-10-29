import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

from portable_fleet.core import Refusal
from portable_fleet.family import OwnedFamily
from portable_fleet.native_io import NativeFile


@unittest.skipUnless(os.name == "nt", "Native Windows handle inheritance")
class NativeStdioTests(unittest.TestCase):
    def test_exact_stdout_handle_and_owned_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handles = [NativeFile("NUL", nul=True), NativeFile(root / "stdout", output=True), NativeFile(root / "stderr", output=True)]
            family = None
            try:
                family = OwnedFamily([sys.executable, "-B", "-c", "import os;os.write(1,b'PF_NATIVE_STDIO_OK')"], root,
                                     dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), str(uuid.uuid4()),
                                     stdio=tuple(handle.handle for handle in handles))
                self.assertFalse(family.policy()["owner_handle_inheritable"])
                family.resume()
                self.assertEqual(family.api.WaitForSingleObject(family.process, 5000), 0)
                self.assertEqual(family.stop(family.scope, 3)["accounting"]["active"], 0)
            finally:
                if family:
                    family.close()
                for handle in reversed(handles):
                    handle.close()
            self.assertEqual((root / "stdout").read_bytes(), b"PF_NATIVE_STDIO_OK")
            self.assertEqual((root / "stderr").read_bytes(), b"")

    def test_unknown_console_mode_creates_nothing(self):
        with self.assertRaises(Refusal):
            OwnedFamily([sys.executable], Path.cwd(), {}, str(uuid.uuid4()), console_mode="implicit")


if __name__ == "__main__":
    unittest.main()
