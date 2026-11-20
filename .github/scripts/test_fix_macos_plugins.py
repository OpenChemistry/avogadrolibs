"""Exercise packaging fixups without requiring macOS or Mach-O binaries."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("fix-macos-plugins.sh")


class FixMacPluginsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / "prefix with spaces"
        self.prefix.mkdir()
        tools = self.root / "tools"
        tools.mkdir()
        self.log = self.root / "calls.jsonl"
        self.env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}",
                        FIXUP_LOG=str(self.log))
        for name in ("otool", "install_name_tool"):
            tool = tools / name
            tool.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['FIXUP_LOG'], 'a') as log:
    log.write(json.dumps([name] + sys.argv[1:]) + '\\n')
if os.environ.get('FAIL_TOOL') == name:
    sys.exit(9)
if name == 'otool':
    print(sys.argv[-1] + ':')
    print('\\t/Users/runner/work/project/build/prefix/lib/libexample.1.dylib (compatibility version 1.0.0, current version 1.0.0)')
    print('\\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)')
''')
            tool.chmod(0o755)

    def add_binary(self, name):
        path = self.prefix / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()

    def run_fixup(self):
        return subprocess.run(["bash", str(SCRIPT), str(self.prefix)],
                              env=self.env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_no_optional_dependencies(self):
        self.assertEqual(self.run_fixup().returncode, 0)
        self.assertFalse(self.log.exists())

    def test_helper_without_openbabel(self):
        self.add_binary("bin/genXrdPattern")
        self.assertEqual(self.run_fixup().returncode, 0)
        self.assertEqual(self.calls()[-1], [
            "install_name_tool", "-change",
            "/Users/runner/work/project/build/prefix/lib/libexample.1.dylib",
            "@executable_path/../Frameworks/libexample.1.dylib",
            "bin/genXrdPattern"])

    def test_flat_and_versioned_plugins(self):
        binaries = ["lib/openbabel/format.so", "lib/openbabel/3.1.0/format.so",
                    "lib/libopenbabel.7.dylib", "lib/libinchi.1.dylib"]
        for name in binaries:
            self.add_binary(name)
        self.assertEqual(self.run_fixup().returncode, 0)
        changes = [call for call in self.calls() if call[0] == "install_name_tool"]
        self.assertCountEqual([call[-1] for call in changes], binaries)

    def test_tool_errors_propagate(self):
        self.add_binary("bin/genXrdPattern")
        for tool in ("otool", "install_name_tool"):
            with self.subTest(tool=tool):
                self.env["FAIL_TOOL"] = tool
                self.assertEqual(self.run_fixup().returncode, 9)


if __name__ == "__main__":
    unittest.main()
