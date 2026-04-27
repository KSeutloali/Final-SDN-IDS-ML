import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


class BenignTrafficScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.bin_dir = Path(self.temp_dir.name) / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = Path(self.temp_dir.name) / "commands.log"

        for name in ("curl", "ping", "nc", "sleep", "python3"):
            self._write_fake_command(name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_fake_command(self, name):
        path = self.bin_dir / name
        script = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$LOG_PATH"
exit 0
"""
        path.write_text(script)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _run_script(self, *args, **env_overrides):
        repo_root = Path(__file__).resolve().parents[1]
        script_path = repo_root / "traffic" / "benign_traffic.sh"
        env = dict(os.environ)
        env.update(
            {
                "PATH": str(self.bin_dir) + os.pathsep + env.get("PATH", ""),
                "LOG_PATH": str(self.log_path),
            }
        )
        env.update(env_overrides)
        return subprocess.run(
            ["sh", str(script_path)] + list(args),
            text=True,
            capture_output=True,
            cwd=str(repo_root),
            env=env,
            check=False,
        )

    def test_script_preserves_existing_target_and_port_interface(self):
        result = self._run_script("10.0.0.2", "80", SDN_BENIGN_ROUNDS="1")

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        log_text = self.log_path.read_text()
        self.assertIn("ping -c 5 10.0.0.2", log_text)
        self.assertIn("curl -m 4 -s -o /dev/null http://10.0.0.2:80/", log_text)
        self.assertIn("curl -m 4 -s -o /dev/null http://10.0.0.2:80/index.html", log_text)

    def test_script_uses_optional_peer_and_multi_fetch_behavior(self):
        result = self._run_script(
            "10.0.0.5",
            "8080",
            "2",
            SDN_BENIGN_ROUNDS="1",
            SDN_BENIGN_PEER_IP="10.0.0.3",
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        log_text = self.log_path.read_text()
        self.assertIn("ping -c 2 10.0.0.5", log_text)
        self.assertIn("ping -c 1 -W 1 10.0.0.3", log_text)
        self.assertIn("curl -m 4 -s -o /dev/null http://10.0.0.5:8080/favicon.ico", log_text)
        self.assertIn("nc -z -w 1 10.0.0.5 8080", log_text)


if __name__ == "__main__":
    unittest.main()
