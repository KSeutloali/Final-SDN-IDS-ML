"""Tests for rolling capture snapshot preservation."""

import json
import tempfile
import time
import unittest
from pathlib import Path

from captures.capture_manager import PacketCaptureManager
from config.settings import CaptureConfig


class PacketCaptureManagerTests(unittest.TestCase):
    def test_preserve_snapshot_uses_newest_ring_file_as_primary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = CaptureConfig(
                enabled=True,
                continuous_enabled=True,
                interfaces=("s2-eth3",),
                output_directory=temp_dir,
                snapshot_files_per_interface=2,
            )
            manager = PacketCaptureManager(config, manage_workers=False)

            ring_root = Path(temp_dir) / "continuous" / "ring" / "s2-eth3"
            ring_root.mkdir(parents=True, exist_ok=True)

            older_file = ring_root / "s2-eth3_20260319-134318.pcap"
            newer_file = ring_root / "s2-eth3_20260319-134348.pcap"
            older_file.write_bytes(b"older")
            newer_file.write_bytes(b"newer")

            older_mtime = time.time() - 30.0
            newer_mtime = time.time() - 5.0
            older_file.touch()
            newer_file.touch()
            older_file.chmod(0o644)
            newer_file.chmod(0o644)
            older_file_stat = (older_mtime, older_mtime)
            newer_file_stat = (newer_mtime, newer_mtime)
            import os

            os.utime(str(older_file), older_file_stat)
            os.utime(str(newer_file), newer_file_stat)

            manager._write_state(
                {
                    "active": True,
                    "enabled": True,
                    "rolling_root": str(Path(temp_dir) / "continuous" / "ring"),
                    "interfaces": [{"interface": "s2-eth3", "status": "active"}],
                }
            )

            snapshot = manager.preserve_snapshot(
                src_ip="10.0.0.1",
                alert_type="random_forest_detected",
                detector="ml",
                reason="ml_confidence_threshold_exceeded",
                timestamp=time.time(),
            )

            self.assertIsNotNone(snapshot)
            self.assertTrue(
                snapshot["primary_file"].endswith("s2-eth3__s2-eth3_20260319-134348.pcap")
            )

    def test_preserve_snapshot_skips_stale_capture_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = CaptureConfig(
                enabled=True,
                continuous_enabled=True,
                interfaces=("s2-eth3",),
                output_directory=temp_dir,
                snapshot_files_per_interface=2,
                ring_file_seconds=30,
            )
            manager = PacketCaptureManager(config, manage_workers=False)

            ring_root = Path(temp_dir) / "continuous" / "ring" / "s2-eth3"
            ring_root.mkdir(parents=True, exist_ok=True)
            stale_file = ring_root / "s2-eth3_20260319-134348.pcap"
            stale_file.write_bytes(b"stale")
            stale_mtime = time.time() - 600.0

            import os

            os.utime(str(stale_file), (stale_mtime, stale_mtime))
            manager._write_state(
                {
                    "active": True,
                    "enabled": True,
                    "rolling_root": str(Path(temp_dir) / "continuous" / "ring"),
                    "interfaces": [{"interface": "s2-eth3", "status": "active"}],
                }
            )
            payload = manager._read_state()
            payload["updated_at_epoch"] = time.time() - 600.0
            manager.state_path.write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )

            snapshot = manager.preserve_snapshot(
                src_ip="10.0.0.1",
                alert_type="port_scan_detected",
                detector="threshold",
                reason="unique_destination_ports_threshold_exceeded",
                timestamp=time.time(),
            )

            self.assertIsNone(snapshot)


if __name__ == "__main__":
    unittest.main()
