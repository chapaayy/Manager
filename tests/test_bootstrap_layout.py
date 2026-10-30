"""Prevent regression of the Compose project-directory mismatch in bootstrap."""
import unittest
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]

class BootstrapComposeLayoutTests(unittest.TestCase):
    def test_source_layout_matches_bootstrap_staging(self):
        script=(ROOT/'bootstrap'/'install.sh').read_text()
        compose=ROOT/'agent'/'docker-compose.yml'
        self.assertTrue(compose.is_file())
        self.assertTrue((ROOT/'agent'/'Dockerfile').is_file())
        self.assertIn('install -m 600 "$SOURCE_COMPOSE" "$TARGET_COMPOSE"',script)
        self.assertIn('docker compose -f "$TARGET_COMPOSE" config -q',script)
        self.assertIn('docker compose -f "$TARGET_COMPOSE" up -d --build xppn-agent',script)
        parsed=yaml.safe_load(compose.read_text())
        self.assertEqual(parsed['services']['xppn-agent']['build'],'./agent')
        # Relative to root-level compose, the Dockerfile exists.
        self.assertTrue((ROOT/parsed['services']['xppn-agent']['build']/'Dockerfile').is_file())

if __name__=='__main__': unittest.main()
