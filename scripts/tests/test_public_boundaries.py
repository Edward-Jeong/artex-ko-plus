"""Prevent runtime credentials and private inputs from silently entering Git."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('public_boundaries', ROOT / 'scripts/check-public-boundaries.py')
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class PublicBoundaryTests(unittest.TestCase):
    def test_tracked_private_paths_fail_even_when_force_added(self):
        paths = ['.env.local', '.local-runtime/jwt.key', 'data/offensive/targets/input.json',
                 'customer.har', 'backup.zip', '.DS_Store']
        self.assertEqual({path for path, _ in boundary.violations(paths)}, set(paths))
        self.assertEqual(boundary.violations(['.env.example', '.gitignore',
                         '.github/workflows/security-ci.yml', 'db/schema.sql',
                         'SOURCE_MANIFEST.sha256', 'docs/evidence/images/screen.png']), [])

    def test_gitignore_blocks_generated_secrets_but_keeps_examples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / '.gitignore').write_bytes((ROOT / '.gitignore').read_bytes())
            protected = ['.env.local', '.local-runtime/jwt.key', 'data/run.json',
                         'nested/.env.production', 'capture.har', 'release-artifacts/source.zip',
                         '.npmrc', 'nested/.netrc', '.pypirc', 'nested/id_ed25519', 'id_rsa']
            result = subprocess.run(['git', '-C', str(root), 'check-ignore', '-z', '--stdin'],
                                    input=('\0'.join(protected) + '\0').encode(),
                                    capture_output=True, check=True)
            self.assertEqual(set(result.stdout.decode().strip('\0').split('\0')), set(protected))
            for path in ['.env.example', 'db/schema.sql', '.github/workflows/security-ci.yml']:
                result = subprocess.run(['git', '-C', str(root), 'check-ignore', path],
                                        capture_output=True)
                self.assertEqual(result.returncode, 1, path)


if __name__ == '__main__':
    unittest.main()
