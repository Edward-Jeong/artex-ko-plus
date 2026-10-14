#!/usr/bin/env python3
"""Reject tracked runtime/private paths; this is not a content secret scanner."""

import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_boundary', ROOT / 'scripts/package-release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def violations(paths):
    # A manifest belongs to the public source distribution, unlike runtime data.
    return [(path, release.exclusion_reason(path)) for path in paths
            if path != release.MANIFEST and release.exclusion_reason(path)]


def main():
    result = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z'],
                            capture_output=True, check=True)
    paths = result.stdout.decode('utf-8').split('\0')
    rejected = violations(path for path in paths if path)
    for path, reason in rejected:
        print(f'Private/generated tracked path: {path} ({reason})', file=sys.stderr)
    if rejected:
        return 1
    print('Tracked paths respect public-release boundaries (content scan still required).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
