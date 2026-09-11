#!/usr/bin/env python3
"""Exercise Docker's real ignore rules with synthetic local-secret files."""

from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    excluded = (
        '.env', '.env.local', '.env.protect', 'private.pem', 'private.key',
        'nested/.env', 'nested/.env.local', 'nested/private.pem',
        'nested/private.key', '.git/config', '.worktrees/other/source.rs',
    )
    included = ('safe.txt', '.env.example', '.env.protect.example')
    with tempfile.TemporaryDirectory(prefix='unifi-build-context-') as directory:
        temporary = Path(directory)
        context = temporary / 'context'
        context.mkdir()
        (context / '.dockerignore').write_bytes((ROOT / '.dockerignore').read_bytes())
        (context / 'Dockerfile').write_text('FROM scratch\nCOPY . /\n', encoding='utf-8')
        for name in (*excluded, *included):
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic test data\n', encoding='utf-8')
        exported = temporary / 'exported'
        subprocess.run(
            ['docker', 'build', '--network', 'none', '--output',
             f'type=local,dest={exported}', str(context)],
            check=True, timeout=120,
        )
        for name in excluded:
            if (exported / name).exists():
                raise RuntimeError(f'private local file entered the build context: {name}')
        for name in included:
            if not (exported / name).is_file():
                raise RuntimeError(f'documented example was excluded: {name}')
    print('Docker build-context isolation passed')


if __name__ == '__main__':
    main()
