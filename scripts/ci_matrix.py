#!/usr/bin/env python3
"""Emit GitHub Actions matrices from .github/ci-matrix.json.

The file lists [OS, compiler] pairs by group and assigns groups to jobs.
Editing a shared group updates every consuming job and the summary inventory.
"""

import argparse
import json
from pathlib import Path


DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / '.github/ci-matrix.json'


def load_matrices(path=DEFAULT_CONFIG):
    config = json.loads(path.read_text())
    matrices = {}
    for job, groups in config['jobs'].items():
        rows, seen = [], set()
        for group in groups:
            for pair in config['pairs'][group]:
                if (not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(value, str) and value for value in pair)):
                    raise ValueError(f'{job}: expected an OS/compiler string pair: {pair!r}')
                key = tuple(pair)
                if key in seen:
                    raise ValueError(f'{job}: duplicate OS/compiler pair: {pair!r}')
                seen.add(key)
                rows.append(dict(os=pair[0], compiler=pair[1]))
        if not rows:
            raise ValueError(f'{job}: empty matrix')
        matrices[job] = dict(include=rows)
    return matrices


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    for job, matrix in load_matrices(args.config).items():
        print('matrix_' + job + '=' + json.dumps(matrix, separators=(',', ':')))


if __name__ == '__main__':
    main()
