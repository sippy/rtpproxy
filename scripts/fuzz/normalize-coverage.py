#!/usr/bin/env python3

"""Map OSS-Fuzz source paths to the checkout and exclude dependencies."""

from pathlib import Path


def normalize(report, checkout):
    excluded = {'external', 'hepconnector', 'libelperiodic', 'dist', 'bench', 'pertools'}
    for record in report.split('end_of_record'):
        lines = record.strip().splitlines()
        for index, line in enumerate(lines):
            if not line.startswith('SF:/src/rtpproxy/'):
                continue
            source = Path(line.removeprefix('SF:/src/rtpproxy/'))
            if not source.parts or '..' in source.parts or source.parts[0] in excluded:
                break
            if not (checkout / source).is_file():
                break
            lines[index] = f'SF:{source.as_posix()}'
            yield '\n'.join(lines) + '\nend_of_record\n'
            break


if __name__ == '__main__':
    checkout = Path(__file__).resolve().parents[2]
    report = (checkout / 'coverage/raw.info').read_text()
    result = ''.join(normalize(report, checkout))
    if not result:
        raise SystemExit('No RTPProxy sources found in fuzzing coverage report')
    (checkout / 'coverage/lcov.info').write_text(result)
