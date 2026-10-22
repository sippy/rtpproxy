#!/usr/bin/env python3

"""Map OSS-Fuzz source paths to the checkout and exclude dependencies."""

from pathlib import Path

# llvm-cov derives some counts by subtracting counters, and increments lost
# to races between threads make such a count negative. It is exported as an
# unsigned value, 64-bit for lines and 32-bit for branches, so read the ones
# with the sign bit set as never executed.
WRAPPED_LINE = 2 ** 63
WRAPPED_BRANCH = 2 ** 31


def unwrap(line):
    tag, _, value = line.partition(':')
    if tag == 'DA':
        lineno, count, *rest = value.split(',')
        if int(count) >= WRAPPED_LINE:
            return f'DA:{",".join([lineno, "0"] + rest)}'
    elif tag == 'BRDA':
        lineno, block, branch, taken = value.split(',', 3)
        if taken != '-' and int(taken) >= WRAPPED_BRANCH:
            return f'BRDA:{lineno},{block},{branch},0'
    return line


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
            lines = [unwrap(line) for line in lines]
            yield '\n'.join(lines) + '\nend_of_record\n'
            break


if __name__ == '__main__':
    checkout = Path(__file__).resolve().parents[2]
    report = (checkout / 'coverage/raw.info').read_text()
    result = ''.join(normalize(report, checkout))
    if not result:
        raise SystemExit('No RTPProxy sources found in fuzzing coverage report')
    (checkout / 'coverage/lcov.info').write_text(result)
