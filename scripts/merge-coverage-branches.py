#!/usr/bin/env python3

"""Combine lcov reports and merge branch records of the same source line.

The reports of all test suites run with one OS/compiler pair are added up
into a single report, so that Coveralls receives one upload per build.

Some sources are compiled several times (normal and RTPP_CHECK_LEAKS
variants, different optimization levels), and each object numbers the blocks
of a line differently. lcov and Coveralls key branches by block, so a line
gets one set of branches per build, and a branch taken in one build only
(e.g. an allocation failure injected by glitching) is still reported as missed
in the others. Fold the blocks of a line onto block 0 when they all have the
same branches, adding up the counts by branch index.

Fuzzing uses source-based coverage, which numbers lines and branches in its
own way. Its report is kept as is, and the tests' coverage is blended into
the records it has (--blend), so it is not reported as missed there. The
tests' own branches only serve for that (--no-branches), since every compiler
numbers them differently and Coveralls cannot match them up.

Optimized builds attribute stack setup to declarations, so a function that
only runs in another build gets its declarations reported as missed. Drop
those that no build executed (--drop-declarations).
"""

import argparse
import re

# A declaration without initializer: type words, then declarators.
DECLARATION = re.compile(r'([A-Za-z_]\w*\s+)*[A-Za-z_]\w*[\s*]+'
                         r'[A-Za-z_]\w*(\[[^]=;(]*\])*'
                         r'(\s*,[\s*]*[A-Za-z_]\w*(\[[^]=;(]*\])*)*')
STATEMENTS = {'return', 'goto', 'break', 'continue', 'case', 'default',
              'do', 'else'}


def is_declaration(text):
    text = re.sub(r'\s*(/\*.*\*/|//.*)\s*$', '', text).strip()
    if not text.endswith(';'):
        return False
    return all(DECLARATION.fullmatch(part.strip()) and
               part.split(None, 1)[0] not in STATEMENTS
               for part in text[:-1].split(';'))


def drop_declarations(record):
    source = next(line for line in record if line.startswith('SF:'))[3:]
    try:
        with open(source) as f:
            text = f.read().splitlines()
    except OSError:
        return record
    out = []
    for line in record:
        if line.startswith('DA:'):
            lineno, count = line[3:].split(',')[:2]
            if (int(count) == 0 and int(lineno) <= len(text) and
              is_declaration(text[int(lineno) - 1])):
                continue
        out.append(line)
    return merge_record(combine_records([out]))


def add_taken(a, b):
    if a == '-':
        return b
    if b == '-':
        return a
    return str(int(a) + int(b))


def merge_line(brdas):
    blocks = {}
    for block, branch, taken in brdas:
        blocks.setdefault(block, []).append((branch, taken))
    shapes = {tuple(branch for branch, _ in brs) for brs in blocks.values()}
    if len(blocks) < 2 or len(shapes) != 1:
        return brdas
    merged = {}
    for brs in blocks.values():
        for branch, taken in brs:
            merged[branch] = add_taken(merged.get(branch, '-'), taken)
    return [('0', branch, taken) for branch, taken in merged.items()]


def combine_records(records):
    """Add up the records that several reports have for one source file."""
    other, fns, fndas, fnls, das, brdas = [], {}, {}, {}, {}, {}
    for record in records:
        fna_lines = {}
        for line in record:
            tag, _, value = line.partition(':')
            if tag == 'DA':
                lineno, count, *rest = value.split(',')
                prev = das.get(int(lineno), (0, rest))
                das[int(lineno)] = (prev[0] + int(count), prev[1])
            elif tag == 'FN':
                fns.setdefault(value.rsplit(',', 1)[1], line)
            elif tag == 'FNDA':
                count, name = value.split(',', 1)
                fndas[name] = fndas.get(name, 0) + int(count)
            elif tag == 'FNL':
                index, location = value.split(',', 1)
                fna_lines[index] = location
            elif tag == 'FNA':
                index, count, name = value.split(',', 2)
                location, prev = fnls.get(name, (fna_lines[index], 0))
                fnls[name] = (location, prev + int(count))
            elif tag == 'BRDA':
                lineno, block, branch, taken = value.split(',', 3)
                key = (int(lineno), block, branch)
                brdas[key] = add_taken(brdas.get(key, '-'), taken)
            elif tag not in ('LF', 'LH', 'FNF', 'FNH', 'BRF', 'BRH'):
                if line not in other:
                    other.append(line)
    out = list(other)
    if fns or fndas:
        out += fns.values()
        out += [f'FNDA:{count},{name}' for name, count in fndas.items()]
        out += [f'FNF:{len(fns)}',
                f'FNH:{sum(1 for count in fndas.values() if count > 0)}']
    if fnls:
        for index, (name, (location, count)) in enumerate(fnls.items()):
            out += [f'FNL:{index},{location}', f'FNA:{index},{count},{name}']
        out += [f'FNF:{len(fnls)}',
                f'FNH:{sum(1 for _, count in fnls.values() if count > 0)}']
    out += [f'BRDA:{lineno},{block},{branch},{taken}'
            for (lineno, block, branch), taken in sorted(brdas.items())]
    out += [f'DA:{lineno},{",".join([str(count)] + rest)}'
            for lineno, (count, rest) in sorted(das.items())]
    if das:
        out += [f'LF:{len(das)}',
                f'LH:{sum(1 for count, _ in das.values() if count > 0)}']
    return out


def merge_record(lines):
    brdas = {}
    out = []
    for line in lines:
        if line.startswith('BRDA:'):
            if not brdas:
                out.append(None)
            lineno, block, branch, taken = line[5:].split(',', 3)
            brdas.setdefault(int(lineno), []).append((block, branch, taken))
        elif not line.startswith(('BRF:', 'BRH:')):
            out.append(line)
    if not brdas:
        return lines
    merged = []
    for lineno in sorted(brdas):
        merged += [(lineno, *brda) for brda in merge_line(brdas[lineno])]
    hit = sum(1 for *_, taken in merged if taken not in ('-', '0'))
    brlines = [f'BRDA:{lineno},{block},{branch},{taken}'
               for lineno, block, branch, taken in merged]
    brlines += [f'BRF:{len(merged)}', f'BRH:{hit}']
    i = out.index(None)
    return out[:i] + brlines + out[i + 1:]


def split_records(reports):
    sources = {}
    for report in reports:
        record = []
        for line in report.splitlines():
            if line == 'end_of_record':
                source = next(l for l in record if l.startswith('SF:'))
                sources.setdefault(source, []).append(record)
                record = []
            elif line:
                record.append(line)
    return sources


def blend_counts(blends):
    """Collect what reports of another kind of build covered in each source.

    Their lines and functions match by number and name. Their branches are
    numbered differently, so only a line on which all branches were taken
    tells that every outcome of its conditions happened.
    """
    counts = {}
    for source, records in split_records(blends).items():
        das, fns, full = counts.setdefault(source, ({}, {}, {}))
        for record in records:
            brdas = {}
            for line in record:
                tag, _, value = line.partition(':')
                if tag == 'DA':
                    lineno, count = value.split(',')[:2]
                    das[int(lineno)] = das.get(int(lineno), 0) + int(count)
                elif tag in ('FNDA', 'FNA'):
                    count, name = value.split(',')[-2:]
                    fns[name] = fns.get(name, 0) + int(count)
                elif tag == 'BRDA':
                    lineno, _, _, taken = value.split(',', 3)
                    brdas.setdefault(int(lineno), []).append(
                      0 if taken == '-' else int(taken))
            for lineno, takens in brdas.items():
                if min(takens) > 0:
                    full[lineno] = max(full.get(lineno, 0), min(takens))
    return counts


def blend_record(lines, counts):
    das, fns, full = counts
    out = []
    for line in lines:
        tag, _, value = line.partition(':')
        if tag == 'DA':
            lineno, count, *rest = value.split(',')
            count = int(count) + das.get(int(lineno), 0)
            line = f'DA:{",".join([lineno, str(count)] + rest)}'
        elif tag == 'FNDA':
            count, name = value.split(',', 1)
            line = f'FNDA:{int(count) + fns.get(name, 0)},{name}'
        elif tag == 'FNA':
            index, count, name = value.split(',', 2)
            line = f'FNA:{index},{int(count) + fns.get(name, 0)},{name}'
        elif tag == 'BRDA':
            lineno, block, branch, taken = value.split(',', 3)
            if taken in ('-', '0') and int(lineno) in full:
                line = f'BRDA:{lineno},{block},{branch},{full[int(lineno)]}'
        out.append(line)
    return merge_record(combine_records([out]))


def merge_reports(reports, blends=(), branches=True, declarations=True):
    counts = blend_counts(blends)
    result = []
    for source, records in split_records(reports).items():
        record = merge_record(combine_records(records))
        if source in counts:
            record = blend_record(record, counts[source])
        if not declarations:
            record = drop_declarations(record)
        if not branches:
            record = [line for line in record
                      if not line.startswith(('BRDA:', 'BRF:', 'BRH:'))]
        result += record + ['end_of_record']
    return '\n'.join(result) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('-o', '--output',
                        help='output file (default: the only input, in place)')
    parser.add_argument('-b', '--blend', action='append', default=[],
                        metavar='lcov.info',
                        help='add coverage of a differently instrumented '
                             'build to the records the reports already have')
    parser.add_argument('--no-branches', dest='branches', action='store_false',
                        help='leave branch records out of the output')
    parser.add_argument('--drop-declarations', dest='declarations',
                        action='store_false',
                        help='leave out declarations that were not executed')
    parser.add_argument('reports', nargs='+', metavar='lcov.info')
    args = parser.parse_args()
    if args.output is None and len(args.reports) != 1:
        parser.error('-o is required with several inputs')

    def read(paths):
        reports = []
        for path in paths:
            with open(path) as f:
                reports.append(f.read())
        return reports

    result = merge_reports(read(args.reports), read(args.blend), args.branches,
                           args.declarations)
    with open(args.output or args.reports[0], 'w') as f:
        f.write(result)
