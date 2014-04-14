from sys import exit
from os import rename, remove
from random import random
from subprocess import call
import sys

def first_pass(fname):
    includes = []
    for line in file(fname).readlines():
        line = line.strip()
        lparts = line.split(None, 1)
        if len(lparts) < 2 or not lparts[0].startswith('#include'):
            continue
        includes.append(lparts[1])
    if len(includes) > 0:
        return tuple(includes)
    return None

def second_pass(fname_in, fname_out, filter):
    fout = file(fname_out, 'w')
    for line in file(fname_in).readlines():
        line_s = line.strip()
        lparts = line_s.split(None, 1)
        if len(lparts) < 2 or not lparts[0].startswith('#include'):
            fout.write(line)
            continue
        if lparts[1] != filter:
            fout.write(line)
            continue
        fout.write('#if 0\n')
        fout.write(line)
        fout.write('#endif\n')

if __name__ == '__main__':
    always_ignore = ('<sys/types.h>',)
    fname = sys.argv[1]
    ignore = list(always_ignore)
    if fname.endswith('.c'):
        ignore.append('"%s.h"' % fname[:-2])
    print 'processing %s' % fname
    includes = first_pass(fname)
    if includes == None:
        print '  ...no includes found'
        exit(0)
    includes = [x for x in includes if x not in ignore]
    print 'collected %d "#include" statements' % len(includes)
    r = int(random() * 1000000.0)
    sfl_includes = []
    for include in includes:
        fname_bak = '%s.%.6d' % (fname, r)
        print 'renamed "%s" into "%s"' % (fname, fname_bak)
        rename(fname, fname_bak)
        second_pass(fname_bak, fname, include)
        rval = call(["make", "clean", "all"])
        if rval == 0:
            sfl_includes.append((include, fname))
        remove(fname)
        rename(fname_bak, fname)
    for include, fname in sfl_includes:
        print '"#include %s" is superfluous in %s' % (include, fname)
        exit(1)
    else:
        exit(0)
