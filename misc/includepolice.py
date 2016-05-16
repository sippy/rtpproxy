#!/usr/bin/env python

from random import random
from subprocess import call
import sys, os

def get_ip_flags(iname):
    for line in file(iname).readlines():
        line = line.strip()
        if not line.startswith('/*') and line.endswith('*/'):
            continue
        line = line[2:-2].strip()
        if not line.startswith('IPOLICE_FLAGS:'):
            continue
        ip_pars = line.split(':', 1)
        ip_flags = ip_pars[1].strip().split(',')
        return ip_flags
    return None

class header_file(object):
    ifname = None
    ip_flags = None

    def __init__(self, ifname):
        self.ifname = ifname
        if not ifname.startswith('"'):
            return
        iname = ifname.strip('"')
        self.ip_flags = get_ip_flags(iname)

    def isflset(self, flname):
        if self.ip_flags == None:
            return False
        return (flname in self.ip_flags)

def first_pass(fname):
    includes = []
    for line in file(fname).readlines():
        line = line.strip()
        lparts = line.split(None, 1)
        if len(lparts) < 2 or not lparts[0].startswith('#include'):
            continue
        includes.append(header_file(lparts[1]))
    if len(includes) > 0:
        return tuple(includes)
    return None

def second_pass(fname_in, fname_out, filter):
    #print 'second_pass', fname_in, fname_out, filter
    fout = file(fname_out, 'w')
    fh_names = [x.ifname for x in filter]
    for line in file(fname_in).readlines():
        line_s = line.strip()
        lparts = line_s.split(None, 1)
        if len(lparts) < 2 or not lparts[0].startswith('#include'):
            fout.write(line)
            continue
        if lparts[1] not in fh_names:
            fout.write(line)
            continue
        fout.write('#if 0\n')
        fout.write(line)
        fout.write('#endif\n')
    ofnames = []
    if fname.endswith('.c') or fname.endswith('.h'):
        objfile = fname[:-2] + '.o'
        ofnames.append(objfile)
        objfile_dbg = 'rtpproxy_debug-' + objfile
        ofnames.append(objfile_dbg)
    for objfile in ofnames:
        if os.path.exists(objfile):
            #print 'removing', objfile
            os.remove(objfile)

if __name__ == '__main__':
    make = os.environ['SMAKE']
    cleanbuild_targets = ('-DRTPP_DEBUG', 'clean', 'all')
    build_targets = ('-DRTPP_DEBUG', 'all')
    try:
        make_flags = os.environ['SMAKEFLAGS'].split()
    except KeyError:
        make_flags = None
    always_ignore = ('<sys/types.h>', '"config.h"')
    fname = sys.argv[1]
    ignore = list(always_ignore)
    if fname.endswith('.c'):
        ignore.append('"%s.h"' % fname[:-2])
    print 'processing %s' % fname
    includes = first_pass(fname)
    if includes == None:
        print '  ...no includes found'
        sys.exit(0)
    includes = [x for x in includes if x.ifname not in ignore \
      and not x.isflset('DONT_REMOVE')]
    includes.sort()
    devnull = file('ipol/' + fname + '.iout', 'a')
    print ' .collected %d "#include" statements' % len(includes)
    print ' .doing dry run'
    cargs = [make,]
    if make_flags != None:
        cargs.extend(make_flags)
    cargs.extend(cleanbuild_targets)
    devnull.write('\n\n***** Dry-Running: %s *****\n\n' % (str(cargs),))
    devnull.flush()
    rval = call(cargs, stdout = devnull, stderr = devnull)
    if rval != 0:
        print '  ...dry run failed'
        sys.exit(255)
    devnull.flush()
    r = int(random() * 1000000.0)
    sfl_includes = []
    fname_bak = '%s.%.6d' % (fname, r)
    os.rename(fname, fname_bak)
    print ' ..renamed "%s" into "%s"' % (fname, fname_bak)
    while True:
        sfl_includes_bak = sfl_includes[:]
        for include in includes:
            if include in sfl_includes:
                continue
            i2 = sfl_includes[:]
            i2.append(include)
            second_pass(fname_bak, fname, i2)
            call(('diff', '-du', fname_bak, fname), stdout = devnull, \
              stderr = devnull)
            devnull.flush()
            cargs = [make,]
            if make_flags != None:
                cargs.extend(make_flags)
            if fname.endswith('.h'):
                cargs.extend(cleanbuild_targets)
            else:
                cargs.extend(build_targets)
            devnull.write('\n\n***** Running: %s *****\n\n' % (str(cargs),))
            devnull.flush()
#            rval = call(cargs)
            rval = call(cargs, stdout = devnull, \
              stderr = devnull)
            os.remove(fname)
            devnull.write('\n\n***** status %d *****\n\n' % (rval,))
            devnull.flush()
            if rval == 0:
                sfl_includes.append(include)
                break
        if len(sfl_includes_bak) == len(sfl_includes):
            break
    os.rename(fname_bak, fname)
    if len(sfl_includes) == 0:
        sys.exit(0)
    for include in sfl_includes:
        print '"#include %s" is superfluous in %s' % (include.ifname, fname)
    sys.exit(1)
