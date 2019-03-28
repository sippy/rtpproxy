#!/usr/bin/env python

from random import random
from subprocess import call
import sys, os

def get_ip_flags(iname, includedirs):
    includedirs = ['.',] + includedirs
    for dname in includedirs:
        try:
            f = file('%s/%s' % (dname, iname))
            break
        except IOError:
            continue
    else:
        raise Exception('%s is not found in %s' % (iname, includedirs))
    for line in f.readlines():
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

    def __init__(self, ifname, includedirs):
        self.ifname = ifname
        if not ifname.startswith('"'):
            return
        iname = ifname.strip('"')
        self.ip_flags = get_ip_flags(iname, includedirs)

    def isflset(self, flname):
        if self.ip_flags == None:
            return False
        return (flname in self.ip_flags)

def first_pass(fname, includedirs):
    includes = []
    for line in file(fname).readlines():
        line = line.strip()
        lparts = line.split(None, 1)
        if len(lparts) < 2 or not lparts[0].startswith('#include'):
            continue
        if lparts[1] in [x.ifname for x in includes]:
            # dupe
            continue
        includes.append(header_file(lparts[1], includedirs))
    if len(includes) > 0:
        return tuple(includes)
    return None

def block_line(fout, line):
    fout.write('#if 0\n')
    fout.write(line)
    fout.write('#endif\n')

def err_line(fout, line):
    fout.write('#error "OOPS"\n')
    fout.write(line)

def second_pass(fname_in, fname_out, filter, target, edit_fn = block_line):
    #print 'second_pass', fname_in, fname_out, filter, target
    fout = file(fname_out, 'w')
    fh_names = [x.ifname for x in filter + [target,]]
    for line in file(fname_in).readlines():
        line_s = line.strip()
        lparts = line_s.split(None, 1)
        if len(lparts) < 2 or not lparts[0].startswith('#include'):
            fout.write(line)
            continue
        if lparts[1] not in fh_names:
            fout.write(line)
            continue
        if lparts[1] == target.ifname:
            edit_fn(fout, line)
        else:
            block_line(fout, line)
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

class PassConf(object):
    devnull = None
    make_flags = None
    cleanbuild_targets = None
    build_targets = None
    fname_bak = None
    fname = None

def pass2_handler(pf):
    call(('diff', '-du', fname_bak, fname), stdout = pf.devnull, \
      stderr = pf.devnull)
    pf.devnull.flush()
    cargs = [make,]
    if pf.make_flags != None:
        cargs.extend(pf.make_flags)
    if fname.endswith('.h'):
        cargs.extend(pf.cleanbuild_targets)
    else:
        cargs.extend(pf.build_targets)
    pf.devnull.write('\n\n***** Running: %s *****\n\n' % (str(cargs),))
    pf.devnull.flush()
    rval = call(cargs, stdout = pf.devnull, stderr = pf.devnull)
    os.remove(fname)
    pf.devnull.write('\n\n***** status %d *****\n\n' % (rval,))
    pf.devnull.flush()
    return rval

if __name__ == '__main__':
    make = os.environ['SMAKE']
    includedirs = os.environ['SIPATH'].split(':')
    pconf = PassConf()
    pconf.cleanbuild_targets = ('clean', 'all')
    pconf.build_targets = ('all',)
    try:
        pconf.make_flags = os.environ['SMAKEFLAGS'].split()
    except KeyError:
        pconf.make_flags = None
    always_ignore = ('<sys/types.h>', '"config.h"')
    fname = sys.argv[1]
    ignore = list(always_ignore)
    if fname.endswith('.c'):
        ignore.append('"%s.h"' % fname[:-2])
    print 'processing %s' % fname
    includes = first_pass(fname, includedirs)
    if includes == None:
        print '  ...no includes found'
        sys.exit(0)
    includes = [x for x in includes if x.ifname not in ignore \
      and not x.isflset('DONT_REMOVE')]
    includes.sort()
    pconf.devnull = file('ipol/' + fname + '.iout', 'a')
    print ' .collected %d "#include" statements' % len(includes)
    print ' .doing dry run'
    cargs = [make,]
    if pconf.make_flags != None:
        cargs.extend(pconf.make_flags)
    cargs.extend(pconf.cleanbuild_targets)
    pconf.devnull.write('\n\n***** Dry-Running: %s *****\n\n' % (str(cargs),))
    pconf.devnull.flush()
    rval = call(cargs, stdout = pconf.devnull, stderr = pconf.devnull)
    if rval != 0:
        print '  ...dry run failed'
        sys.exit(255)
    pconf.devnull.flush()
    r = int(random() * 1000000.0)
    sfl_includes = []
    unusd_includes = []
    fname_bak = '%s.%.6d' % (fname, r)
    os.rename(fname, fname_bak)
    print ' ..renamed "%s" into "%s"' % (fname, fname_bak)
    while True:
        #print 'sfl_includes:', [x.ifname for x in sfl_includes]
        sfl_includes_bak = sfl_includes[:]
        for include in includes:
            if include in sfl_includes + unusd_includes:
                continue
            second_pass(fname_bak, fname, sfl_includes, include, err_line)
            rval = pass2_handler(pconf)
            if rval == 0:
                unusd_includes.append(include)
                continue
            second_pass(fname_bak, fname, sfl_includes, include, block_line)
            rval = pass2_handler(pconf)
            if rval == 0:
                sfl_includes.append(include)
                break
        if len(sfl_includes_bak) == len(sfl_includes):
            break
    os.rename(fname_bak, fname)
    for include in sfl_includes:
        print '"#include %s" is superfluous in %s' % (include.ifname, fname)
    sys.exit(len(sfl_includes))
