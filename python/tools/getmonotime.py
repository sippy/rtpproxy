# Copyright (c) 2015-2018 Sippy Software, Inc. All rights reserved.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import getopt, sys
import os.path

def usage():
    sys.stderr.write('Usage: %s [-r] [-S sippy_path] [-C clock_name]\n' % \
      (os.path.basename(sys.argv[0])))
    sys.exit(1)

if __name__ == '__main__':
    sippy_path = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'rS:C:')
    except getopt.GetoptError:
        usage()

    out_realtime = False
    clock_name = 'CLOCK_MONOTONIC'
    for o, a in opts:
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-r':
            out_realtime = True
            continue
        if o == '-C':
            clock_name = a.strip()
            continue

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    exec('from sippy.Time.clock_dtime import clock_getdtime, %s' % clock_name)
    if not out_realtime:
        print(clock_getdtime(eval(clock_name)))
    else:
        from sippy.Time.clock_dtime import CLOCK_REALTIME
        print("%f %f" % (clock_getdtime(eval(clock_name)), clock_getdtime(CLOCK_REALTIME)))
