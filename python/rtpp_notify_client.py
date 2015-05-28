#!/usr/bin/env python2
#
# Copyright (c) 2015 Sippy Software, Inc. All rights reserved.
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

import sys
import getopt

from twisted.internet import reactor

DEFAULT_RTPP_SPATH = 'unix:/var/run/rtpproxy.sock'

class cli_handler(object):
    file_out = None
    rval = 0

    def __init__(self, file_out):
        self.file_out = file_out

    def command_received(self, clm, cmd):
        try:
            self.file_out.write(cmd + '\n')
            self.file_out.flush()
        except:
            self.rval = 1
            reactor.crash()
            return

    def done(self):
        reactor.crash()

if __name__ == '__main__':
    spath = DEFAULT_RTPP_SPATH
    stype = 'unix'
    sippy_path = None
    file_out = sys.stdout
    timeout = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:o:t:')
    except getopt.GetoptError:
        usage()

    for o, a in opts:
        if o == '-s':
            spath = a.strip()
            if spath.startswith('unix:'):
                spath = spath[5:]
                stype = 'unix'
            elif spath.startswith('tcp:'):
                spath = spath[4:].split(':', 1)
                if len(spath) != 2:
                    raise ValueError('TCP listening socket not in the form "IP:port": ' + spath[0])
                spath[1] = int(spath[1])
                if spath[1] <= 0 or spath[1] > 65535:
                    raise ValueError('TCP listening port not in the range 1-65535: %d' % spath[1])
                stype = 'tcp'
            continue
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-o':
           fname = a.strip()
           if fname == '-':
               file_out = sys.stdout
           else:
               file_out = file(fname, 'w')
        if o == '-t':
           timeout = float(a.strip())
           continue

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    from sippy.Cli_server_local import Cli_server_local
    from sippy.Cli_server_tcp import Cli_server_tcp
    from sippy.Timeout import Timeout

    ch = cli_handler(file_out)
    if stype == 'unix':
        cs = Cli_server_local(ch.command_received, spath)
    else:
        cs = Cli_server_tcp(ch.command_received, spath)
    if timeout != None:
        Timeout(ch.done, timeout)
    reactor.run(installSignalHandlers = 1)
    sys.exit(ch.rval)
