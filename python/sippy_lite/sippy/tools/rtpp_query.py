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

import sys, getopt

DEFAULT_RTPP_SPATH = 'unix:/var/run/rtpproxy.sock'

class command_runner(object):
    responses = None
    commands = None
    rc = None
    fin = None
    fout = None
    rval = 0
    maxfails = 5

    def __init__(self, rc, commands = None, fin = None, fout = None):
        self.responses = []
        if commands == None and fin == None:
            raise ValueError('either "commands" or "fin" argument should be non-None')
        if commands != None:
            self.commands = list(commands)
        self.fin = fin
        self.fout = fout
        self.rc = rc
        self.issue_next_cmd()

    def issue_next_cmd(self):
        if self.commands != None:
            if len(self.commands) == 0:
                ED2.breakLoop()
                return
            command = self.commands.pop(0)
        else:
            command = self.fin.readline()
            if command == None or len(command) == 0:
                ED2.breakLoop()
                return
        self.rc.send_command(command, self.got_result)

    def got_result(self, result):
        if result == None:
            if self.maxfails == 0:
                self.rval = 2
                ED2.breakLoop()
                return
            self.maxfails -= 1
        if self.fout != None:
            try:
                self.fout.write('%s\n' % result)
                self.fout.flush()
            except:
                self.rval = 1
                ED2.breakLoop()
                return
        self.responses.append(result)
        self.issue_next_cmd()

    def timeout(self):
        self.rval = 3
        ED2.breakLoop()

def usage():
    print('usage: rtpp_query.py [-s rtpp_socket_path] [-S sippy_root_path] [-i infile] ' \
      '[-o outfile] [-n nworkers] [cmd1 [cmd2]..[cmdN]]')
    sys.exit(1)

if __name__ == '__main__':
    global_config = {}
    global_config['_sip_address'] = '127.0.0.1'
    spath = DEFAULT_RTPP_SPATH
    sippy_path = None
    file_in = None
    file_out = sys.stdout
    commands = None
    no_rtpp_version_check = False
    timeout = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:i:o:bn:t:')
    except getopt.GetoptError:
        usage()

    nwrks = 4
    for o, a in opts:
        if o == '-s':
            spath = a.strip()
        elif o == '-S':
            sippy_path = a.strip()
        elif o == '-i':
            fname = a.strip()
            if fname == '-':
                file_in = sys.stdin
            else:
                file_in = open(fname, 'r')
        elif o == '-o':
           fname = a.strip()
           if fname == '-':
               file_out = sys.stdout
           else:
               file_out = open(fname, 'w')
        elif o == '-b':
           no_rtpp_version_check = True
        elif o == '-n':
           nwrks = int(a)
        elif o == '-t':
           timeout = float(a.strip())

    if len(args) > 0:
        commands = args

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    from sippy.Rtp_proxy_client import Rtp_proxy_client
    from sippy.Time.Timeout import Timeout
    from sippy.Core.EventDispatcher import ED2

    rc = Rtp_proxy_client(global_config, spath = spath, nworkers = nwrks, \
      no_version_check = no_rtpp_version_check)
    #commands = ('VF 123456', 'G nsess_created', 'G ncmds_rcvd')
    crun = command_runner(rc, commands, file_in, file_out)
    if timeout != None:
        Timeout(crun.timeout, timeout)
    ED2.loop(freq = 1000.0)
    rc.shutdown()
    sys.exit(crun.rval)
