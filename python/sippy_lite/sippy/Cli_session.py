#
# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2014 Sippy Software, Inc. All rights reserved.
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

from twisted.internet.protocol import Protocol
import sys, traceback

class Cli_session(Protocol):
    command_cb = None
    rbuffer = None
    wbuffer = None
    cb_busy = False
    expect_lf = True
    raddr = None

    def __init__(self):
        self.rbuffer = ''
        self.wbuffer = ''

    #def connectionMade(self):
    #    print self.transport.getPeer()
    #    self.transport.loseConnection()

    def dataReceived(self, data):
	#print 'Cli_session::dataReceived', self, data
        if len(data) == 0:
            return
        self.rbuffer += data
        self.pump_rxdata()

    def pump_rxdata(self):
        while self.rbuffer != None and len(self.rbuffer) > 0:
            if self.cb_busy:
                return
            if self.rbuffer.find('\n') == -1 and self.expect_lf:
                return
            parts = self.rbuffer.split('\n', 1)
            if len(parts) == 1:
                parts = (parts[0], '')
            cmd, self.rbuffer = parts
            cmd = cmd.strip()
            if len(cmd) > 0:
                try:
                    self.cb_busy = self.command_cb(self, cmd)
                except:
                    print 'Cli_session: unhandled exception when processing incoming data'
                    print '-' * 70
                    traceback.print_exc(file = sys.stdout)
                    print '-' * 70

    def done(self):
        self.cb_busy = False
        self.pump_rxdata()

    def send(self, data):
        if isinstance(data, unicode):
            data = data.encode('ascii')
        return self.transport.write(data)

    def close(self):
        return self.transport.loseConnection()
