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

from twisted.internet.protocol import Factory
from twisted.internet import reactor
from Cli_session import Cli_session

class Cli_server_tcp(Factory):
    command_cb = None
    lport = None
    accept_list = None

    def __init__(self, command_cb, address):
        self.command_cb = command_cb
        self.protocol = Cli_session
        self.lport = reactor.listenTCP(address[1], self, interface = address[0])

    def buildProtocol(self, addr):
        if self.accept_list != None and addr.host not in self.accept_list:
            return None
        p = Factory.buildProtocol(self, addr)
        p.command_cb = self.command_cb
        p.raddr = addr
        return p

    def shutdown(self):
        self.lport.stopListening()

if __name__ == '__main__':
    def callback(clm, cmd):
        print cmd
        return False
    laddr = ('127.0.0.1', 12345)
    f = Cli_server_tcp(callback, laddr)
    reactor.run()
