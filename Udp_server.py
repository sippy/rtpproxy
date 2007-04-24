# Copyright (c) 2006-2007 Sippy Software, Inc. All rights reserved.
#
# This file is part of SIPPY, a free RFC3261 SIP stack and B2BUA.
#
# SIPPY is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# For a license to use the ser software under conditions
# other than those described here, or to purchase support for this
# software, please contact Sippy Software, Inc. by e-mail at the
# following addresses: sales@sippysoft.com.
#
# SIPPY is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

from warnings import filterwarnings
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from socket import inet_aton
from datetime import datetime
from traceback import print_exc
from sys import stdout

class Udp_server(DatagramProtocol):
    data_callback = None

    def __init__(self, address = None, data_callback = None):
        self.data_callback = data_callback
        if address == None:
            reactor.listenUDP(0, self)
        else:
            reactor.listenUDP(address[1], self, address[0])
        filterwarnings('ignore', '^Please only pass')

    def send_to(self, data, address):
        try:
            inet_aton(address[0])
        except:
            reactor.callInThread(self.transport.write, data, address)
            return
        self.transport.write(data, address)

    def datagramReceived(self, data, address):
        if self.data_callback != None:
            try:
                self.data_callback(data, address, self)
            except:
                print datetime.now(), 'Udp_server: unhandled exception in incoming data callback'
                print '-' * 70
                print_exc(file = stdout)
                print '-' * 70
                stdout.flush()

if __name__ == '__main__':
    from twisted.internet import reactor
    from system import exit

    def ping_received(data, address, udp_server):
        #print 'ping_received'
        if not (data == 'ping!' and address == ('127.0.0.1', 54321)):
            exit(1)
        udp_server.send_to('pong!', address)

    def pong_received(data, address, udp_server):
        #print 'pong_received'
        if not (data == 'pong!' and address == ('127.0.0.1', 12345)):
            exit(1)
        reactor.stop()

    udp_server_ping = Udp_server(('127.0.0.1', 12345), ping_received)
    udp_server_pong = Udp_server(('127.0.0.1', 54321), pong_received)
    udp_server_pong.send_to('ping!', ('127.0.0.1', 12345))
    reactor.run()
