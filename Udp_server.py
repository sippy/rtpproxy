# Copyright (c) 2006-2009 Sippy Software, Inc. All rights reserved.
#
# This file is part of SIPPY, a free RFC3261 SIP stack and B2BUA.
#
# SIPPY is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# For a license to use the SIPPY software under conditions
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

from twisted.internet import reactor
from errno import ECONNRESET, ENOTCONN, ESHUTDOWN, EWOULDBLOCK, ENOBUFS, EAGAIN, \
  EINTR
from datetime import datetime
from time import sleep
from threading import Thread, Condition
import socket
import sys, traceback

MAX_WORKERS = 30

class AsyncSender(Thread):
    userv = None

    def __init__(self, userv):
        Thread.__init__(self)
        self.userv = userv
        self.setDaemon(True)
        self.start()

    def run(self):
        while True:
            self.userv.wi_available.acquire()
            while len(self.userv.wi) == 0:
                self.userv.wi_available.wait()
            wi = self.userv.wi.pop(0)
            if wi == None:
                # Shutdown request, relay it further
                self.userv.wi.append(None)
                self.userv.wi_available.notify()
            self.userv.wi_available.release()
            if wi == None:
                break
            data, address = wi
            try:
                ai = socket.getaddrinfo(address[0], None, self.userv.family)
            except:
                continue
            if self.userv.family == socket.AF_INET:
                address = (ai[0][4][0], address[1])
            else:
                address = (ai[0][4][0], address[1], ai[0][4][2], ai[0][4][3])
            for i in range(0, 20):
                try:
                    if self.userv.skt.sendto(data, address) == len(data):
                        break
                except socket.error, why:
                    if why[0] not in (EWOULDBLOCK, ENOBUFS, EAGAIN):
                        break
                sleep(0.01)
        self.userv = None

class AsyncReceiver(Thread):
    userv = None

    def __init__(self, userv):
        Thread.__init__(self)
        self.userv = userv
        self.setDaemon(True)
        self.start()

    def run(self):
        while True:
            try:
                data, address = self.userv.skt.recvfrom(8192)
                if not data:
                    break
            except Exception, why:
                if isinstance(why, socket.error) and why[0] in (ECONNRESET, ENOTCONN, ESHUTDOWN):
                    break
                if isinstance(why, socket.error) and why[0] in (EINTR,):
                    continue
                else:
                    print datetime.now(), 'Udp_server: unhandled exception when receiving incoming data'
                    print '-' * 70
                    traceback.print_exc(file = sys.stdout)
                    print '-' * 70
                    sys.stdout.flush()
                    sleep(1)
                    continue
            if self.userv.family == socket.AF_INET6:
                address = ('[%s]' % address[0], address[1])
            reactor.callFromThread(self.userv.handle_read, data, address)
        self.userv = None

class Udp_server(object):
    skt = None
    family = None
    data_callback = None
    laddress = None
    sendqueue = None
    stats = None
    wi_available = None
    wi = None

    def __init__(self, address, data_callback, family = None):
        self.laddress = address
        if family == None:
            if address != None and address[0].startswith('['):
                family = socket.AF_INET6
                address = (address[0][1:-1], address[1])
            else:
                family = socket.AF_INET
        self.family = family
        self.skt = socket.socket(family, socket.SOCK_DGRAM)
        if address != None:
            ai = socket.getaddrinfo(address[0], None, family)
            if family == socket.AF_INET:
                address = (ai[0][4][0], address[1])
            else:
                address = (ai[0][4][0], address[1], ai[0][4][2], ai[0][4][3])
            self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.skt.bind(address)
        self.data_callback = data_callback
        self.sendqueue = []
        self.stats = [0, 0, 0]
        self.wi_available = Condition()
        self.wi = []
        for i in range(0, MAX_WORKERS):
            AsyncSender(self)
            AsyncReceiver(self)

    def send_to(self, data, address):
        if self.family == socket.AF_INET6:
            if not address[0].startswith('['):
                raise Exception('Invalid IPv6 address: %s' % address[0])
            address = (address[0][1:-1], address[1])
        self.wi_available.acquire()
        self.wi.append((data, address))
        self.wi_available.notify()
        self.wi_available.release()
 
    def handle_read(self, data, address):
        self.stats[2] += 1
        try:
            self.data_callback(data, address, self)
        except:
            print datetime.now(), 'Udp_server: unhandled exception when processing incoming data'
            print '-' * 70
            traceback.print_exc(file = sys.stdout)
            print '-' * 70
            sys.stdout.flush()

    def shutdown(self):
        self.skt.shutdown(socket.SHUT_RDWR)
        self.wi_available.acquire()
        self.wi.append(None)
        self.wi_available.notify()
        self.wi_available.release()
        self.data_callback = None

if __name__ == '__main__':
    from sys import exit
    npongs = 2

    def ping_received(data, address, udp_server):
        print 'ping_received'
        if not (data == 'ping!' and address == ('127.0.0.1', 54321)):
            exit(1)
        udp_server.send_to('pong!', address)

    def pong_received(data, address, udp_server):
        print 'pong_received'
        if not (data == 'pong!' and address == ('127.0.0.1', 12345)):
            exit(1)
        global npongs
        npongs -= 1
        if npongs == 0:
            reactor.stop()

    def ping_received6(data, address, udp_server):
        print 'ping_received6', address
        if not (data == 'ping!' and address == ('[::1]', 54321)):
            exit(1)
        udp_server.send_to('pong!', address)

    def pong_received6(data, address, udp_server):
        print 'pong_received6', address
        if not (data == 'pong!' and address == ('[::1]', 12345)):
            exit(1)
        global npongs
        npongs -= 1
        if npongs == 0:
            reactor.stop()

    udp_server_ping = Udp_server(('127.0.0.1', 12345), ping_received)
    udp_server_pong = Udp_server(('127.0.0.1', 54321), pong_received)
    udp_server_pong.send_to('ping!', ('127.0.0.1', 12345))
    udp_server_ping6 = Udp_server(('[::1]', 12345), ping_received6)
    udp_server_pong6 = Udp_server(('::1', 54321), pong_received6, socket.AF_INET6)
    udp_server_pong6.send_to('ping!', ('[::1]', 12345))
    reactor.run()
