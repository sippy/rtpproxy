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

from __future__ import print_function

from errno import ECONNRESET, ENOTCONN, ESHUTDOWN, EWOULDBLOCK, ENOBUFS, EAGAIN, \
  EINTR
from datetime import datetime
from time import sleep, time
from threading import Thread, Condition
from random import random
import socket
import sys, traceback

from sippy.Core.EventDispatcher import ED2
from sippy.Time.Timeout import Timeout
from sippy.Time.MonoTime import MonoTime

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
                ai = socket.getaddrinfo(address[0], None, self.userv.uopts.family)
            except:
                continue
            if self.userv.uopts.family == socket.AF_INET:
                address = (ai[0][4][0], address[1])
            else:
                address = (ai[0][4][0], address[1], ai[0][4][2], ai[0][4][3])
            for i in range(0, 20):
                try:
                    if self.userv.skt.sendto(data, address) == len(data):
                        break
                except socket.error as why:
                    if isinstance(why, BrokenPipeError):
                        self.userv = None
                        return
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
        maxemptydata = 100
        while True:
            try:
                data, address = self.userv.skt.recvfrom(8192)
                if not data and address == None:
                    # Ugly hack to detect socket being closed under us on Linux.
                    # The problem is that even call on non-closed socket can
                    # sometimes return empty data buffer, making AsyncReceiver
                    # to exit prematurely.
                    maxemptydata -= 1
                    if maxemptydata == 0:
                        break
                    continue
                else:
                    maxemptydata = 100
                rtime = MonoTime()
            except Exception as why:
                if isinstance(why, socket.error) and why[0] in (ECONNRESET, ENOTCONN, ESHUTDOWN):
                    break
                if isinstance(why, socket.error) and why[0] in (EINTR,):
                    continue
                else:
                    print(datetime.now(), 'Udp_server: unhandled exception when receiving incoming data')
                    print('-' * 70)
                    traceback.print_exc(file = sys.stdout)
                    print('-' * 70)
                    sys.stdout.flush()
                    sleep(1)
                    continue
            if self.userv.uopts.family == socket.AF_INET6:
                address = ('[%s]' % address[0], address[1])
            ED2.callFromThread(self.userv.handle_read, data, address, rtime)
        self.userv = None

_DEFAULT_FLAGS = socket.SO_REUSEADDR
if hasattr(socket, 'SO_REUSEPORT'):
    _DEFAULT_FLAGS |= socket.SO_REUSEPORT
_DEFAULT_NWORKERS = 30

class Udp_server_opts(object):
    laddress = None
    data_callback = None
    family = None
    flags = _DEFAULT_FLAGS
    nworkers = None
    ploss_out_rate = 0.0
    pdelay_out_max = 0.0
    ploss_in_rate = 0.0
    pdelay_in_max = 0.0

    def __init__(self, laddress, data_callback, family = None, o = None):
        if o == None:
            if family == None:
                if laddress != None and laddress[0].startswith('['):
                    family = socket.AF_INET6
                    laddress = (laddress[0][1:-1], laddress[1])
                else:
                    family = socket.AF_INET
            self.family = family
            self.laddress = laddress
            self.data_callback = data_callback
        else:
            self.laddress, self.data_callback, self.family, self.nworkers, self.flags, \
              self.ploss_out_rate, self.pdelay_out_max, self.ploss_in_rate, \
              self.pdelay_in_max = o.laddress, o.data_callback, o.family, \
              o.nworkers, o.flags, o.ploss_out_rate, o.pdelay_out_max, o.ploss_in_rate, \
              o.pdelay_in_max

    def getCopy(self):
        return self.__class__(None, None, o = self)

    def getSIPaddr(self):
        if self.family == socket.AF_INET:
            return self.laddress
        return (('[%s]' % self.laddress[0], self.laddress[1]))

    def isWildCard(self):
        if (self.family, self.laddress[0]) in ((socket.AF_INET, '0.0.0.0'), \
          (socket.AF_INET6, '::')):
            return True
        return False

class Udp_server(object):
    skt = None
    uopts = None
    sendqueue = None
    stats = None
    wi_available = None
    wi = None
    asenders = None
    areceivers = None

    def __init__(self, global_config, uopts):
        self.uopts = uopts.getCopy()
        self.skt = socket.socket(self.uopts.family, socket.SOCK_DGRAM)
        if self.uopts.laddress != None:
            ai = socket.getaddrinfo(self.uopts.laddress[0], None, self.uopts.family)
            if self.uopts.family == socket.AF_INET:
                address = (ai[0][4][0], self.uopts.laddress[1])
            else:
                address = (ai[0][4][0], self.uopts.laddress[1], ai[0][4][2], ai[0][4][3])
            if (self.uopts.flags & socket.SO_REUSEADDR) != 0:
                self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT') and \
              (self.uopts.flags & socket.SO_REUSEPORT) != 0:
                self.skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.skt.bind(address)
            if self.uopts.laddress[1] == 0:
                self.uopts.laddress = self.skt.getsockname()
        self.sendqueue = []
        self.stats = [0, 0, 0]
        self.wi_available = Condition()
        self.wi = []
        self.asenders = []
        self.areceivers = []
        if self.uopts.nworkers == None:
            nworkers = _DEFAULT_NWORKERS
        else:
            nworkers = self.uopts.nworkers
        for i in range(0, nworkers):
            self.asenders.append(AsyncSender(self))
            self.areceivers.append(AsyncReceiver(self))

    def send_to(self, data, address, delayed = False):
        if not isinstance(address, tuple):
            raise Exception('Invalid address, not a tuple: %s' % str(address))
        if not isinstance(data, bytes):
            data = data.encode('utf-8')
        if self.uopts.ploss_out_rate > 0.0 and not delayed:
            if random() < self.uopts.ploss_out_rate:
                return
        if self.uopts.pdelay_out_max > 0.0 and not delayed:
            pdelay = self.uopts.pdelay_out_max * random()
            Timeout(self.send_to, pdelay, 1, data, address, True)
            return
        addr, port = address
        if self.uopts.family == socket.AF_INET6:
            if not addr.startswith('['):
                raise Exception('Invalid IPv6 address: %s' % addr)
            address = (addr[1:-1], port)
        self.wi_available.acquire()
        self.wi.append((data, address))
        self.wi_available.notify()
        self.wi_available.release()
 
    def handle_read(self, data, address, rtime, delayed = False):
        if len(data) > 0 and self.uopts.data_callback != None:
            self.stats[2] += 1
            if self.uopts.ploss_in_rate > 0.0 and not delayed:
                if random() < self.uopts.ploss_in_rate:
                    return
            if self.uopts.pdelay_in_max > 0.0 and not delayed:
                pdelay = self.uopts.pdelay_in_max * random()
                Timeout(self.handle_read, pdelay, 1, data, address, rtime.getOffsetCopy(pdelay), True)
                return
            try:
                self.uopts.data_callback(data, address, self, rtime)
            except Exception as ex:
                if isinstance(ex, SystemExit):
                    raise 
                print(datetime.now(), 'Udp_server: unhandled exception when processing incoming data')
                print('-' * 70)
                traceback.print_exc(file = sys.stdout)
                print('-' * 70)
                sys.stdout.flush()

    def shutdown(self):
        try:
            self.skt.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.wi_available.acquire()
        self.wi.append(None)
        self.wi_available.notify()
        self.wi_available.release()
        self.uopts.data_callback = None
        for worker in self.asenders + self.areceivers:
            worker.join()
        self.asenders = None
        self.areceivers = None

class self_test(object):
    from sys import exit
    npongs = 2
    ping_data = b'ping!'
    ping_data6 = b'ping6!'
    pong_laddr = None
    pong_laddr6 = None
    pong_data = b'pong!'
    pong_data6 = b'pong6!'
    ping_laddr = None
    ping_laddr6 = None
    ping_raddr = None
    ping_raddr6 = None
    pong_raddr = None
    pong_raddr6 = None

    def ping_received(self, data, address, udp_server, rtime):
        if udp_server.uopts.family == socket.AF_INET:
            print('ping_received')
            if data != self.ping_data or address != self.pong_raddr:
                print(data, address, self.ping_data, self.pong_raddr)
                exit(1)
            udp_server.send_to(self.pong_data, address)
        else:
            print('ping_received6')
            if data != self.ping_data6 or address != self.pong_raddr6:
                print(data, address, self.ping_data6, self.pong_raddr6)
                exit(1)
            udp_server.send_to(self.pong_data6, address)

    def pong_received(self, data, address, udp_server, rtime):
        if udp_server.uopts.family == socket.AF_INET:
            print('pong_received')
            if data != self.pong_data or address != self.ping_raddr:
                print(data, address, self.pong_data, self.ping_raddr)
                exit(1)
        else:
            print('pong_received6')
            if data != self.pong_data6 or address != self.ping_raddr6:
                print(data, address, self.pong_data6, self.ping_raddr6)
                exit(1)
        self.npongs -= 1
        if self.npongs == 0:
            ED2.breakLoop()

    def run(self):
        local_host = '127.0.0.1'
        local_host6 = '[::1]'
        remote_host = local_host
        remote_host6 = local_host6
        self.ping_laddr = (local_host, 12345)
        self.pong_laddr = (local_host, 54321)
        self.ping_laddr6 = (local_host6, 12345)
        self.pong_laddr6 = (local_host6, 54321)
        self.ping_raddr = (remote_host, 12345)
        self.pong_raddr = (remote_host, 54321)
        self.ping_raddr6 = (remote_host6, 12345)
        self.pong_raddr6 = (remote_host6, 54321)
        uopts_ping = Udp_server_opts(self.ping_laddr, self.ping_received)
        uopts_ping6 = Udp_server_opts(self.ping_laddr6, self.ping_received)
        uopts_pong = Udp_server_opts(self.pong_laddr, self.pong_received)
        uopts_pong6 = Udp_server_opts(self.pong_laddr6, self.pong_received)
        udp_server_ping = Udp_server({}, uopts_ping)
        udp_server_pong = Udp_server({}, uopts_pong)
        udp_server_pong.send_to(self.ping_data, self.ping_laddr)
        udp_server_ping6 = Udp_server({}, uopts_ping6)
        udp_server_pong6 = Udp_server({}, uopts_pong6)
        udp_server_pong6.send_to(self.ping_data6, self.ping_laddr6)
        ED2.loop()
        udp_server_ping.shutdown()
        udp_server_pong.shutdown()
        udp_server_ping6.shutdown()
        udp_server_pong6.shutdown()

if __name__ == '__main__':
    self_test().run()
