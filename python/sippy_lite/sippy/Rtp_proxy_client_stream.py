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

from sippy.Time.Timeout import Timeout
from threading import Thread, Condition
from errno import EINTR, EPIPE, ENOTCONN, ECONNRESET
from sippy.Time.MonoTime import MonoTime
from sippy.Math.recfilter import recfilter
from sippy.Rtp_proxy_client_net import Rtp_proxy_client_net
from sippy.Rtp_proxy_cmd import Rtp_proxy_cmd

import socket

from sippy.Core.Exceptions import dump_exception
from sippy.Core.EventDispatcher import ED2

_MAX_RECURSE = 10

class _RTPPLWorker(Thread):
    userv = None
    s = None

    def __init__(self, userv):
        Thread.__init__(self)
        self.userv = userv
        self.setDaemon(True)
        self.start()

    def connect(self):
        self.s = socket.socket(self.userv.family, socket.SOCK_STREAM)
        if self.userv.family == socket.AF_INET6:
            address = (self.userv.address[0][1:-1], self.userv.address[1])
        else:
            address = self.userv.address
        self.s.connect(address)

    def send_raw(self, command, _recurse = 0, stime = None):
        if _recurse > _MAX_RECURSE:
            raise Exception('Cannot reconnect: %s' % (str(self.userv.address),))
        if self.s == None:
            self.connect()
        #print('%s.send_raw(%s)' % (id(self), command))
        if stime == None:
            stime = MonoTime()
        while True:
            try:
                self.s.send(command.encode())
                break
            except socket.error as why:
                if why.errno == EINTR:
                    continue
                elif why.errno in (EPIPE, ENOTCONN, ECONNRESET):
                    self.s = None
                    return self.send_raw(command, _recurse + 1, stime)
                raise why
        while True:
            try:
                rval = self.s.recv(1024)
                if len(rval) == 0:
                    self.s = None
                    return self.send_raw(command, _MAX_RECURSE, stime)
                rval = rval.decode().strip()
                break
            except socket.error as why:
                if why.errno == EINTR:
                    continue
                elif why.errno in (EPIPE, ENOTCONN, ECONNRESET):
                    self.s = None
                    return self.send_raw(command, _recurse + 1, stime)
                raise why
        rtpc_delay = stime.offsetFromNow()
        return (rval, rtpc_delay)

    def run(self):
        #print(self.run, 'enter')
        while True:
            #print(self.run, 'spin')
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
            command, result_callback, callback_parameters = wi
            try:
                data, rtpc_delay = self.send_raw(command)
                if len(data) == 0:
                    data, rtpc_delay = None, None
            except Exception as e:
                dump_exception('Rtp_proxy_client_stream: unhandled exception I/O RTPproxy')
                data, rtpc_delay = None, None
            if result_callback != None:
                ED2.callFromThread(self.dispatch, result_callback, data, callback_parameters)
            if rtpc_delay != None:
                ED2.callFromThread(self.userv.register_delay, rtpc_delay)
        self.userv = None

    def dispatch(self, result_callback, data, callback_parameters):
        try:
            result_callback(data, *callback_parameters)
        except:
            dump_exception('Rtp_proxy_client_stream: unhandled exception when processing RTPproxy reply')

class Rtp_proxy_client_stream(Rtp_proxy_client_net):
    is_local = None
    wi_available = None
    wi = None
    nworkers = None
    nworkers_act = None
    workers = None
    delay_flt = None
    family = None
    sock_type = socket.SOCK_STREAM

    def __init__(self, global_config, address = '/var/run/rtpproxy.sock', \
      bind_address = None, nworkers = 1, family = socket.AF_UNIX):
        #print('Rtp_proxy_client_stream.__init__', address, bind_address, nworkers, family)
        if family == socket.AF_UNIX:
            self.is_local = True
            self.address = address
        else:
            self.is_local = False
            self.address = self.getdestbyaddr(address, family)
        self.family = family
        self.wi_available = Condition()
        self.wi = []
        self.nworkers = nworkers
        self.workers = []
        for i in range(0, self.nworkers):
            try:
                self.workers.append(_RTPPLWorker(self))
            except:
                break
        self.nworkers_act = i + 1
        self.delay_flt = recfilter(0.95, 0.25)

    def send_command(self, command, result_callback = None, *callback_parameters):
        if self.nworkers_act == 0:
            self.rtpp_class._reconnect(self, self.address)
        if isinstance(command, Rtp_proxy_cmd):
            command = str(command)
        elif not command.endswith('\n'):
            command += '\n'
        self.wi_available.acquire()
        self.wi.append((command, result_callback, callback_parameters))
        self.wi_available.notify()
        self.wi_available.release()

    def reconnect(self, address, bind_address = None):
        if not self.is_local:
            address = self.getdestbyaddr(address, family)
        self.rtpp_class._reconnect(self, address, bind_address)

    def _reconnect(self, address, bind_address = None):
        Rtp_proxy_client_stream.shutdown(self)
        self.address = address
        self.workers = []
        for i in range(0, self.nworkers):
            try:
                self.workers.append(_RTPPLWorker(self))
            except:
                break
        self.nworkers_act = i + 1
        self.delay_flt = recfilter(0.95, 0.25)

    def shutdown(self):
        self.wi_available.acquire()
        self.wi.append(None)
        self.wi_available.notify()
        self.wi_available.release()
        for rworker in self.workers:
            rworker.join()
        self.workers = None

    def register_delay(self, rtpc_delay):
        self.delay_flt.apply(rtpc_delay)

    def get_rtpc_delay(self):
        return self.delay_flt.lastval

if __name__ == '__main__':
    class robj(object):
        rval = None
    r = robj()
    def display(res, ro, arg):
        print(res, arg)
        ro.rval = (res, arg)
        ED2.breakLoop()
    r = Rtp_proxy_client_stream({'_sip_address':'1.2.3.4'})
    r.send_command('VF 123456', display, r, 'abcd')
    ED2.loop()
    r.shutdown()
    print(r.rval)
    assert(r.rval == (u'0', 'abcd'))
    print('passed')
