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

from Timeout import Timeout
from threading import Thread, Condition
from errno import EINTR
from twisted.internet import reactor

from datetime import datetime
import socket
import sys, traceback

class _RTPPLWorker(Thread):
    userv = None

    def __init__(self, userv):
        Thread.__init__(self)
        self.userv = userv
        self.setDaemon(True)
        self.start()

    def send_raw(self, command):
        if not command.endswith('\n'):
            command += '\n'
        #print '%s.send_raw(%s)' % (id(self), command)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.userv.address)
        while True:
            try:
                s.send(command)
                break
            except socket.error, why:
                if why[0] == EINTR:
                    continue
                raise why
        while True:
            try:
                rval = s.recv(1024).strip()
                break
            except socket.error, why:
                if why[0] == EINTR:
                    continue
                raise why
        return rval

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
            command, result_callback, callback_parameters = wi
            try:
                data = self.send_raw(command)
                if len(data) == 0:
                    data = None
            except:
                data = None
            if result_callback != None:
                reactor.callFromThread(self.dispatch, result_callback, data, callback_parameters)
        self.userv = None

    def dispatch(self, result_callback, data, callback_parameters):
        try:
            result_callback(data, *callback_parameters)
        except:
            print datetime.now(), 'Rtp_proxy_client_local: unhandled exception when processing RTPproxy reply'
            print '-' * 70
            traceback.print_exc(file = sys.stdout)
            print '-' * 70
            sys.stdout.flush()

    def shutdown(self):
        self.userv.wi_available.acquire()
        self.userv.wi.append(None)
        self.userv.wi_available.notify()
        self.userv.wi_available.release()

class Rtp_proxy_client_local(object):
    is_local = True
    wi_available = None
    wi = None
    worker = None

    def __init__(self, global_config, address = '/var/run/rtpproxy.sock', \
      bind_address = None):
        self.address = address
        self.is_local = True
        self.proxy_address = global_config['_sip_address']
        self.wi_available = Condition()
        self.wi = []
        self.worker = _RTPPLWorker(self)

    def send_command(self, command, result_callback = None, *callback_parameters):
        self.wi_available.acquire()
        self.wi.append((command, result_callback, callback_parameters))
        self.wi_available.notify()
        self.wi_available.release()

    def reconnect(self, address, bind_address = None):
        self.worker.shutdown()
        self.address = address
        self.worker = _RTPPLWorker(self)

if __name__ == '__main__':
    def display(*args):
        print args
    r = Rtp_proxy_client_local({'_sip_address':'1.2.3.4'})
    r.send_command('VF 123456', display, 'abcd')
    from twisted.internet import reactor
    reactor.run(installSignalHandlers = 1)
