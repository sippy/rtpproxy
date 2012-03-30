# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
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

from Timeout import Timeout
from threading import Thread, Condition
from errno import EINTR
from twisted.internet import reactor

import socket

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
            except:
                data = None
            if result_callback != None:
                reactor.callFromThread(result_callback, data, *callback_parameters)
        self.userv = None

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

    def __init__(self, global_config, address = '/var/run/rtpproxy.sock'):
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

    def reconnect(self, address):
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
