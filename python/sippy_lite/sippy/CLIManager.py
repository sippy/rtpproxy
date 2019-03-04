#
# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2017 Sippy Software, Inc. All rights reserved.
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

from os import remove, chown, chmod
import socket
from errno import EPIPE, ENOTCONN, EBADF, ECONNABORTED
from select import poll, POLLIN, POLLNVAL

from threading import Thread, Condition

from sippy.Core.Exceptions import dump_exception
from sippy.Core.EventDispatcher import ED2

try:
    _uobj = unicode
except NameError:
    _uobj = bytes

class _Acceptor(Thread):
    clicm = None
    pollobj = None
    fileno = None

    def __init__(self, clicm):
        Thread.__init__(self)
        self.clicm = clicm
        self.pollobj = poll()
        self.fileno = self.clicm.serversock.fileno()
        self.pollobj.register(self.fileno, POLLIN)
        self.setDaemon(True)
        self.start()

    def run(self):
        #print(self.run, 'enter')
        while True:
            #print(self.run, 'cycle')
            pollret = dict(self.pollobj.poll()).get(self.fileno, 0)
            if pollret & POLLNVAL != 0:
                break
            if pollret & POLLIN == 0:
                continue
            try:
                clientsock, addr = self.clicm.serversock.accept()
            except Exception as why:
                if isinstance(why, socket.error):
                    if why.errno == ECONNABORTED:
                        continue
                    elif why.errno == EBADF:
                        break
                    else:
                        raise
                dump_exception('CLIConnectionManager: unhandled exception when accepting incoming connection')
                break
            #print(self.run, 'handle_accept')
            ED2.callFromThread(self.clicm.handle_accept, clientsock, addr)
        self.clicm = None
        #print(self.run, 'exit')

class CLIConnectionManager(object):
    command_cb = None
    tcp = False
    accept_list = None
    serversock = None
    atr = None

    def __init__(self, command_cb, address = None, sock_owner = None, backlog = 16, \
      tcp = False, sock_mode = None):
        #print(CLIConnectionManager.__init__, ED2)
        self.command_cb = command_cb
        if not tcp:
            self.serversock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        else:
            self.serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp = tcp
        self.serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if address == None:
            if not tcp:
                address = '/var/run/ccm.sock'
            else:
                address = ('127.0.0.1', 22222)
        if not tcp:
            try:
                remove(address)
            except:
                pass
        self.serversock.bind(address)
        if not tcp:
            if sock_owner != None:
                chown(address, sock_owner[0], sock_owner[1])
            if sock_mode != None:
                chmod(address, sock_mode)
        self.serversock.listen(backlog)
        self.atr = _Acceptor(self)

    def handle_accept(self, conn, address):
        #print(self.handle_accept)
        if self.tcp and self.accept_list != None and address[0] not in self.accept_list:
            conn.close()
            return
        try:
            cm = CLIManager(conn, self.command_cb, address)
        except Exception as e:
            dump_exception('CLIConnectionManager: unhandled exception when setting up incoming connection handler')
            conn.close()
            return

    def shutdown(self):
        self.serversock.close()
        self.command_cb = None
        self.atr.join()

class _CLIManager_w(Thread):
    clim = None
    wbuffer = None
    w_available = None
    close_pendind = False

    def __init__(self, clientsock, clim):
        #print(self.__init__)
        Thread.__init__(self)
        self.clientsock = clientsock
        self.clim = clim
        self.w_available = Condition()
        self.wbuffer = bytes()
        self.setDaemon(True)
        self.start()

    def run(self):
        #print(self.run, 'enter')
        while True:
            #print(self.run, 'cycle')
            self.w_available.acquire()
            while self.wbuffer != None and len(self.wbuffer) == 0 and not self.close_pendind:
                self.w_available.wait()
            if self.wbuffer == None:
                self.w_available.release()
                break
            wbuffer = self.wbuffer
            if not self.close_pendind:
                self.wbuffer = bytes()
            else:
                self.wbuffer = None
            self.w_available.release()
            while True:
                res = self.clientsock.send(wbuffer)
                if res == len(wbuffer):
                    break
                if res > 0:
                    wbuffer = wbuffer[res:]
        if self.close_pendind:
            ED2.callFromThread(self.clim.shutdown)
        self.clim = None
        #print(self.run, 'exit')

    def send(self, data):
        self.w_available.acquire()
        if self.wbuffer != None:
            self.wbuffer += data
        self.w_available.notify()
        self.w_available.release()

    def shutdown(self, soft = False):
        self.w_available.acquire()
        if soft:
            self.close_pendind = True
        else:
            self.wbuffer = None
        self.w_available.notify()
        self.w_available.release()

class _CLIManager_r(Thread):
    clim = None

    def __init__(self, clientsock, clim):
        #print(self.__init__)
        Thread.__init__(self)
        self.clientsock = clientsock
        self.clim = clim
        self.setDaemon(True)
        self.start()

    def run(self):
        rbuffer = ''
        while True:
            data = self.clientsock.recv(1024)
            if len(data) == 0:
                ED2.callFromThread(self.clim.shutdown)
                break
            try:
                rbuffer += data.decode('ascii')
            except UnicodeDecodeError:
                ED2.callFromThread(self.clim.shutdown)
                break
            while rbuffer.find('\n') != -1:
                cmd, rbuffer = rbuffer.split('\n', 1)
                cmd = cmd.strip()
                if len(cmd) == 0:
                    continue
                ED2.callFromThread(self.clim.handle_cmd, cmd)
        self.clim = None

class CLIManager(object):
    clientsock = None
    command_cb = None
    close_pendind = False
    raddr = None
    wthr = None
    rthr = None

    def __init__(self, clientsock, command_cb, raddr):
        self.clientsock = clientsock
        self.command_cb = command_cb
        self.raddr = raddr
        self.wthr = _CLIManager_w(clientsock, self)
        self.rthr = _CLIManager_r(clientsock, self)

    def handle_cmd(self, cmd):
        try:
            self.command_cb(self, cmd)
        except:
            dump_exception('CLIManager: unhandled exception when processing incoming data')
            self.close()

    def send(self, data):
        if not isinstance(data, _uobj):
            data = data.encode('ascii')
        self.wthr.send(data)

    def write(self, data):
        return self.send(data)

    def close(self):
        self.wthr.shutdown(soft = True)

    def shutdown(self):
        if self.wthr == None:
            return
        self.wthr.shutdown()
        try:
            self.clientsock.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            if not isinstance(e, socket.error) or e.errno != ENOTCONN:
                dump_exception('self.clientsock.shutdown(socket.SHUT_RDWR)')
        self.clientsock.close()
        self.wthr = None
        self.rthr = None

if __name__ == '__main__':
    def callback(clm, cmd):
        print('in:', cmd)
        clm.send('hello, there!\n')
        clm.close()
        ED2.breakLoop()
    laddr_tcp = ('127.0.0.1', 12345)
    laddr_unix = '/tmp/test.sock'
    f = CLIConnectionManager(callback, laddr_tcp, tcp = True)
    ED2.loop()
    f.shutdown()
    f = CLIConnectionManager(callback, laddr_unix)
    ED2.loop()
    f.shutdown()
