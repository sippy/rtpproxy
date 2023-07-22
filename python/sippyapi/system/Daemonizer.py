# Copyright (c) 2006-2022 Sippy Software, Inc. All rights reserved.
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

import os, sys, signal, socket

class DChildProcessError(ChildProcessError):
    logfile: str

    def __init__(self, *args, logfile = None):
        self.logfile = logfile
        super().__init__(*args)

class Daemonizer():
    amiparent = True
    childpid = None
    ssock = None
    report_token = 'init_ok\n'
    logfile = None
    extra_rsize = 0

    def __init__(self, logfile = None, tweakhup = False):
        if tweakhup:
            old_sighup = signal.getsignal(signal.SIGHUP)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        sp = socket.socketpair()
        # Fork once
        if os.fork() != 0:
            sp[1].close()
            rdata = sp[0].recv(16).decode('ascii')
            estr = F'Invalid/no token returned by a child: {rdata}'
            if len(rdata) != 16:
                raise DChildProcessError(estr) from None
            try:
                self.childpid = int(rdata)
            except ValueError as exc:
                raise DChildProcessError(estr) from None
            self.ssock = sp[0]
            return
        self.amiparent = False
        sp[0].close()
        # Create new session
        os.setsid()
        if os.fork() != 0:
            os._exit(0)
        fd = os.open('/dev/null', os.O_RDWR)
        os.dup2(fd, sys.__stdin__.fileno())
        if logfile != None:
            fake_stdout = open(logfile, 'a', 1)
            sys.stdout = fake_stdout
            sys.stderr = fake_stdout
            fd = fake_stdout.fileno()
            self.logfile = logfile
        os.dup2(fd, sys.__stdout__.fileno())
        os.dup2(fd, sys.__stderr__.fileno())
        if logfile == None:
            os.close(fd)
        if tweakhup:
            signal.signal(signal.SIGHUP, old_sighup)
        self.childpid = os.getpid()
        spid = '%.16d' % (self.childpid,)
        os.chdir('/')
        sp[1].send(spid.encode('ascii'))
        self.ssock = sp[1]
        return

    def waitchild(self):
        assert(self.amiparent)
        status = self.ssock.recv(len(self.report_token) + self.extra_rsize).decode('ascii')
        if self.extra_rsize > 0:
            ext_status = status[-self.extra_rsize:]
            status = status[:-self.extra_rsize]
        if status == self.report_token:
            if self.extra_rsize == 0:
                return status
            return (status, ext_status)
        if status is None:
            estatus = 'NULL'
        else:
            estatus = F'"{status[:-self.extra_rsize]}"'
        report_token = self.report_token
        if report_token[-1] == '\n':
            report_token = report_token[:-1]
        emsg = F'Expected "{report_token}", got {estatus}'
        #sys.stderr.write(emsg + '\n')
        exc = None
        while True:
            try:
                os.kill(self.childpid, signal.SIGTERM)
            except ProcessLookupError:
                break
        raise DChildProcessError(emsg, self.logfile) from None

    def childreport(self, extra = None):
        assert(not self.amiparent)
        assert(extra == None or len(extra) == self.extra_rsize)
        rep = self.report_token
        if extra:
            rep += extra
        self.ssock.send(rep.encode('ascii'))

if __name__ == '__main__':
    dob = Daemonizer()
    if not dob.amiparent:
        from time import sleep
        sleep(5)
        #sys.exit(1)
        dob.childreport('init_ok\n')
        sleep(10)
        sys.exit(1)
    print('Pid: %d' % dob.childpid)
    print('Report: %s' % dob.waitchild('init_ok\n')[:-1])
    os.kill(dob.childpid, signal.SIGTERM)
