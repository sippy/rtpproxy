# Copyright (c) 2015 Sippy Software, Inc. All rights reserved.
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

import sys
import getopt
from signal import SIGTERM

from sippyapi.system.Daemonizer import Daemonizer

DEFAULT_RTPP_SPATH = 'unix:/var/run/rtpproxy.sock'

def usage():
    sys.stderr.write('usage: rtpp_notify_client.py [-s unix:path|tcp:IP:port] ' \
      '[-S sippy_root_path] [-o outfile] [-t timeout] [-D] [-l logfile] [-P] [-G]\n')
    sys.exit(1)

class cli_handler(object):
    file_out = None
    rval = 0
    exception = None

    def __init__(self, file_out):
        self.file_out = file_out

    def command_received(self, x, clm, cmd):
        from sippy.Core.EventDispatcher import ED2
        try:
            self.file_out.write('%s\n' % (cmd,))
            self.file_out.flush()
        except Exception as ex:
            self.rval = 1
            clm.shutdown()
            ED2.breakLoop()
            self.exception = ex
            return

    def done(self):
        from sippy.Core.EventDispatcher import ED2
        ED2.breakLoop()

def collect_glitches(address, file_out, timeout, ready):
    """Collect newline-delimited reports without per-connection threads."""
    import selectors
    import signal
    import socket
    import time

    stopped = False
    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    old_handler = signal.signal(SIGTERM, stop)
    deadline = None if timeout is None else time.monotonic() + timeout
    with selectors.DefaultSelector() as selector, \
      socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(tuple(address))
            server.listen(socket.SOMAXCONN)
            server.setblocking(False)
            selector.register(server, selectors.EVENT_READ)
            ready(server.getsockname()[1])
            while not stopped:
                delay = 0.25
                if deadline is not None:
                    delay = min(delay, deadline - time.monotonic())
                    if delay <= 0:
                        break
                for key, _ in selector.select(delay):
                    conn = key.fileobj
                    if conn is server:
                        while True:
                            try:
                                client, _ = server.accept()
                            except BlockingIOError:
                                break
                            except ConnectionAbortedError:
                                continue
                            client.setblocking(False)
                            try:
                                selector.register(client, selectors.EVENT_READ, bytearray())
                            except BaseException:
                                client.close()
                                raise
                        continue
                    try:
                        data = conn.recv(65536)
                    except BlockingIOError:
                        continue
                    except (ConnectionResetError, ConnectionAbortedError):
                        data = b''
                    if not data:
                        selector.unregister(conn)
                        conn.close()
                        continue
                    buffer = key.data
                    buffer.extend(data)
                    while b'\n' in buffer:
                        line, _, rest = buffer.partition(b'\n')
                        file_out.write(line.decode() + '\n')
                        buffer[:] = rest
                    file_out.flush()
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            signal.signal(SIGTERM, old_handler)

def main():
    spath = DEFAULT_RTPP_SPATH
    stype = 'unix'
    sippy_path = None
    file_out = sys.stdout
    timeout = None
    daemonize = False
    logfile = None
    print_port = False
    glitch_mode = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:o:t:Dl:PG')
    except getopt.GetoptError:
        usage()

    for o, a in opts:
        if o == '-s':
            spath = a.strip()
            if spath.startswith('unix:'):
                spath = spath[5:]
                stype = 'unix'
            elif spath.startswith('tcp:'):
                spath = spath[4:].split(':', 1)
                if len(spath) != 2:
                    raise ValueError('TCP listening socket not in the form "IP:port": ' + spath[0])
                spath[1] = int(spath[1])
                if spath[1] < 0 or spath[1] > 65535:
                    raise ValueError('TCP listening port not in the range 0-65535: %d' % spath[1])
                stype = 'tcp'
            continue
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-o':
           fname = a.strip()
           if fname == '-':
               file_out = sys.stdout
           else:
               file_out = open(fname, 'w')
        if o == '-t':
           timeout = float(a.strip())
           continue
        if o == '-D':
           daemonize = True
           continue
        if o == '-P':
           print_port = True
           continue
        if o == '-G':
            glitch_mode = True
            continue
        if o == '-l':
           logfile = a

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    if glitch_mode and stype != 'tcp':
        raise ValueError('glitch collection requires a TCP listening socket')
    if not glitch_mode:
        from sippy.CLIManager import CLIConnectionManager
        from sippy.Time.Timeout import Timeout
        from sippy.Core.EventDispatcher import ED2

    if daemonize:
        dob = Daemonizer(logfile = logfile)
        if stype != 'unix':
            dob.extra_rsize = 5
        if dob.amiparent:
            portnum = dob.waitchild()
            out = F'{dob.childpid}'
            if stype != 'unix' and spath[1] == 0:
                out += F' {portnum[1]}'
            print(out)
            sys.exit(0)

    if glitch_mode:
        def ready(port):
            if daemonize:
                dob.childreport(str(port))
            elif print_port:
                print(port, flush=True)
        collect_glitches(spath, file_out, timeout, ready)
        return

    ch = cli_handler(file_out)
    if stype == 'unix':
        rep = lambda x, y: ch.command_received(spath, x, y)
        cs = CLIConnectionManager(rep, spath, tcp = False)
    else:
        rep = lambda x, y: ch.command_received(spath[0], x, y)
        cs = CLIConnectionManager(rep, tuple(spath), tcp = True)
    if timeout != None:
        Timeout(ch.done, timeout)
    ED2.regSignal(SIGTERM, ch.done)
    if daemonize:
        if stype == 'unix':
            pnum = None
        else:
            port = cs.serversock.getsockname()[1]
            pnum = f'{port}'
        dob.childreport(pnum)
    elif print_port and stype != 'unix':
        # Report the port allocated, e.g. when started with port 0
        print(cs.serversock.getsockname()[1], flush = True)
    ED2.loop()
    if ch.exception is not None:
        raise ch.exception
    sys.exit(ch.rval)

if __name__ == '__main__':
    main()
