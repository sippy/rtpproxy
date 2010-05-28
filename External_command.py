# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2007 Sippy Software, Inc. All rights reserved.
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

from threading import Condition
from subprocess import Popen, PIPE
from twisted.internet import reactor
from datetime import datetime
from traceback import print_exc
from sys import stdout, platform
from threading import Thread, Lock
from errno import EINTR

_MAX_WORKERS = 20

class _Worker(Thread):
    command = None
    master = None

    def __init__(self, command, master):
        Thread.__init__(self)
        self.command = command
        self.master = master
        self.setDaemon(True)
        self.start()

    def run(self):
        need_close_fds = True
        if platform == 'win32':
            need_close_fds = False
        pipe = Popen(self.command, shell = False, stdin = PIPE, \
          stdout = PIPE, stderr = PIPE, close_fds = need_close_fds)
        while True:
            self.master.work_available.acquire()
            while len(self.master.work) == 0:
                self.master.work_available.wait()
            wi = self.master.work.pop(0)
            if wi == None:
                # Shutdown request, relay it further
                self.master.work.append(None)
                self.master.work_available.notify()
            self.master.work_available.release()
            if wi == None:
                break
            if wi.is_cancelled():
                wi.data = None
                wi.result_callback = None
                wi.callback_parameters = None
                continue
            batch = [x + '\n' for x in wi.data]
            batch.append('\n')
            pipe.stdin.writelines(batch)
            pipe.stdin.flush()
            result = []
            while True:
                try:
                    line = pipe.stdout.readline().strip()
                except IOError, e:
                    # Catch EINTR
                    if e.args[0] != EINTR:
                        raise e
                    continue
                if len(line) == 0:
                    break
                result.append(line)
            reactor.callFromThread(self.master.process_result, wi.result_callback, tuple(result), *wi.callback_parameters)
            wi.data = None
            wi.result_callback = None
            wi.callback_parameters = None

class Work_item(object):
    cancelled = False
    cancelled_lock = None
    # The parameters below once inited should be managed by the worker thread
    data = None
    result_callback = None
    callback_parameters = None

    def __init__(self, data, result_callback, callback_parameters):
        self.data = data
        self.result_callback = result_callback
        self.callback_parameters = callback_parameters
        self.cancelled_lock = Lock()

    def cancel(self):
        self.cancelled_lock.acquire()
        self.cancelled = True
        self.cancelled_lock.release()

    def is_cancelled(self):
        self.cancelled_lock.acquire()
        status = self.cancelled
        self.cancelled_lock.release()
        return status

class External_command(object):
    work_available = None
    work = None

    def __init__(self, command, max_workers = _MAX_WORKERS):
        self.work_available = Condition()
        self.work = []
        for i in range(0, max_workers):
            _Worker(command, self)

    def process_command(self, data, result_callback, *callback_parameters):
        wi = Work_item(tuple(data), result_callback, callback_parameters)
        self.work_available.acquire()
        self.work.append(wi)
        self.work_available.notify()
        self.work_available.release()
        return wi

    def shutdown(self):
        self.work_available.acquire()
        self.work.append(None)
        self.work_available.notify()
        self.work_available.release()

    def process_result(self, result_callback, result, *callback_parameters):
        try:
            result_callback(result, *callback_parameters)
        except:
            print datetime.now(), 'External_command: unhandled exception in external command results callback'
            print '-' * 70
            print_exc(file = stdout)
            print '-' * 70
            stdout.flush()

if __name__ == '__main__':
    from sys import exit
    from time import sleep

    def results_received(results):
        global external_command
        external_command.shutdown()
        # Give threads time to finish
        sleep(0.05)
        if not results == ('foo', 'bar'):
            exit(1)
        reactor.crash()

    external_command = External_command('/bin/cat')
    external_command.process_command(('foo', 'bar'), results_received)
    reactor.run()
