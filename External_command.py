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
#
# $Id: External_command.py,v 1.1 2007/09/18 06:49:11 sobomax Exp $

from threading import Condition
from popen2 import Popen3
from twisted.internet import reactor
from datetime import datetime
from traceback import print_exc
from sys import stdout

MAX_WORKERS = 5

class _Worker:
    command = None
    master = None

    def __init__(self, command, master):
        self.command = command
        self.master = master

    def do_work(self):
        pipe = Popen3(self.command, True)
        while True:
            self.master.work_available.acquire()
            while len(self.master.work) == 0:
                self.master.work_available.wait()
            data, result_callback, callback_parameters = self.master.work.pop(0)
            self.master.work_available.release()
            batch = map(lambda x: x + '\n', data)
            batch.append('\n')
            pipe.tochild.writelines(batch)
            pipe.tochild.flush()
            result = []
            while True:
                line = pipe.fromchild.readline().strip()
                if len(line) == 0:
                    break
                result.append(line)
            reactor.callFromThread(self.master.process_result, result_callback, tuple(result), *callback_parameters)

class External_command:
    work_available = None
    work = None

    def __init__(self, command):
        self.work_available = Condition()
        self.work = []
        for i in range(0, MAX_WORKERS):
            reactor.callInThread(_Worker(command, self).do_work)

    def process_command(self, data, result_callback, *callback_parameters):
        self.work_available.acquire()
        self.work.append((tuple(data), result_callback, callback_parameters))
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

    def results_received(results):
        if not results == ('foo', 'bar'):
            exit(1)
        reactor.crash()

    external_command = External_command('/bin/cat')
    external_command.process_command(('foo', 'bar'), results_received)
    reactor.run(installSignalHandlers = 0)
