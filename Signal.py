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

from signal import signal, SIG_IGN, SIG_DFL
from twisted.internet import reactor
from datetime import datetime
from traceback import print_exc
from sys import stdout

class Signal(object):
    callback = None
    parameters = None
    previous_handler = None

    def __init__(self, signum, callback, *parameters):
        self.callback = callback
        self.parameters = parameters
        self.previous_handler = signal(signum, self.signal_handler)

    def signal_handler(self, signum, *frame):
        try:
            reactor.callFromThread(self.callback, *self.parameters)
        except:
            print datetime.now(), 'Signal: unhandled exception in signal callback'
            print '-' * 70
            print_exc(file = stdout)
            print '-' * 70
            stdout.flush()
        if self.previous_handler not in (SIG_IGN, SIG_DFL):
            try:
                self.previous_handler(signum, *frame)
            except:
                print datetime.now(), 'Signal: unhandled exception in signal chain'
                print '-' * 70
                print_exc(file = stdout)
                print '-' * 70
                stdout.flush()

if __name__ == '__main__':
    from signal import SIGHUP
    from os import kill, getpid

    def test(arguments):
        arguments['test'] = True
        reactor.crash()

    arguments = {'test':False}
    Signal(SIGHUP, test, arguments)
    kill(getpid(), SIGHUP)
    reactor.run()
    assert(arguments['test'])
