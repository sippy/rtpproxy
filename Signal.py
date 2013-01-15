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
        self.signum = signum
        self.callback = callback
        self.parameters = parameters
        self.previous_handler = signal(signum, self.signal_handler)

    def signal_handler(self, signum, *frame):
        reactor.callFromThread(self.dispatch)
        if self.previous_handler not in (SIG_IGN, SIG_DFL):
            try:
                self.previous_handler(signum, *frame)
            except:
                print datetime.now(), 'Signal: unhandled exception in signal chain'
                print '-' * 70
                print_exc(file = stdout)
                print '-' * 70
                stdout.flush()

    def dispatch(self):
        try:
            self.callback(*self.parameters)
        except:
            print datetime.now(), 'Signal: unhandled exception in signal callback'
            print '-' * 70
            print_exc(file = stdout)
            print '-' * 70
            stdout.flush()

    def cancel(self):
        signal(self.signum, self.previous_handler)
        self.callback = None
        self.parameters = None
        self.previous_handler = None

def log_signal(signum, sip_logger, signal_cb, cb_params):
    sip_logger.write('Dispatching signal %d to handler %s' % (signum, str(signal_cb)))
    return signal_cb(*cb_params)

def LogSignal(sip_logger, signum, signal_cb, *cb_params):
    sip_logger.write('Registering signal %d to handler %s' % (signum, str(signal_cb)))
    return Signal(signum, log_signal, signum, sip_logger, signal_cb, cb_params)

if __name__ == '__main__':
    from signal import SIGHUP, SIGURG, SIGTERM
    from os import kill, getpid

    def test(arguments):
        arguments['test'] = not arguments['test']
        reactor.crash()

    arguments = {'test':False}
    s = Signal(SIGURG, test, arguments)
    kill(getpid(), SIGURG)
    reactor.run()
    assert(arguments['test'])
    s.cancel()
    Signal(SIGHUP, test, arguments)
    kill(getpid(), SIGURG)
    kill(getpid(), SIGHUP)
    reactor.run()
    assert(not arguments['test'])
    from SipLogger import SipLogger
    sip_logger = SipLogger('Signal::selftest')
    LogSignal(sip_logger, SIGTERM, test, arguments)
    kill(getpid(), SIGTERM)
    reactor.run()
    assert(arguments['test'])
