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

from twisted.internet.protocol import Protocol
import sys, traceback

class Cli_session(Protocol):
    command_cb = None
    rbuffer = None
    wbuffer = None
    cb_busy = False
    expect_lf = True

    def __init__(self):
        self.rbuffer = ''
        self.wbuffer = ''

    #def connectionMade(self):
    #    print self.transport.getPeer()
    #    self.transport.loseConnection()

    def dataReceived(self, data):
	#print 'Cli_session::dataReceived', self, data
        if len(data) == 0:
            return
        self.rbuffer += data
        self.pump_rxdata()

    def pump_rxdata(self):
        while self.rbuffer != None and len(self.rbuffer) > 0:
            if self.cb_busy:
                return
            if self.rbuffer.find('\n') == -1 and self.expect_lf:
                return
            parts = self.rbuffer.split('\n', 1)
            if len(parts) == 1:
                parts = (parts[0], '')
            cmd, self.rbuffer = parts
            cmd = cmd.strip()
            if len(cmd) > 0:
                try:
                    self.cb_busy = self.command_cb(self, cmd)
                except:
                    print 'Cli_session: unhandled exception when processing incoming data'
                    print '-' * 70
                    traceback.print_exc(file = sys.stdout)
                    print '-' * 70

    def done(self):
        self.cb_busy = False
        self.pump_rxdata()

    def send(self, data):
        if isinstance(data, unicode):
            data = data.encode('ascii')
        return self.transport.write(data)

    def close(self):
        return self.transport.loseConnection()
