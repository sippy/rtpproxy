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

from twisted.internet.protocol import Factory
from twisted.internet import reactor
from Cli_session import Cli_session
from os import chown, unlink
from os.path import exists

class Cli_server_local(Factory):
    command_cb = None

    def __init__(self, command_cb, address = None, sock_owner = None):
        self.command_cb = command_cb
        self.protocol = Cli_session
        if address == None:
            address = '/var/run/ccm.sock'
        if exists(address):
            unlink(address)
        reactor.listenUNIX(address, self)
        if sock_owner != None:
            chown(address, sock_owner[0], sock_owner[1])

    def buildProtocol(self, addr):
        p = Factory.buildProtocol(self, addr)
        p.command_cb = self.command_cb
        return p

if __name__ == '__main__':
    def callback(clm, cmd):
        print cmd
        return False
    f = Cli_server_local(callback)
    reactor.run()
