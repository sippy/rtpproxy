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
#
# $Id: Rtp_proxy_client_udp.py,v 1.6 2009/08/15 22:04:17 sobomax Exp $

from Timeout import Timeout
from Udp_server import Udp_server

from time import time
from md5 import md5
from random import random

class Rtp_proxy_client_udp(object):
    udp_server = None
    pending_requests = None
    address = None
    online = False
    copy_supported = False
    stat_supported = False
    tnot_supported = False
    shutdown = False
    proxy_address = None
    caps_done = False
    is_local = False

    def __init__(self, global_config, address):
        self.udp_server = Udp_server(None, self.process_reply)
        self.pending_requests = {}
        self.address = address
        self.proxy_address = address[0]
        self.heartbeat()

    def send_command(self, command, result_callback = None, *callback_parameters):
        cookie = md5(str(random()) + str(time())).hexdigest()
        command = '%s %s' % (cookie, command)
        timer = Timeout(self.retransmit, 1, -1, cookie)
        self.pending_requests[cookie] = [3, timer, command, result_callback, callback_parameters]
        self.udp_server.send_to(command, self.address)

    def retransmit(self, cookie):
        triesleft, timer, command, result_callback, callback_parameters = self.pending_requests[cookie]
        if triesleft == 0:
            timer.cancel()
            del self.pending_requests[cookie]
            self.online = False
            if result_callback != None:
                result_callback(None, *callback_parameters)
            return
        self.udp_server.send_to(command, self.address)
        self.pending_requests[cookie][0] -= 1

    def process_reply(self, data, address, udp_server):
        cookie, result = data.split(None, 1)
        parameters = self.pending_requests.pop(cookie, None)
        if parameters == None:
            return
        parameters[1].cancel()
        if parameters[3] != None:
            parameters[3](result.strip(), *parameters[4])

    def caps_query1(self, result):
        if self.shutdown:
            return
        if result != '1':
            if result != None:
                self.copy_supported = False
                self.stat_supported = False
                self.tnot_supported = False
                self.caps_done = True
            Timeout(self.heartbeat, 60)
            return
        self.copy_supported = True
        self.send_command('VF 20080403', self.caps_query2)

    def caps_query2(self, result):
        if self.shutdown:
            return
        if result != None:
            if result == '1':
                self.stat_supported = True
                self.send_command('VF 20081224', self.caps_query3)
                return
            else:
                self.stat_supported = False
                self.tnot_supported = False
                self.caps_done = True
        Timeout(self.heartbeat, 60)

    def caps_query3(self, result):
        if self.shutdown:
            return
        if result != None:
            if result == '1':
                self.tnot_supported = True
            else:
                self.tnot_supported = False
            self.caps_done = True
        Timeout(self.heartbeat, 60)

    def heartbeat(self):
        self.send_command('V', self.heartbeat_reply)

    def heartbeat_reply(self, version):
        if self.shutdown:
            return
        if version == '20040107':
            self.online = True
            if not self.caps_done:
                self.send_command('VF 20071218', self.caps_query1)
                return
        else:
            self.online = False
        Timeout(self.heartbeat, 60)
