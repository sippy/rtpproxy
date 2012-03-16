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

from Timeout import Timeout
from Udp_server import Udp_server

from time import time
from hashlib import md5
from random import random

class Rtp_proxy_client_udp(object):
    pending_requests = None
    is_local = False
    worker = None

    def __init__(self, global_config, address):
        self.address = address
        self.is_local = False
        self.worker = Udp_server(None, self.process_reply)
        self.pending_requests = {}
        self.proxy_address = address[0]

    def send_command(self, command, result_callback = None, *callback_parameters):
        cookie = md5(str(random()) + str(time())).hexdigest()
        command = '%s %s' % (cookie, command)
        timer = Timeout(self.retransmit, 1, -1, cookie)
        self.pending_requests[cookie] = [3, timer, command, result_callback, callback_parameters]
        self.worker.send_to(command, self.address)

    def retransmit(self, cookie):
        triesleft, timer, command, result_callback, callback_parameters = self.pending_requests[cookie]
        if triesleft == 0:
            timer.cancel()
            del self.pending_requests[cookie]
            self.go_offline()
            if result_callback != None:
                result_callback(None, *callback_parameters)
            return
        self.worker.send_to(command, self.address)
        self.pending_requests[cookie][0] -= 1

    def process_reply(self, data, address, worker):
        cookie, result = data.split(None, 1)
        parameters = self.pending_requests.pop(cookie, None)
        if parameters == None:
            return
        parameters[1].cancel()
        if parameters[3] != None:
            parameters[3](result.strip(), *parameters[4])

    def reconnect(self, address):
        self.address = address
