# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2014 Sippy Software, Inc. All rights reserved.
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

from Timeout import Timeout
from Udp_server import Udp_server

from time import time
from hashlib import md5
from random import random

class Rtp_proxy_client_udp(object):
    pending_requests = None
    is_local = False
    worker = None
    bind_address = None
    global_config = None

    def __init__(self, global_config, address, bind_address = None, nworkers = None):
        self.address = address
        self.is_local = False
        if nworkers == None:
            self.worker = Udp_server(global_config, bind_address, \
              self.process_reply, flags = 0)
        else:
            self.worker = Udp_server(global_config, bind_address, \
              self.process_reply, flags = 0, nworkers = nworkers)
        self.pending_requests = {}
        self.bind_address = bind_address
        self.global_config = global_config

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

    def reconnect(self, address, bind_address = None):
        self.address = address
        if bind_address != self.bind_address:
            self.worker.shutdown()
            self.worker = Udp_server(self.global_config, bind_address, \
              self.process_reply, flags = 0)
            self.bind_address = bind_address

    def shutdown(self):
        self.worker.shutdown()
        self.worker = None
