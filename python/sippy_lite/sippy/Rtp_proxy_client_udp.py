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
from Udp_server import Udp_server, Udp_server_opts
from Time.MonoTime import MonoTime
from Math.recfilter import recfilter
from Rtp_proxy_cmd import Rtp_proxy_cmd

from time import time
from hashlib import md5
from random import random

def getnretrans(first_rert, timeout):
    n = 0
    while True:
        timeout -= first_rert
        if timeout < 0:
            break
        first_rert *= 2.0
        n += 1
    return n

class Rtp_proxy_client_udp(object):
    pending_requests = None
    is_local = False
    worker = None
    uopts = None
    global_config = None
    delay_flt = None
    ploss_out_rate = 0.0
    pdelay_out_max = 0.0

    def __init__(self, global_config, address, bind_address = None, family = None, nworkers = None):
        self.address = address
        self.is_local = False
        self.uopts = Udp_server_opts(bind_address, self.process_reply, family)
        self.uopts.flags = 0
        self.uopts.ploss_out_rate = self.ploss_out_rate
        self.uopts.pdelay_out_max = self.pdelay_out_max
        if nworkers != None:
            self.uopts.nworkers = nworkers
        self.worker = Udp_server(global_config, self.uopts)
        self.pending_requests = {}
        self.global_config = global_config
        self.delay_flt = recfilter(0.95, 0.25)

    def send_command(self, command, result_callback = None, *callback_parameters):
        cookie = md5(str(random()) + str(time())).hexdigest()
        next_retr = self.delay_flt.lastval * 4.0
        rtime = 3.0
        if isinstance(command, Rtp_proxy_cmd):
            if command.type == 'I':
                rtime = 10.0
            if command.type == 'G':
                rtime = 1.0
            nretr = command.nretr
            command = str(command)
        else:
            if command.startswith('I'):
                rtime = 10.0
            elif command.startswith('G'):
                rtime = 1.0
            nretr = None
        if nretr == None:
            nretr = getnretrans(next_retr, rtime)
        command = '%s %s' % (cookie, command)
        timer = Timeout(self.retransmit, next_retr, 1, cookie)
        stime = MonoTime()
        self.worker.send_to(command, self.address)
        nretr -= 1
        self.pending_requests[cookie] = (next_retr, nretr, timer, command, result_callback, stime, callback_parameters)

    def retransmit(self, cookie):
        next_retr, triesleft, timer, command, result_callback, stime, callback_parameters = self.pending_requests[cookie]
        #print 'command to %s timeout %s cookie %s triesleft %d' % (str(self.address), command, cookie, triesleft)
        if triesleft <= 0 or self.worker == None:
            del self.pending_requests[cookie]
            self.go_offline()
            if result_callback != None:
                result_callback(None, *callback_parameters)
            return
        next_retr *= 2
        timer = Timeout(self.retransmit, next_retr, 1, cookie)
        stime = MonoTime()
        self.worker.send_to(command, self.address)
        triesleft -= 1
        self.pending_requests[cookie] = (next_retr, triesleft, timer, command, result_callback, stime, callback_parameters)

    def process_reply(self, data, address, worker, rtime):
        try:
            cookie, result = data.split(None, 1)
        except:
            print('Rtp_proxy_client_udp.process_reply(): invalid response %s' % data)
            return
        parameters = self.pending_requests.pop(cookie, None)
        if parameters == None:
            return
        next_retr, triesleft, timer, command, result_callback, stime, callback_parameters = parameters
        timer.cancel()
        if result_callback != None:
            result_callback(result.strip(), *callback_parameters)
        self.delay_flt.apply(rtime - stime)
        #print 'Rtp_proxy_client_udp.process_reply(): delay %f' % (rtime - stime)

    def reconnect(self, address, bind_address = None):
        self.address = address
        if bind_address != self.uopts.laddress:
            self.uopts.laddress = bind_address
            self.worker.shutdown()
            self.worker = Udp_server(self.global_config, self.uopts)
            self.delay_flt = recfilter(0.95, 0.25)

    def shutdown(self):
        self.worker.shutdown()
        self.worker = None

    def get_rtpc_delay(self):
        return self.delay_flt.lastval

class selftest(object):
    def gotreply(self, *args):
        from twisted.internet import reactor
        print args
        reactor.crash()

    def run(self):
        import os
        from twisted.internet import reactor
        global_config = {}
        global_config['my_pid'] = os.getpid()
        rtpc = Rtp_proxy_client_udp(global_config, ('127.0.0.1', 22226), None)
        os.system('sockstat | grep -w %d' % global_config['my_pid'])
        rtpc.send_command('Ib', self.gotreply)
        reactor.run()
        rtpc.reconnect(('localhost', 22226), ('0.0.0.0', 34222))
        os.system('sockstat | grep -w %d' % global_config['my_pid'])
        rtpc.send_command('V', self.gotreply)
        reactor.run()
        rtpc.reconnect(('localhost', 22226), ('127.0.0.1', 57535))
        os.system('sockstat | grep -w %d' % global_config['my_pid'])
        rtpc.send_command('V', self.gotreply)
        reactor.run()
        rtpc.shutdown()

if __name__ == '__main__':
    selftest().run()
