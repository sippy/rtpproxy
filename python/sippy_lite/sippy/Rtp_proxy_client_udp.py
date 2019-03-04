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

from __future__ import print_function

from sippy.Time.Timeout import Timeout
from sippy.Udp_server import Udp_server, Udp_server_opts
from sippy.Time.MonoTime import MonoTime
from sippy.Math.recfilter import recfilter
from sippy.Rtp_proxy_cmd import Rtp_proxy_cmd
from sippy.Rtp_proxy_client_net import Rtp_proxy_client_net

from socket import SOCK_DGRAM, AF_INET
from time import time
from hashlib import md5
from random import random

def getnretrans(first_rert, timeout):
    if first_rert <= 0:
        raise ValueError('getnretrans(%f, %f)' % (first_rert, timeout))
    n = 0
    while True:
        timeout -= first_rert
        if timeout < 0:
            break
        first_rert *= 2.0
        n += 1
    return n

class Rtp_proxy_pending_req(object):
    retransmits = 0
    next_retr = None
    triesleft = None
    timer = None
    command = None
    result_callback = None
    stime = None
    callback_parameters = None

    def __init__(self, next_retr, nretr, timer, command, result_callback, \
      callback_parameters):
        self.stime = MonoTime()
        self.next_retr, self.triesleft, self.timer, self.command, self.result_callback, \
          self.callback_parameters = next_retr, nretr, timer, command, \
          result_callback, callback_parameters

class Rtp_proxy_client_udp(Rtp_proxy_client_net):
    pending_requests = None
    is_local = False
    worker = None
    uopts = None
    global_config = None
    delay_flt = None
    ploss_out_rate = 0.0
    pdelay_out_max = 0.0
    sock_type = SOCK_DGRAM

    def __init__(self, global_config, address, bind_address = None, family = AF_INET, nworkers = None):
        #print('Rtp_proxy_client_udp(family=%s)' % family)
        self.address = self.getdestbyaddr(address, family)
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
        entropy = str(random()) + str(time())
        cookie = md5(entropy.encode()).hexdigest()
        next_retr = self.delay_flt.lastval * 4.0
        exp_time = 3.0
        if isinstance(command, Rtp_proxy_cmd):
            if command.type == 'I':
                exp_time = 10.0
            if command.type == 'G':
                exp_time = 1.0
            nretr = command.nretr
            command = str(command)
        else:
            if command.startswith('I'):
                exp_time = 10.0
            elif command.startswith('G'):
                exp_time = 1.0
            nretr = None
        if nretr == None:
            nretr = getnretrans(next_retr, exp_time)
        command = '%s %s' % (cookie, command)
        timer = Timeout(self.retransmit, next_retr, 1, cookie)
        preq = Rtp_proxy_pending_req(next_retr, nretr - 1, timer, command, \
          result_callback, callback_parameters)
        self.worker.send_to(command, self.address)
        self.pending_requests[cookie] = preq

    def retransmit(self, cookie):
        preq = self.pending_requests[cookie]
        #print('command to %s timeout %s cookie %s triesleft %d' % (str(self.address), preq.command, cookie, preq.triesleft))
        if preq.triesleft <= 0 or self.worker == None:
            del self.pending_requests[cookie]
            self.go_offline()
            if preq.result_callback != None:
                preq.result_callback(None, *preq.callback_parameters)
            return
        preq.retransmits += 1
        preq.next_retr *= 2
        preq.timer = Timeout(self.retransmit, preq.next_retr, 1, cookie)
        self.worker.send_to(preq.command, self.address)
        preq.triesleft -= 1

    def go_offline(self):
        # To be replaced in the upper level class
        pass

    def process_reply(self, data, address, worker, rtime):
        try:
            cookie, result = data.split(None, 1)
        except:
            print('Rtp_proxy_client_udp.process_reply(): invalid response from %s: "%s"' % \
              (str(address), data))
            return
        cookie = cookie.decode()
        preq = self.pending_requests.pop(cookie, None)
        if preq == None:
            return
        preq.timer.cancel()
        if rtime <= preq.stime:
            # MonoTime as the name suggests is supposed to be monotonic,
            # so if we get response earlier than request went out something
            # is very wrong. Fail immediately.
            rtime_fix = MonoTime()
            raise AssertionError('cookie=%s: MonoTime stale/went' \
              ' backwards (%f <= %f, now=%f)' % (cookie, rtime.monot, \
              preq.stime.monot, rtime_fix.monot))
        if preq.result_callback != None:
            result = result.decode()
            preq.result_callback(result.strip(), *preq.callback_parameters)

        # When we had to do retransmit it is not possible to figure out whether
        # or not this reply is related to the original request or one of the
        # retransmits. Therefore, using it to estimate delay could easily produce
        # bogus value that is too low or even negative if we cook up retransmit
        # while the original response is already in the queue waiting to be
        # processed. This should not be a big issue since UDP command channel does
        # not work very well if the packet loss goes to more than 30-40%.
        if preq.retransmits == 0:
            self.delay_flt.apply(rtime - preq.stime)
            #print('Rtp_proxy_client_udp.process_reply(): delay %f' % (rtime - preq.stime))

    def reconnect(self, address, bind_address = None):
        #print('reconnect', address)
        address = self.getdestbyaddr(address, self.uopts.family)
        self.rtpp_class._reconnect(self, address, bind_address)

    def _reconnect(self, address, bind_address = None):
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

from sippy.Core.EventDispatcher import ED2

class selftest(object):

    def gotreply(self, *args):
        print(args)
        ED2.breakLoop()

    def run(self):
        import os
        global_config = {}
        global_config['my_pid'] = os.getpid()
        rtpc = Rtp_proxy_client_udp(global_config, ('127.0.0.1', 22226), None)
        rtpc.rtpp_class = Rtp_proxy_client_udp
        os.system('sockstat | grep -w %d' % global_config['my_pid'])
        rtpc.send_command('Ib', self.gotreply)
        ED2.loop()
        rtpc.reconnect(('localhost', 22226), ('0.0.0.0', 34222))
        os.system('sockstat | grep -w %d' % global_config['my_pid'])
        rtpc.send_command('V', self.gotreply)
        ED2.loop()
        rtpc.reconnect(('localhost', 22226), ('127.0.0.1', 57535))
        os.system('sockstat | grep -w %d' % global_config['my_pid'])
        rtpc.send_command('V', self.gotreply)
        ED2.loop()
        rtpc.shutdown()

if __name__ == '__main__':
    selftest().run()
