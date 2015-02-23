#!/usr/bin/env python2
#
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

from sippy.UA import UA
from sippy.CCEvents import CCEventDisconnect, CCEventTry
from sippy.UaStateDead import UaStateDead
from sippy.SipConf import SipConf
from sippy.SipLogger import SipLogger
from sippy.SipTransactionManager import SipTransactionManager
from sippy.StatefulProxy import StatefulProxy
from sippy.misc import daemonize
from twisted.internet import reactor
import getopt, os, sys
#import gc

class CallController(object):
    global_config = None
    uaA = None
    uaO = None
    nh_addr = None

    def __init__(self, global_config):
        self.global_config = global_config
        self.uaA = UA(self.global_config, self.recvEvent)
        self.uaO = None

    def recvEvent(self, event, ua):
        if ua == self.uaA:
            if self.uaO == None:
                if not isinstance(event, CCEventTry):
                    # Some weird event received
                    self.uaA.recvEvent(CCEventDisconnect())
                    return
                self.uaO = UA(self.global_config, event_cb = self.recvEvent, \
                  nh_address = self.global_config['nh_addr'])
            self.uaO.recvEvent(event)
        else:
            self.uaA.recvEvent(event)

class CallMap(object):
    global_config = None
    proxy = None
    #rc1 = None
    #rc2 = None

    def __init__(self, global_config):
        self.global_config = global_config
        self.proxy = StatefulProxy(global_config, self.global_config['nh_addr'])
        #gc.disable()
        #gc.set_debug(gc.DEBUG_STATS)
        #gc.set_threshold(0)
        #print gc.collect()

    def recvRequest(self, req, sip_t):
        if req.getHFBody('to').getTag() != None:
            # Request within dialog, but no such dialog
            return (req.genResponse(481, 'Call Leg/Transaction Does Not Exist'), None, None)
        if req.getMethod() == 'INVITE':
            # New dialog
            cc = CallController(self.global_config)
            return cc.uaA.recvRequest(req, sip_t)
        if req.getMethod() == 'REGISTER':
            # Registration
            return self.proxy.recvRequest(req)
        if req.getMethod() in ('NOTIFY', 'PING'):
            # Whynot?
            return (req.genResponse(200, 'OK'), None, None)
        return (req.genResponse(501, 'Not Implemented'), None, None)

def main_func():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'fl:p:n:L:')
    except getopt.GetoptError:
        print('usage: b2bua.py [-l addr] [-p port] [-n addr] [-f] [-L logfile]')
        sys.exit(1)
    laddr = None
    lport = None
    logfile = '/var/log/sippy.log'
    global_config = {'nh_addr':['192.168.0.102', 5060]}
    foreground = False
    for o, a in opts:
        if o == '-f':
            foreground = True
            continue
        if o == '-l':
            laddr = a
            continue
        if o == '-p':
            lport = int(a)
            continue
        if o == '-L':
            logfile = a
        if o == '-n':
            if a.startswith('['):
                parts = a.split(']', 1)
                global_config['nh_addr'] = [parts[0] + ']', 5060]
                parts = parts[1].split(':', 1)
            else:
                parts = a.split(':', 1)
                global_config['nh_addr'] = [parts[0], 5060]
            if len(parts) == 2:
                global_config['nh_addr'][1] = int(parts[1])
            continue
    global_config['nh_addr'] = tuple(global_config['nh_addr'])

    if not foreground:
        daemonize(logfile)

    SipConf.my_uaname = 'Sippy B2BUA (Simple)'
    SipConf.allow_formats = (0, 8, 18, 100, 101)
    global_config['_sip_address'] = SipConf.my_address
    global_config['_sip_port'] = SipConf.my_port
    if laddr != None:
        global_config['_sip_address'] = laddr
    if lport != None:
        global_config['_sip_port'] = lport
    global_config['_sip_logger'] = SipLogger('b2bua')

    cmap = CallMap(global_config)

    global_config['_sip_tm'] = SipTransactionManager(global_config, cmap.recvRequest)

    reactor.run(installSignalHandlers = True)

if __name__ == '__main__':
    main_func()

