#!/usr/local/bin/python
#
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

from sippy.UA import UA
from sippy.CCEvents import CCEventDisconnect, CCEventTry
from sippy.UaStateDead import UaStateDead
from sippy.SipConf import SipConf
from sippy.SipLogger import SipLogger
from sippy.SipTransactionManager import SipTransactionManager
from sippy.StatefulProxy import StatefulProxy
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

    def recvRequest(self, req):
        if req.getHFBody('to').getTag() != None:
            # Request within dialog, but no such dialog
            return (req.genResponse(481, 'Call Leg/Transaction Does Not Exist'), None, None)
        if req.getMethod() == 'INVITE':
            # New dialog
            cc = CallController(self.global_config)
            return cc.uaA.recvRequest(req)
        if req.getMethod() == 'REGISTER':
            # Registration
            return self.proxy.recvRequest(req)
        if req.getMethod() in ('NOTIFY', 'PING'):
            # Whynot?
            return (req.genResponse(200, 'OK'), None, None)
        return (req.genResponse(501, 'Not Implemented'), None, None)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'fl:p:n:')
    except getopt.GetoptError:
        print 'usage: b2bua.py [-l addr] [-p port] [-n addr] [-f]'
        sys.exit(1)
    laddr = None
    lport = None
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
        #print 'foobar'
        # Fork once
        if os.fork() != 0:
            os._exit(0)
        # Create new session
        os.setsid()
        if os.fork() != 0:
            os._exit(0)
        os.chdir('/')
        fd = os.open('/dev/null', os.O_RDONLY)
        os.dup2(fd, sys.__stdin__.fileno())
        os.close(fd)
        fd = os.open('/var/log/sippy.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        os.dup2(fd, sys.__stdout__.fileno())
        os.dup2(fd, sys.__stderr__.fileno())
        os.close(fd)

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
