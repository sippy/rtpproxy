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
from Rtp_proxy_client_udp import Rtp_proxy_client_udp
from Rtp_proxy_client_local import Rtp_proxy_client_local

from time import time
from hashlib import md5
from random import random

def randomize(x, p):
    return x * (1.0 + p * (1.0 - 2.0 * random()))

class Rtp_proxy_client(Rtp_proxy_client_udp, Rtp_proxy_client_local):
    worker = None
    address = None
    online = False
    copy_supported = False
    stat_supported = False
    tnot_supported = False
    sbind_supported = False
    shutdown = False
    proxy_address = None
    caps_done = False
    sessions_created = None
    active_sessions = None
    active_streams = None
    preceived = None
    ptransmitted = None

    def __init__(self, global_config, *address, **kwargs):
        #print 'Rtp_proxy_client', address
        if len(address) > 0 and type(address[0]) in (tuple, list):
            Rtp_proxy_client_udp.__init__(self, global_config, *address, \
              **kwargs)
            self.proxy_address = address[0]
        else:            
            Rtp_proxy_client_local.__init__(self, global_config, *address, \
              **kwargs)
            self.proxy_address = global_config['_sip_address']
        self.version_check()

    def send_command(self, *args, **kwargs):
        if self.is_local:
            Rtp_proxy_client_local.send_command(self, *args, **kwargs)
        else:
            Rtp_proxy_client_udp.send_command(self, *args, **kwargs)

    def caps_query1(self, result):
        #print '%s.caps_query1(%s)' % (id(self), result)
        if self.shutdown:
            if self.worker != None:
                self.worker.shutdown()
                self.worker = None
            return
        if not self.online:
            return
        if result != '1':
            if result != None:
                self.copy_supported = False
                self.stat_supported = False
                self.tnot_supported = False
                self.sbind_supported = False
                self.caps_done = True
            return
        self.copy_supported = True
        self.send_command('VF 20080403', self.caps_query2)

    def caps_query2(self, result):
        #print '%s.caps_query2(%s)' % (id(self), result)
        if self.shutdown:
            if self.worker != None:
                self.worker.shutdown()
                self.worker = None
            return
        if not self.online:
            return
        if result != None:
            if result == '1':
                self.stat_supported = True
                self.send_command('VF 20081224', self.caps_query3)
                return
            else:
                self.stat_supported = False
                self.tnot_supported = False
                self.sbind_supported = False
                self.caps_done = True

    def caps_query3(self, result):
        #print '%s.caps_query3(%s)' % (id(self), result)
        if self.shutdown:
            if self.worker != None:
                self.worker.shutdown()
                self.worker = None
            return
        if not self.online:
            return
        if result != None:
            if result == '1':
                self.tnot_supported = True
            else:
                self.tnot_supported = False
            self.send_command('VF 20090810', self.caps_query4)
            return

    def caps_query4(self, result):
        #print '%s.caps_query4(%s)' % (id(self), result)
        if self.shutdown:
            if self.worker != None:
                self.worker.shutdown()
                self.worker = None
            return
        if not self.online:
            return
        if result != None:
            if result == '1':
                self.sbind_supported = True
            else:
                self.sbind_supported = False
            self.caps_done = True

    def version_check(self):
        self.send_command('V', self.version_check_reply)

    def version_check_reply(self, version):
        if self.shutdown:
            if self.worker != None:
                self.worker.shutdown()
                self.worker = None
            return
        if version == '20040107':
            self.go_online()
        elif self.online:
            self.go_offline()
        else:
            Timeout(self.version_check, randomize(60, 0.1))

    def heartbeat(self):
        #print 'heartbeat', self, self.address
        self.send_command('Ib', self.heartbeat_reply)

    def heartbeat_reply(self, stats):
        #print 'heartbeat_reply', self.address, stats, self.online
        if self.shutdown:
            if self.worker != None:
                self.worker.shutdown()
                self.worker = None
            return
        if not self.online:
            return
        if stats == None:
            self.active_sessions = None
            self.go_offline()
        else:
            sessions_created = active_sessions = active_streams = preceived = ptransmitted = 0
            for line in stats.splitlines():
                line_parts = line.split(':', 1)
                if line_parts[0] == 'sessions created':
                    sessions_created = int(line_parts[1])
                elif line_parts[0] == 'active sessions':
                    active_sessions = int(line_parts[1])
                elif line_parts[0] == 'active streams':
                    active_streams = int(line_parts[1])
                elif line_parts[0] == 'packets received':
                    preceived = int(line_parts[1])
                elif line_parts[0] == 'packets transmitted':
                    ptransmitted = int(line_parts[1])
                self.update_active(active_sessions, sessions_created, active_streams, preceived, ptransmitted)
        Timeout(self.heartbeat, randomize(10, 0.1))

    def go_online(self):
        if not self.online:
            self.caps_done = False
            self.send_command('VF 20071218', self.caps_query1)
            self.online = True
            self.heartbeat()

    def go_offline(self):
        #print 'go_offline', self.address, self.online
        if self.online:
            self.online = False
            Timeout(self.version_check, randomize(60, 0.1))

    def update_active(self, active_sessions, sessions_created, active_streams, preceived, ptransmitted):
        self.sessions_created = sessions_created
        self.active_sessions = active_sessions
        self.active_streams = active_streams
        self.preceived = preceived
        self.ptransmitted = ptransmitted
