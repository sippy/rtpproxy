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

from sippy.Time.Timeout import TimeoutInact
from sippy.Rtp_proxy_client_udp import Rtp_proxy_client_udp
from sippy.Rtp_proxy_client_stream import Rtp_proxy_client_stream

import socket

CAPSTABLE = {'20071218':'copy_supported', '20080403':'stat_supported', \
  '20081224':'tnot_supported', '20090810':'sbind_supported', \
  '20150617':'wdnt_supported'}

class Rtpp_caps_checker(object):
    caps_requested = 0
    caps_received = 0
    rtpc = None

    def __init__(self, rtpc):
        self.rtpc = rtpc
        rtpc.caps_done = False
        for vers in CAPSTABLE.keys():
            self.caps_requested += 1
            rtpc.send_command('VF %s' % vers, self.caps_query_done, vers)

    def caps_query_done(self, result, vers):
        self.caps_received += 1
        vname = CAPSTABLE[vers]
        if result == '1':
            setattr(self.rtpc, vname, True)
        else:
            setattr(self.rtpc, vname, False)
        if self.caps_received == self.caps_requested:
            self.rtpc.caps_done = True
            self.rtpc.go_online()
            self.rtpc = None

class Rtp_proxy_client(Rtp_proxy_client_udp, Rtp_proxy_client_stream):
    worker = None
    address = None
    online = False
    copy_supported = False
    stat_supported = False
    tnot_supported = False
    sbind_supported = False
    wdnt_supported = False
    shut_down = False
    proxy_address = None
    caps_done = False
    sessions_created = None
    active_sessions = None
    active_streams = None
    preceived = None
    ptransmitted = None
    hrtb_ival = 1.0
    hrtb_retr_ival = 60.0
    rtpp_class = None

    def __init__(self, global_config, *address, **kwargs):
        #print 'Rtp_proxy_client', address
        no_version_check = False
        if 'no_version_check' in kwargs:
            no_version_check = kwargs['no_version_check']
            del kwargs['no_version_check']
        if len(address) == 0 and 'spath' in kwargs:
            a = kwargs['spath']
            del kwargs['spath']
            if a.startswith('udp:'):
                a = a.split(':', 2)
                if len(a) == 2:
                    rtppa = (a[1], 22222)
                else:
                    rtppa = (a[1], int(a[2]))
                self.proxy_address = rtppa[0]
                kwargs['family'] = socket.AF_INET
                self.rtpp_class = Rtp_proxy_client_udp
            elif a.startswith('udp6:'):
                proto, a = a.split(':', 1)
                if not a.endswith(']'):
                    a = a.rsplit(':', 1)
                    if len(a) == 1:
                        rtp_proxy_host, rtp_proxy_port = a[0], 22222
                    else:
                        rtp_proxy_host, rtp_proxy_port = (a[0], int(a[1]))
                else:
                    rtp_proxy_host, rtp_proxy_port = a, 22222
                if not rtp_proxy_host.startswith('['):
                    rtp_proxy_host = '[%s]' % rtp_proxy_host
                rtppa = (rtp_proxy_host, rtp_proxy_port)
                self.proxy_address = rtppa[0]
                kwargs['family'] = socket.AF_INET6
                self.rtpp_class = Rtp_proxy_client_udp
            elif a.startswith('tcp:'):
                a = a.split(':', 2)
                if len(a) == 2:
                    rtppa = (a[1], 22222)
                else:
                    rtppa = (a[1], int(a[2]))
                self.proxy_address = rtppa[0]
                kwargs['family'] = socket.AF_INET
                self.rtpp_class = Rtp_proxy_client_stream
            elif a.startswith('tcp6:'):
                proto, a = a.split(':', 1)
                if not a.endswith(']'):
                    a = a.rsplit(':', 1)
                    if len(a) == 1:
                        rtp_proxy_host, rtp_proxy_port = a[0], 22222
                    else:
                        rtp_proxy_host, rtp_proxy_port = (a[0], int(a[1]))
                else:
                    rtp_proxy_host, rtp_proxy_port = a, 22222
                if not rtp_proxy_host.startswith('['):
                    rtp_proxy_host = '[%s]' % rtp_proxy_host
                rtppa = (rtp_proxy_host, rtp_proxy_port)
                self.proxy_address = rtppa[0]
                kwargs['family'] = socket.AF_INET6
                self.rtpp_class = Rtp_proxy_client_stream
            else:
                if a.startswith('unix:'):
                    rtppa = a[5:]
                elif a.startswith('cunix:'):
                    rtppa = a[6:]
                else:
                    rtppa = a
                self.proxy_address = global_config['_sip_address']
                kwargs['family'] = socket.AF_UNIX
                self.rtpp_class = Rtp_proxy_client_stream
            self.rtpp_class.__init__(self, global_config, rtppa, **kwargs)
        elif len(address) > 0 and type(address[0]) in (tuple, list):
            self.rtpp_class = Rtp_proxy_client_udp
            self.proxy_address = address[0][0]
            Rtp_proxy_client_udp.__init__(self, global_config, *address, \
              **kwargs)
        else:
            self.rtpp_class = Rtp_proxy_client_stream
            self.proxy_address = global_config['_sip_address']
            Rtp_proxy_client_stream.__init__(self, global_config, *address, \
              **kwargs)
        if not no_version_check:
            self.version_check()
        else:
            self.caps_done = True
            self.online = True

    def send_command(self, *args, **kwargs):
        self.rtpp_class.send_command(self, *args, **kwargs)

    def reconnect(self, *args, **kwargs):
        self.rtpp_class.reconnect(self, *args, **kwargs)

    def version_check(self):
        if self.shut_down:
            return
        self.send_command('V', self.version_check_reply)

    def version_check_reply(self, version):
        if self.shut_down:
            return
        if version == '20040107':
            self.go_online()
        elif self.online:
            self.go_offline()
        else:
            to = TimeoutInact(self.version_check, self.hrtb_retr_ival)
            to.spread_runs(0.1)
            to.go()

    def heartbeat(self):
        #print 'heartbeat', self, self.address
        if self.shut_down:
            return
        self.send_command('Ib', self.heartbeat_reply)

    def heartbeat_reply(self, stats):
        #print 'heartbeat_reply', self.address, stats, self.online
        if self.shut_down:
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
        to = TimeoutInact(self.heartbeat, self.hrtb_ival)
        to.spread_runs(0.1)
        to.go()

    def go_online(self):
        if self.shut_down:
            return
        if not self.online:
            if not self.caps_done:
                rtpp_cc = Rtpp_caps_checker(self)
                return
            self.online = True
            self.heartbeat()

    def go_offline(self):
        if self.shut_down:
            return
        #print 'go_offline', self.address, self.online
        if self.online:
            self.online = False
            to = TimeoutInact(self.version_check, self.hrtb_retr_ival)
            to.spread_runs(0.1)
            to.go()

    def update_active(self, active_sessions, sessions_created, active_streams, preceived, ptransmitted):
        self.sessions_created = sessions_created
        self.active_sessions = active_sessions
        self.active_streams = active_streams
        self.preceived = preceived
        self.ptransmitted = ptransmitted

    def shutdown(self):
        if self.shut_down: # do not crash when shutdown() called twice
            return
        self.shut_down = True
        self.rtpp_class.shutdown(self)
        self.rtpp_class = None

    def get_rtpc_delay(self):
        return self.rtpp_class.get_rtpc_delay(self)

if __name__ == '__main__':
    from sippy.Core.EventDispatcher import ED2
    from sippy.Time.Timeout import Timeout
    def display(*args):
        print(args)
        ED2.breakLoop()
    def waitonline(rpc):
        if rpc.online:
            ED2.breakLoop()
    r = Rtp_proxy_client({'_sip_address':'1.2.3.4'})
    t = Timeout(waitonline, 0.1, 10, r)
    ED2.loop(2.0)
    assert(r.online)
    t.cancel()
    r.send_command('VF 123456', display, 'abcd')
    ED2.loop()
    r.shutdown()
    print('passed')
