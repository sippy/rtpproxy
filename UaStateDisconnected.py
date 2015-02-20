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
from UaStateGeneric import UaStateGeneric

class UaStateDisconnected(UaStateGeneric):
    sname = 'Disconnected'

    def __init__(self, ua):
        UaStateGeneric.__init__(self, ua)
        ua.on_local_sdp_change = None
        ua.on_remote_sdp_change = None
        Timeout(self.goDead, ua.godead_timeout)

    def recvRequest(self, req):
        if req.getMethod() == 'BYE':
            #print 'BYE received in the Disconnected state'
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', server = self.ua.local_ua))
        else:
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(500, 'Disconnected', server = self.ua.local_ua))
        return None

    def goDead(self):
        #print 'Time in Disconnected state expired, going to the Dead state'
        self.ua.changeState((UaStateDead,))

if not globals().has_key('UaStateDead'):
    from UaStateDead import UaStateDead
