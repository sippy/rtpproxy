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
from SipAddress import SipAddress
from SipRoute import SipRoute

class UacStateCancelling(UaStateGeneric):
    sname = 'Cancelling(UAC)'

    def __init__(self, ua):
        UaStateGeneric.__init__(self, ua)
        ua.on_local_sdp_change = None
        ua.on_remote_sdp_change = None
        # 300 provides good estimate on the amount of time during which
        # we can wait for receiving non-negative response to CANCELled
        # INVITE transaction.
        self.te = Timeout(self.goIdle, 300.0)

    def goIdle(self):
        #print 'Time in Cancelling state expired, going to the Dead state'
        self.te = None
        self.ua.changeState((UaStateDead,))

    def recvResponse(self, resp, tr):
        code, reason = resp.getSCode()
        if code < 200:
            return None
        if self.te != None:
            self.te.cancel()
            self.te = None
        # When the final response arrives make sure to send BYE
        # if response is positive 200 OK and move into
        # UaStateDisconnected to catch any in-flight BYE from the
        # called party.
        #
        # If the response is negative or redirect go to the UaStateDead
        # immediately, since this means that we won't receive any more
        # requests from the calling party. XXX: redirects should probably
        # somehow reported to the upper level, but it will create
        # significant additional complexity there, since after signalling
        # Failure/Disconnect calling party don't expect any more
        # events to be delivered from the called one. In any case,
        # this should be fine, since we are in this state only when
        # caller already has declared his wilingless to end the session,
        # so that he is probably isn't interested in redirects anymore.
        if code >= 200 and code < 300:
            if resp.countHFs('contact') > 0:
                self.ua.rTarget = resp.getHFBody('contact').getUrl().getCopy()
            self.ua.routes = [x.getCopy() for x in resp.getHFBodys('record-route')]
            self.ua.routes.reverse()
            if len(self.ua.routes) > 0:
                if not self.ua.routes[0].getUrl().lr:
                    self.ua.routes.append(SipRoute(address = SipAddress(url = self.ua.rTarget)))
                    self.ua.rTarget = self.ua.routes.pop(0).getUrl()
                    self.ua.rAddr = self.ua.rTarget.getAddr()
                elif self.ua.outbound_proxy != None:
                    self.ua.routes.append(SipRoute(address = SipAddress(url = self.ua.rTarget)))
                    self.ua.rTarget = self.ua.routes[0].getUrl().getCopy()
                    self.ua.rTarget.lr = False
                    self.ua.rTarget.other = tuple()
                    self.ua.rTarget.headers = tuple()
                else:
                    self.ua.rAddr = self.ua.routes[0].getAddr()
            else:
                self.ua.rAddr = self.ua.rTarget.getAddr()
            self.ua.rUri.setTag(resp.getHFBody('to').getTag())
            req = self.ua.genRequest('BYE')
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)
            return (UaStateDisconnected,)
        return (UaStateDead,)

    def recvEvent(self, event):
        #print 'wrong event %s in the Cancelling state' % event
        return None

if not globals().has_key('UaStateDead'):
    from UaStateDead import UaStateDead
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
