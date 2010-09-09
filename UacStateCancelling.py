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

    def recvResponse(self, resp):
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
                    self.ua.routes.append(SipRoute(address = SipAddress(url = self.ua.rTarget.getCopy())))
                    self.ua.rTarget = self.ua.routes.pop(0).getUrl()
                    self.ua.rAddr = self.ua.rTarget.getAddr()
                else:
                    self.ua.rAddr = self.ua.routes[0].getAddr()
            else:
                self.ua.rAddr = self.ua.rTarget.getAddr()
            self.ua.rUri.setTag(resp.getHFBody('to').getTag())
            req = self.ua.genRequest('BYE')
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address)
            return (UaStateDisconnected,)
        return (UaStateDead,)

    def recvEvent(self, event):
        #print 'wrong event %s in the Cancelling state' % event
        return None

if not globals().has_key('UaStateDead'):
    from UaStateDead import UaStateDead
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
