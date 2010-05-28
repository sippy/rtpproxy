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

from SipAddress import SipAddress
from SipRoute import SipRoute
from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect, CCEventDisconnect

class UacStateRinging(UaStateGeneric):
    sname = 'Ringing(UAC)'
    triedauth = False

    def recvResponse(self, resp):
        body = resp.getBody()
        code, reason = resp.getSCode()
        scode = (code, reason, body)
        if code < 200:
            if self.ua.p1xx_ts == None:
                self.ua.p1xx_ts = resp.rtime
            self.ua.last_scode = code
            event = CCEventRing(scode, rtime = resp.rtime, origin = self.ua.origin)
            for ring_cb in self.ua.ring_cbs:
                ring_cb(self.ua, resp.rtime, self.ua.origin, code)
            if body != None:
                if self.ua.on_remote_sdp_change != None:
                    self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                    return None
                else:
                    self.ua.rSDP = body.getCopy()
            else:
                self.ua.rSDP = None
            self.ua.equeue.append(event)
            return None
        if self.ua.expire_timer != None:
            self.ua.expire_timer.cancel()
            self.ua.expire_timer = None
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
            event = CCEventConnect(scode, rtime = resp.rtime, origin = self.ua.origin)
            self.ua.startCreditTimer(resp.rtime)
            if body != None:
                if self.ua.on_remote_sdp_change != None:
                    self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                    self.ua.connect_ts = resp.rtime
                    return (UaStateConnected, self.ua.conn_cbs, resp.rtime, self.ua.origin)
                else:
                    self.ua.rSDP = body.getCopy()
            else:
                self.ua.rSDP = None
            self.ua.equeue.append(event)
            self.ua.connect_ts = resp.rtime
            return (UaStateConnected, self.ua.conn_cbs, resp.rtime, self.ua.origin)
        if code in (301, 302) and resp.countHFs('contact') > 0:
            scode = (code, reason, body, resp.getHFBody('contact').getUrl().getCopy())
            self.ua.equeue.append(CCEventRedirect(scode, rtime = resp.rtime, origin = self.ua.origin))
        else:
            event = CCEventFail(scode, rtime = resp.rtime, origin = self.ua.origin)
            try:
                event.reason = resp.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
        self.ua.disconnect_ts = resp.rtime
        return (UaStateFailed, self.ua.fail_cbs, resp.rtime, self.ua.origin, code)

    def recvEvent(self, event):
        if isinstance(event, CCEventFail) or isinstance(event, CCEventRedirect) or isinstance(event, CCEventDisconnect):
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ua.tr, reason = event.reason)
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            self.ua.disconnect_ts = event.rtime
            return (UacStateCancelling, self.ua.disc_cbs, event.rtime, event.origin, self.ua.last_scode)
        #print 'wrong event %s in the Ringing state' % event
        return None

if not globals().has_key('UaStateFailed'):
    from UaStateFailed import UaStateFailed
if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UacStateCancelling'):
    from UacStateCancelling import UacStateCancelling
