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

from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect, CCEventDisconnect
from SipContact import SipContact
from SipAddress import SipAddress

class UasStateRinging(UaStateGeneric):
    sname = 'Ringing(UAS)'

    def recvEvent(self, event):
        if isinstance(event, CCEventRing):
            scode = event.getData()
            if scode == None:
                code, reason, body = (180, 'Ringing', None)
            else:
                code, reason, body = scode
                if code == 100:
                    return None
                if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                    self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                    return None
            self.ua.lSDP = body
            if self.ua.p1xx_ts == None:
                self.ua.p1xx_ts = event.rtime
            self.ua.sendUasResponse(code, reason, body)
            for ring_cb in self.ua.ring_cbs:
                ring_cb(self.ua, event.rtime, event.origin, code)
            return None
        elif isinstance(event, CCEventConnect):
            code, reason, body = event.getData()
            if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                return None
            self.ua.lSDP = body
            self.ua.sendUasResponse(code, reason, body, self.ua.lContact)
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            self.ua.startCreditTimer(event.rtime)
            self.ua.connect_ts = event.rtime
            return (UaStateConnected, self.ua.conn_cbs, event.rtime, event.origin)
        elif isinstance(event, CCEventRedirect):
            scode = event.getData()
            if scode == None:
                scode = (500, 'Failed', None, None)
            self.ua.sendUasResponse(scode[0], scode[1], scode[2], SipContact(address = SipAddress(url = scode[3])))
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            self.ua.disconnect_ts = event.rtime
            return (UaStateFailed, self.ua.fail_cbs, event.rtime, event.origin, scode[0])
        elif isinstance(event, CCEventFail):
            scode = event.getData()
            if scode == None:
                scode = (500, 'Failed')
            self.ua.sendUasResponse(scode[0], scode[1], reason_rfc3326 = event.reason, \
              extra_header = event.extra_header)
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            self.ua.disconnect_ts = event.rtime
            return (UaStateFailed, self.ua.fail_cbs, event.rtime, event.origin, scode[0])
        elif isinstance(event, CCEventDisconnect):
            #import sys, traceback
            #traceback.print_stack(file = sys.stdout)
            self.ua.sendUasResponse(500, 'Disconnected', reason_rfc3326 = event.reason)
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            self.ua.disconnect_ts = event.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime, event.origin, self.ua.last_scode)
        #print 'wrong event %s in the Ringing state' % event
        return None

    def recvRequest(self, req):
        if req.getMethod() == 'BYE':
            self.ua.sendUasResponse(487, 'Request Terminated')
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK'))
            #print 'BYE received in the Ringing state, going to the Disconnected state'
            if req.countHFs('also') > 0:
                also = req.getHFBody('also').getUrl().getCopy()
            else:
                also = None
            event = CCEventDisconnect(also, rtime = req.rtime, origin = self.ua.origin)
            try:
                event.reason = req.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            self.ua.disconnect_ts = req.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, req.rtime, self.ua.origin)
        return None

    def cancel(self, rtime, req):
        self.ua.disconnect_ts = rtime
        self.ua.changeState((UaStateDisconnected, self.ua.disc_cbs, rtime, self.ua.origin))
        event = CCEventDisconnect(rtime = rtime, origin = self.ua.origin)
        if req != None:
            try:
                event.reason = req.getHFBody('reason')
            except:
                pass
        self.ua.emitEvent(event)

if not globals().has_key('UaStateFailed'):
    from UaStateFailed import UaStateFailed
if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
