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

from SipContact import SipContact
from SipAddress import SipAddress
from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventDisconnect, CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect

class UasStateUpdating(UaStateGeneric):
    sname = 'Updating(UAS)'
    connected = True

    def recvRequest(self, req):
        if req.getMethod() == 'INVITE':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(491, 'Request Pending'))
            return None
        elif req.getMethod() == 'BYE':
            self.ua.sendUasResponse(487, 'Request Terminated')
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK'))
            #print 'BYE received in the Updating state, going to the Disconnected state'
            event = CCEventDisconnect(rtime = req.rtime, origin = self.ua.origin)
            try:
                event.reason = req.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = req.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, req.rtime, self.ua.origin)
        elif req.getMethod() == 'REFER':
            if req.countHFs('refer-to') == 0:
                self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(400, 'Bad Request'))
                return None
            self.ua.sendUasResponse(487, 'Request Terminated')
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(202, 'Accepted'))
            also = req.getHFBody('refer-to').getUrl().getCopy()
            self.ua.equeue.append(CCEventDisconnect(also, rtime = req.rtime, origin = self.ua.origin))
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = req.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, req.rtime, self.ua.origin)
        #print 'wrong request %s in the state Updating' % req.getMethod()
        return None

    def recvEvent(self, event):
        if isinstance(event, CCEventRing):
            scode = event.getData()
            if scode == None:
                scode = (180, 'Ringing', None)
            body = scode[2]
            if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                return None
            self.ua.lSDP = body
            self.ua.sendUasResponse(scode[0], scode[1], body)
            return None
        elif isinstance(event, CCEventConnect):
            code, reason, body = event.getData()
            if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                return None
            self.ua.lSDP = body
            self.ua.sendUasResponse(code, reason, body, self.ua.lContact)
            return (UaStateConnected,)
        elif isinstance(event, CCEventRedirect):
            scode = event.getData()
            if scode == None:
                scode = (500, 'Failed', None, None)
            self.ua.sendUasResponse(scode[0], scode[1], scode[2], SipContact(address = SipAddress(url = scode[3])))
            return (UaStateConnected,)
        elif isinstance(event, CCEventFail):
            scode = event.getData()
            if scode == None:
                scode = (500, 'Failed')
            self.ua.sendUasResponse(scode[0], scode[1], reason_rfc3326 = event.reason)
            return (UaStateConnected,)
        elif isinstance(event, CCEventDisconnect):
            self.ua.sendUasResponse(487, 'Request Terminated', reason_rfc3326 = event.reason)
            req = self.ua.genRequest('BYE', reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = event.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime, event.origin)
        #print 'wrong event %s in the Updating state' % event
        return None

    def cancel(self, rtime, req):
        req = self.ua.genRequest('BYE')
        self.ua.lCSeq += 1
        self.ua.global_config['_sip_tm'].newTransaction(req, \
          laddress = self.ua.source_address)
        self.ua.cancelCreditTimer()
        self.ua.disconnect_ts = rtime
        self.ua.changeState((UaStateDisconnected, self.ua.disc_cbs, rtime, self.ua.origin))
        event = CCEventDisconnect(rtime = rtime, origin = self.ua.origin)
        if req != None:
            try:
                event.reason = req.getHFBody('reason')     
            except:
                pass
        self.ua.emitEvent(event)

if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
