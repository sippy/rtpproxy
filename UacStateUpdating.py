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
from CCEvents import CCEventDisconnect, CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect

class UacStateUpdating(UaStateGeneric):
    sname = 'Updating(UAC)'
    triedauth = False
    connected = True

    def recvRequest(self, req):
        if req.getMethod() == 'INVITE':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(491, 'Request Pending'))
            return None
        elif req.getMethod() == 'BYE':
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ua.tr)
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
        #print 'wrong request %s in the state Updating' % req.getMethod()
        return None

    def recvResponse(self, resp):
        body = resp.getBody()
        code, reason = resp.getSCode()
        scode = (code, reason, body)
        if code < 200:
            self.ua.equeue.append(CCEventRing(scode, rtime = resp.rtime, origin = self.ua.origin))
            return None
        if code >= 200 and code < 300:
            event = CCEventConnect(scode, rtime = resp.rtime, origin = self.ua.origin)
            if body != None:
                if self.ua.on_remote_sdp_change != None:
                    self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                    return (UaStateConnected,)
                else:
                    self.ua.rSDP = body.getCopy()
            else:
                self.ua.rSDP = None
            self.ua.equeue.append(event)
            return (UaStateConnected,)
        if code in (301, 302) and resp.countHFs('contact') > 0:
            scode = (code, reason, body, resp.getHFBody('contact').getUrl().getCopy())
            self.ua.equeue.append(CCEventRedirect(scode, rtime = resp.rtime, origin = self.ua.origin))
        elif code in (408, 481):
            # If the response for a request within a dialog is a 481
            # (Call/Transaction Does Not Exist) or a 408 (Request Timeout), the UAC
            # SHOULD terminate the dialog.  A UAC SHOULD also terminate a dialog if
            # no response at all is received for the request (the client
            # transaction would inform the TU about the timeout.)
            event = CCEventDisconnect(rtime = resp.rtime, origin = self.ua.origin)
            try:
                event.reason = resp.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = resp.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, resp.rtime, self.ua.origin)
        else:
            event = CCEventFail(scode, rtime = resp.rtime, origin = self.ua.origin)
            try:
                event.reason = resp.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
        return (UaStateConnected,)

    def recvEvent(self, event):
        if isinstance(event, CCEventDisconnect) or isinstance(event, CCEventFail) or isinstance(event, CCEventRedirect):
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ua.tr)
            req = self.ua.genRequest('BYE', reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = event.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime, event.origin)
        #print 'wrong event %s in the Updating state' % event
        return None

if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
