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

from SipContact import SipContact
from SipAddress import SipAddress
from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventDisconnect, CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect

class UasStateUpdating(UaStateGeneric):
    sname = 'Updating(UAS)'
    connected = True

    def recvRequest(self, req):
        if req.getMethod() == 'INVITE':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(491, \
              'Request Pending', server = self.ua.local_ua, lossemul = self.ua.uas_lossemul))
            return None
        elif req.getMethod() == 'BYE':
            self.ua.sendUasResponse(487, 'Request Terminated')
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', \
              server = self.ua.local_ua, lossemul = self.ua.uas_lossemul))
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
                self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(400, 'Bad Request',
                  server = self.ua.local_ua, lossemul = self.ua.uas_lossemul))
                return None
            self.ua.sendUasResponse(487, 'Request Terminated')
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(202, 'Accepted', \
              server = self.ua.local_ua, lossemul = self.ua.uas_lossemul))
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
            if event.warning != None:
                extra_headers = (event.warning,)
            else:
                extra_headers = None
            self.ua.sendUasResponse(scode[0], scode[1], reason_rfc3326 = event.reason, \
              extra_headers = extra_headers)
            return (UaStateConnected,)
        elif isinstance(event, CCEventDisconnect):
            self.ua.sendUasResponse(487, 'Request Terminated', reason_rfc3326 = event.reason)
            req = self.ua.genRequest('BYE', reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = event.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime, event.origin)
        #print 'wrong event %s in the Updating state' % event
        return None

    def cancel(self, rtime, req):
        req = self.ua.genRequest('BYE')
        self.ua.lCSeq += 1
        self.ua.global_config['_sip_tm'].newTransaction(req, \
          laddress = self.ua.source_address, compact = self.ua.compact_sip)
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
