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

from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventDisconnect, CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect

class UacStateUpdating(UaStateGeneric):
    sname = 'Updating(UAC)'
    triedauth = False
    connected = True

    def recvRequest(self, req):
        if req.getMethod() == 'INVITE':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(491, 'Request Pending', server = self.ua.local_ua))
            return None
        elif req.getMethod() == 'BYE':
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ua.tr)
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', server = self.ua.local_ua))
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

    def recvResponse(self, resp, tr):
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
        else:
            event = CCEventFail(scode, rtime = resp.rtime, origin = self.ua.origin)
            try:
                event.reason = resp.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)

        if code in (408, 481):
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

            req = self.ua.genRequest('BYE', reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)

            self.ua.equeue.append(event)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = resp.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, resp.rtime, self.ua.origin)

        return (UaStateConnected,)

    def recvEvent(self, event):
        if isinstance(event, CCEventDisconnect) or isinstance(event, CCEventFail) or isinstance(event, CCEventRedirect):
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ua.tr)
            req = self.ua.genRequest('BYE', reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = event.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime, event.origin)
        #print 'wrong event %s in the Updating state' % event
        return None

if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
