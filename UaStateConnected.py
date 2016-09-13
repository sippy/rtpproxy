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
from SipAlso import SipAlso
from SipAddress import SipAddress
from SipHeader import SipHeader
from SipReferTo import SipReferTo
from SipReferredBy import SipReferredBy
from SipProxyAuthorization import SipProxyAuthorization
from SipMaxForwards import SipMaxForwards
from CCEvents import CCEventDisconnect, CCEventFail, CCEventRedirect, CCEventUpdate, CCEventInfo, CCEventConnect

class UaStateConnected(UaStateGeneric):
    sname = 'Connected'
    triedauth = None
    keepalives = None
    ka_tr = None
    connected = True

    def __init__(self, ua):
        self.keepalives = 0
        self.ka_tr = None
        UaStateGeneric.__init__(self, ua)
        self.ua.branch = None
        if self.ua.kaInterval > 0:
            Timeout(self.keepAlive, self.ua.kaInterval)

    def recvRequest(self, req):
        if req.getMethod() == 'REFER':
            if req.countHFs('refer-to') == 0:
                self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(400, 'Bad Request', server = self.ua.local_ua))
                return None
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(202, 'Accepted', server = self.ua.local_ua))
            also = req.getHFBody('refer-to').getUrl().getCopy()
            self.ua.equeue.append(CCEventDisconnect(also, rtime = req.rtime, origin = self.ua.origin))
            self.ua.recvEvent(CCEventDisconnect(rtime = req.rtime, origin = self.ua.origin))
            return None
        if req.getMethod() == 'INVITE':
            self.ua.uasResp = req.genResponse(100, 'Trying', server = self.ua.local_ua)
            self.ua.global_config['_sip_tm'].sendResponse(self.ua.uasResp)
            body = req.getBody()
            if body == None:
                # Some brain-damaged stacks use body-less re-INVITE as a means
                # for putting session on hold. Quick and dirty hack to make this
                # scenario working.
                body = self.ua.rSDP.getCopy()
                body.parse()
                for sect in body.content.sections:
                    sect.c_header.addr = '0.0.0.0'
            elif str(self.ua.rSDP) == str(body):
                self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', self.ua.lSDP, server = self.ua.local_ua))
                return None
            event = CCEventUpdate(body, rtime = req.rtime, origin = self.ua.origin)
            try:
                event.reason = req.getHFBody('reason')
            except:
                pass
            try:
                event.max_forwards = req.getHFBody('max-forwards').getNum()
            except:
                pass
            if body != None:
                if self.ua.on_remote_sdp_change != None:
                    self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                    return (UasStateUpdating,)
                else:
                    self.ua.rSDP = body.getCopy()
            else:
                self.ua.rSDP = None
            self.ua.equeue.append(event)
            return (UasStateUpdating,)
        if req.getMethod() == 'BYE':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', server = self.ua.local_ua))
            #print 'BYE received in the Connected state, going to the Disconnected state'
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
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = req.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, req.rtime, self.ua.origin)
        if req.getMethod() == 'INFO':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', server = self.ua.local_ua))
            event = CCEventInfo(req.getBody(), rtime = req.rtime, origin = self.ua.origin)
            try:
                event.reason = req.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
            return None
        if req.getMethod() == 'OPTIONS':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', server = self.ua.local_ua))
            return None
        #print 'wrong request %s in the state Connected' % req.getMethod()
        return None

    def recvACK(self, req):
        body = req.getBody()
        scode = ('ACK', 'ACK', body)
        event = CCEventConnect(scode, rtime = req.rtime, origin = self.ua.origin)
        if self.ua.expire_timer != None:
            self.ua.expire_timer.cancel()
            self.ua.expire_timer = None
        self.ua.startCreditTimer(req.rtime)
        self.ua.connect_ts = req.rtime
        for callback in self.ua.conn_cbs:
            callback(self.ua, req.rtime, self.ua.origin)
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

    def recvEvent(self, event):
        if isinstance(event, CCEventDisconnect) or isinstance(event, CCEventFail) or isinstance(event, CCEventRedirect):
            #print 'event', event, 'received in the Connected state sending BYE'
            if not isinstance(event, CCEventFail):
                redirect = event.getData()
            else:
                redirect = None
            if redirect != None and self.ua.useRefer:
                req = self.ua.genRequest('REFER', reason = event.reason)
                self.ua.lCSeq += 1
                also = SipReferTo(address = SipAddress(url = redirect))
                req.appendHeader(SipHeader(name = 'refer-to', body = also))
                rby = SipReferredBy(address = SipAddress(url = self.ua.lUri.getUrl()))
                req.appendHeader(SipHeader(name = 'referred-by', body = rby))
                self.ua.global_config['_sip_tm'].newTransaction(req, self.rComplete, \
                  laddress = self.ua.source_address, compact = self.ua.compact_sip)
            else:
                req = self.ua.genRequest('BYE', reason = event.reason)
                self.ua.lCSeq += 1
                if redirect != None:
                    also = SipAlso(address = SipAddress(url = redirect))
                    req.appendHeader(SipHeader(name = 'also', body = also))
                self.ua.global_config['_sip_tm'].newTransaction(req, \
                  laddress = self.ua.source_address, compact = self.ua.compact_sip)
            self.ua.cancelCreditTimer()
            self.ua.disconnect_ts = event.rtime
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime, event.origin)
        if isinstance(event, CCEventUpdate):
            body = event.getData()
            if str(self.ua.lSDP) == str(body):
                if self.ua.rSDP != None:
                    self.ua.equeue.append(CCEventConnect((200, 'OK', self.ua.rSDP.getCopy()), \
                        rtime = event.rtime, origin = event.origin))
                else:
                    self.ua.equeue.append(CCEventConnect((200, 'OK', None), rtime = event.rtime, \
                      origin = event.origin))
                return None
            if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                try:
                    self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event), en_excpt = True)
                except Exception, e:
                    event = CCEventFail((400, 'Malformed SDP Body'), rtime = event.rtime)
                    event.setWarning(str(e))
                    self.ua.equeue.append(event)
                return None
            if event.max_forwards != None:
                max_forwards_hf = SipMaxForwards(number = event.max_forwards - 1)
            else:
                max_forwards_hf = None
            req = self.ua.genRequest('INVITE', body, reason = event.reason, \
              maxforwards = max_forwards_hf)
            self.ua.lCSeq += 1
            self.ua.lSDP = body
            self.ua.tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.ua.recvResponse, \
              laddress = self.ua.source_address, cb_ifver = 2, compact = self.ua.compact_sip)
            return (UacStateUpdating,)
        if isinstance(event, CCEventInfo):
            body = event.getData()
            req = self.ua.genRequest('INFO', reason = event.reason)
            req.setBody(body)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, None, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)
            return None
        if self.ua.pending_tr != None and isinstance(event, CCEventConnect):
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            code, reason, body = event.getData()
            if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                return None
            self.ua.startCreditTimer(event.rtime)
            self.ua.connect_ts = event.rtime
            self.ua.lSDP = body
            self.ua.pending_tr.ack.setBody(body)
            self.ua.global_config['_sip_tm'].sendACK(self.ua.pending_tr)
            self.ua.pending_tr = None
            for callback in self.ua.conn_cbs:
                callback(self.ua, event.rtime, self.ua.origin)
            return None
        #print 'wrong event %s in the Connected state' % event
        return None

    def keepAlive(self):
        if self.ua.state != self:
            return
        #self.ua.lSDP.parse()
        #self.ua.lSDP.content.m_header.port += 4
        req = self.ua.genRequest('INVITE', self.ua.lSDP)
        self.ua.lCSeq += 1
        self.triedauth = False
        self.ka_tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.keepAliveResp, \
          laddress = self.ua.source_address, compact = self.ua.compact_sip)

    def keepAliveResp(self, resp):
        if self.ua.state != self:
            return
        code, reason = resp.getSCode()
        if code == 401 and resp.countHFs('www-authenticate') != 0 and \
          self.ua.username != None and self.ua.password != None and not self.triedauth:
            challenge = resp.getHFBody('www-authenticate')
            req = self.ua.genRequest('INVITE', self.ua.lSDP, challenge.getNonce(), challenge.getRealm())
            self.ua.lCSeq += 1
            self.ka_tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.keepAliveResp, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)
            self.triedauth = True
            return
        if code == 407 and resp.countHFs('proxy-authenticate') != 0 and \
          self.ua.username != None and self.ua.password != None and not self.triedauth:
            challenge = resp.getHFBody('proxy-authenticate')
            req = self.ua.genRequest('INVITE', self.ua.lSDP, challenge.getNonce(), challenge.getRealm(), SipProxyAuthorization)
            self.ua.lCSeq += 1
            self.ka_tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.keepAliveResp, \
              laddress = self.ua.source_address, compact = self.ua.compact_sip)
            self.triedauth = True
            return
        if code < 200:
            return
        self.ka_tr = None
        self.keepalives += 1
        if code in (408, 481, 486):
            if self.keepalives == 1:
                print '%s: Remote UAS at %s:%d does not support re-INVITES, disabling keep alives' % (self.ua.cId, self.ua.rAddr[0], self.ua.rAddr[1])
                Timeout(self.ua.disconnect, 600)
                return
            print '%s: Received %d response to keep alive from %s:%d, disconnecting the call' % (self.ua.cId, code, self.ua.rAddr[0], self.ua.rAddr[1])
            self.ua.disconnect()
            return
        Timeout(self.keepAlive, self.ua.kaInterval)

    def onStateChange(self, newstate):
        if self.ka_tr != None:
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ka_tr)
            self.ka_tr = None
        if self.ua.pending_tr != None:
            self.ua.global_config['_sip_tm'].sendACK(self.ua.pending_tr)
            self.ua.pending_tr = None
        if self.ua.expire_timer != None:
            self.ua.expire_timer.cancel()
            self.ua.expire_timer = None

    def rComplete(self, resp):
        req = self.ua.genRequest('BYE')
        self.ua.lCSeq += 1
        self.ua.global_config['_sip_tm'].newTransaction(req, \
          laddress = self.ua.source_address, compact = self.ua.compact_sip)

if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
if not globals().has_key('UasStateUpdating'):
    from UasStateUpdating import UasStateUpdating
if not globals().has_key('UacStateUpdating'):
    from UacStateUpdating import UacStateUpdating
