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
from SipAlso import SipAlso
from SipAddress import SipAddress
from SipHeader import SipHeader
from SipReferTo import SipReferTo
from SipReferredBy import SipReferredBy
from SipProxyAuthorization import SipProxyAuthorization
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
                self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(400, 'Bad Request'))
                return None
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(202, 'Accepted'))
            also = req.getHFBody('refer-to').getUrl().getCopy()
            self.ua.equeue.append(CCEventDisconnect(also, rtime = req.rtime, origin = self.ua.origin))
            self.ua.recvEvent(CCEventDisconnect(rtime = req.rtime, origin = self.ua.origin))
            return None
        if req.getMethod() == 'INVITE':
            self.ua.uasResp = req.genResponse(100, 'Trying')
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
                self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK', self.ua.lSDP))
                return None
            event = CCEventUpdate(body, rtime = req.rtime, origin = self.ua.origin)
            try:
                event.reason = req.getHFBody('reason')
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
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK'))
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
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK'))
            event = CCEventInfo(req.getBody(), rtime = req.rtime, origin = self.ua.origin)
            try:
                event.reason = req.getHFBody('reason')
            except:
                pass
            self.ua.equeue.append(event)
            return None
        if req.getMethod() == 'OPTIONS':
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK'))
            return None
        #print 'wrong request %s in the state Connected' % req.getMethod()
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
                  laddress = self.ua.source_address)
            else:
                req = self.ua.genRequest('BYE', reason = event.reason)
                self.ua.lCSeq += 1
                if redirect != None:
                    also = SipAlso(address = SipAddress(url = redirect))
                    req.appendHeader(SipHeader(name = 'also', body = also))
                self.ua.global_config['_sip_tm'].newTransaction(req, \
                  laddress = self.ua.source_address)
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
                self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                return None
            req = self.ua.genRequest('INVITE', body, reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.lSDP = body
            self.ua.tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.ua.recvResponse, \
              laddress = self.ua.source_address)
            return (UacStateUpdating,)
        if isinstance(event, CCEventInfo):
            body = event.getData()
            req = self.ua.genRequest('INFO', reason = event.reason)
            req.setBody(body)
            self.ua.lCSeq += 1
            self.ua.global_config['_sip_tm'].newTransaction(req, None, \
              laddress = self.ua.source_address)
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
          laddress = self.ua.source_address)

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
              laddress = self.ua.source_address)
            self.triedauth = True
            return
        if code == 407 and resp.countHFs('proxy-authenticate') != 0 and \
          self.ua.username != None and self.ua.password != None and not self.triedauth:
            challenge = resp.getHFBody('proxy-authenticate')
            req = self.ua.genRequest('INVITE', self.ua.lSDP, challenge.getNonce(), challenge.getRealm(), SipProxyAuthorization)
            self.ua.lCSeq += 1
            self.ka_tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.keepAliveResp, \
              laddress = self.ua.source_address)
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

    def rComplete(self, resp):
        req = self.ua.genRequest('BYE')
        self.ua.lCSeq += 1
        self.ua.global_config['_sip_tm'].newTransaction(req, \
          laddress = self.ua.source_address)

if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
if not globals().has_key('UasStateUpdating'):
    from UasStateUpdating import UasStateUpdating
if not globals().has_key('UacStateUpdating'):
    from UacStateUpdating import UacStateUpdating
