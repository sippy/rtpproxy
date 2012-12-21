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
from Timeout import TimeoutAbs
from CCEvents import CCEventRing, CCEventConnect, CCEventFail, CCEventRedirect, CCEventDisconnect

class UacStateTrying(UaStateGeneric):
    sname = 'Trying(UAC)'
    triedauth = False

    def recvResponse(self, resp, tr):
        body = resp.getBody()
        code, reason = resp.getSCode()
        scode = (code, reason, body)
        self.ua.last_scode = code

        if self.ua.no_reply_timer != None:
            self.ua.no_reply_timer.cancel()
            self.ua.no_reply_timer = None
            if code == 100 and self.ua.no_progress_time != None:
                self.ua.no_progress_timer = TimeoutAbs(self.ua.no_progress_expires, self.ua.no_progress_time)
            elif code < 200 and self.ua.expire_time != None:
                self.ua.expire_timer = TimeoutAbs(self.ua.expires, self.ua.expire_time)
        if code == 100:
            if self.ua.p100_ts == None:
                self.ua.p100_ts = resp.rtime
            self.ua.equeue.append(CCEventRing(scode, rtime = resp.rtime, origin = self.ua.origin))
            return None
        if self.ua.no_progress_timer != None:
            self.ua.no_progress_timer.cancel()
            self.ua.no_progress_timer = None
            if code < 200 and self.ua.expire_time != None:
                self.ua.expire_timer = TimeoutAbs(self.ua.expires, self.ua.expire_time)
        if code < 200:
            event = CCEventRing(scode, rtime = resp.rtime, origin = self.ua.origin)
            if body != None:
                if self.ua.on_remote_sdp_change != None:
                    self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                    self.ua.p1xx_ts = resp.rtime
                    return (UacStateRinging, self.ua.ring_cbs, resp.rtime, self.ua.origin, code)
                else:
                    self.ua.rSDP = body.getCopy()
            else:
                self.ua.rSDP = None
            self.ua.equeue.append(event)
            self.ua.p1xx_ts = resp.rtime
            return (UacStateRinging, self.ua.ring_cbs, resp.rtime, self.ua.origin, code)
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
            tag = resp.getHFBody('to').getTag()
            if tag == None:
                print 'tag-less 200 OK, disconnecting'
                scode = (502, 'Bad Gateway')
                self.ua.equeue.append(CCEventFail(scode, rtime = resp.rtime, origin = self.ua.origin))
                # Generate and send BYE
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
                req = self.ua.genRequest('BYE')
                self.ua.lCSeq += 1
                self.ua.global_config['_sip_tm'].newTransaction(req, \
                  laddress = self.ua.source_address)
                return (UaStateFailed, self.ua.fail_cbs, resp.rtime, self.ua.origin, scode[0])
            self.ua.rUri.setTag(tag)
            if not self.ua.late_media or body == None:
                self.ua.late_media = False
                event = CCEventConnect(scode, rtime = resp.rtime, origin = self.ua.origin)
                self.ua.startCreditTimer(resp.rtime)
                self.ua.connect_ts = resp.rtime
                rval = (UaStateConnected, self.ua.conn_cbs, resp.rtime, self.ua.origin)
            else:
                event = CCEventPreConnect(scode, rtime = resp.rtime, origin = self.ua.origin)
                tr.uack = True
                self.ua.pending_tr = tr
                rval = (UaStateConnected,)
            if body != None:
                if self.ua.on_remote_sdp_change != None:
                    self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                    return rval
                else:
                    self.ua.rSDP = body.getCopy()
            else:
                self.ua.rSDP = None
            self.ua.equeue.append(event)
            return rval
        if code in (301, 302) and resp.countHFs('contact') > 0:
            scode = (code, reason, body, resp.getHFBody('contact').getUrl().getCopy())
            self.ua.equeue.append(CCEventRedirect(scode, rtime = resp.rtime, origin = self.ua.origin))
        else:
            event = CCEventFail(scode, rtime = resp.rtime, origin = self.ua.origin)
            if self.ua.pass_auth:
                if code == 401 and resp.countHFs('www-authenticate') != 0:
                    event.challenge = resp.getHF('www-authenticate').getCopy()
                elif code == 407 and resp.countHFs('proxy-authenticate') != 0:
                    event.challenge = resp.getHF('proxy-authenticate').getCopy()
            if resp.countHFs('reason') != 0:
                event.reason = resp.getHFBody('reason').getCopy()
            self.ua.equeue.append(event)
        self.ua.disconnect_ts = resp.rtime
        return (UaStateFailed, self.ua.fail_cbs, resp.rtime, self.ua.origin, code)

    def recvEvent(self, event):
        if isinstance(event, CCEventFail) or isinstance(event, CCEventRedirect) or isinstance(event, CCEventDisconnect):
            self.ua.global_config['_sip_tm'].cancelTransaction(self.ua.tr, reason = event.reason)
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            if self.ua.no_progress_timer != None:
                self.ua.no_progress_timer.cancel()
                self.ua.no_progress_timer = None
            if self.ua.no_reply_timer != None:
                self.ua.no_reply_timer.cancel()
                self.ua.no_reply_timer = None
            self.ua.disconnect_ts = event.rtime
            return (UacStateCancelling, self.ua.disc_cbs, event.rtime, event.origin, self.ua.last_scode)
        #print 'wrong event %s in the Trying state' % event
        return None

if not globals().has_key('UacStateRinging'):
    from UacStateRinging import UacStateRinging
if not globals().has_key('UaStateFailed'):
    from UaStateFailed import UaStateFailed
if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UacStateCancelling'):
    from UacStateCancelling import UacStateCancelling
