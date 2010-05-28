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

from Timeout import TimeoutAbs
from SipAddress import SipAddress
from SipRoute import SipRoute
from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventTry
from SipContact import SipContact
from SipCiscoGUID import SipCiscoGUID
from SipFrom import SipFrom
from SipTo import SipTo

class UasStateIdle(UaStateGeneric):
    sname = 'Idle(UAS)'

    def recvRequest(self, req):
        if req.getMethod() != 'INVITE':
            #print 'wrong request %s in the Trying state' % req.getMethod()
            return None
        self.ua.origin = 'caller'
        #print 'INVITE received in the Idle state, going to the Trying state'
        if req.countHFs('cisco-guid') != 0:
            self.ua.cGUID = req.getHFBody('cisco-guid').getCopy()
        elif req.countHFs('h323-conf-id') != 0:
            self.ua.cGUID = req.getHFBody('h323-conf-id').getCopy()
        else:
            self.ua.cGUID = SipCiscoGUID()
        self.ua.uasResp = req.genResponse(100, 'Trying')
        self.ua.lCSeq = 100 # XXX: 100 for debugging so that incorrect CSeq generation will be easily spotted
        self.ua.lContact = SipContact()
        self.ua.rTarget = req.getHFBody('contact').getUrl().getCopy()
        self.ua.routes = [x.getCopy() for x in self.ua.uasResp.getHFBodys('record-route')]
        if len(self.ua.routes) > 0:
            if not self.ua.routes[0].getUrl().lr:
                self.ua.routes.append(SipRoute(address = SipAddress(url = self.ua.rTarget.getCopy())))
                self.ua.rTarget = self.ua.routes.pop(0).getUrl()
                self.ua.rAddr = self.ua.rTarget.getAddr()
            else:
                self.ua.rAddr = self.ua.routes[0].getAddr()
        else:
            self.ua.rAddr = self.ua.rTarget.getAddr()
        self.ua.rAddr0 = self.ua.rAddr
        self.ua.global_config['_sip_tm'].sendResponse(self.ua.uasResp)
        self.ua.uasResp.getHFBody('to').setTag(self.ua.lTag)
        self.ua.lUri = SipFrom(address = self.ua.uasResp.getHFBody('to').getUri())
        self.ua.rUri = SipTo(address = self.ua.uasResp.getHFBody('from').getUri())
        self.ua.cId = self.ua.uasResp.getHFBody('call-id')
        self.ua.global_config['_sip_tm'].regConsumer(self.ua, str(self.ua.cId))
        if req.countHFs('authorization') == 0:
            auth = None
        else:
            auth = req.getHFBody('authorization').getCopy()
        body = req.getBody()
        self.ua.branch = req.getHFBody('via').getBranch()
        event = CCEventTry((self.ua.cId, self.ua.cGUID, self.ua.rUri.getUrl().username, req.getRURI().username, body, auth, \
          self.ua.rUri.getUri().name), rtime = req.rtime, origin = self.ua.origin)
        try:
            event.reason = req.getHFBody('reason')
        except:
            pass
        if self.ua.expire_time != None:
            self.ua.expire_time += event.rtime
        if self.ua.no_progress_time != None:
            self.ua.no_progress_time += event.rtime
            if self.ua.expire_time != None and self.ua.no_progress_time >= self.ua.expire_time:
                self.ua.no_progress_time = None
        if self.ua.no_progress_time != None:
            self.ua.no_progress_timer = TimeoutAbs(self.ua.no_progress_expires, self.ua.no_progress_time)
        elif self.ua.expire_time != None:
            self.ua.expire_timer = TimeoutAbs(self.ua.expires, self.ua.expire_time)
        if body != None:
            if self.ua.on_remote_sdp_change != None:
                self.ua.on_remote_sdp_change(body, lambda x: self.ua.delayed_remote_sdp_update(event, x))
                self.ua.setup_ts = req.rtime
                return (UasStateTrying,)
            else:
                self.ua.rSDP = body.getCopy()
        else:
            self.ua.rSDP = None
        self.ua.equeue.append(event)
        self.ua.setup_ts = req.rtime
        return (UasStateTrying,)

if not globals().has_key('UasStateTrying'):
    from UasStateTrying import UasStateTrying
