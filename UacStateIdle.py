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
from UaStateGeneric import UaStateGeneric
from CCEvents import CCEventTry, CCEventFail, CCEventRedirect, CCEventDisconnect
from SipContact import SipContact
from SipAddress import SipAddress
from SipURL import SipURL
from SipTo import SipTo
from SipFrom import SipFrom
from SipCallId import SipCallId

class UacStateIdle(UaStateGeneric):
    sname = 'Idle(UAC)'

    def recvEvent(self, event):
        if isinstance(event, CCEventTry):
            if self.ua.setup_ts == None:
                self.ua.setup_ts = event.rtime
            self.ua.origin = 'callee'
            cId, cGUID, callingID, calledID, body, auth, callingName = event.getData()
            if body != None and self.ua.on_local_sdp_change != None and body.needs_update:
                self.ua.on_local_sdp_change(body, lambda x: self.ua.recvEvent(event))
                return None
            if cId == None:
                self.ua.cId = SipCallId()
            else:
                self.ua.cId = cId.getCopy()
            self.ua.global_config['_sip_tm'].regConsumer(self.ua, str(self.ua.cId))
            self.ua.rTarget = SipURL(username = calledID, host = self.ua.rAddr0[0], port = self.ua.rAddr0[1])
            self.ua.rUri = SipTo(address = SipAddress(url = self.ua.rTarget.getCopy(), hadbrace = True))
            self.ua.rUri.getUrl().port = None
            self.ua.lUri = SipFrom(address = SipAddress(url = SipURL(username = callingID), hadbrace = True, name = callingName))
            self.ua.lUri.getUrl().port = None
            self.ua.lUri.setTag(self.ua.lTag)
            self.ua.lCSeq = 200
            self.ua.lContact = SipContact()
            self.ua.lContact.getUrl().username = callingID
            self.ua.routes = []
            self.ua.cGUID = cGUID
            self.ua.lSDP = body
            req = self.ua.genRequest('INVITE', body, reason = event.reason)
            self.ua.lCSeq += 1
            self.ua.tr = self.ua.global_config['_sip_tm'].newTransaction(req, self.ua.recvResponse, \
              laddress = self.ua.source_address)
            self.ua.auth = None
            if self.ua.expire_time != None:
                self.ua.expire_time += event.rtime
            if self.ua.no_progress_time != None:
                self.ua.no_progress_time += event.rtime
                if self.ua.expire_time != None and self.ua.no_progress_time >= self.ua.expire_time:
                    self.ua.no_progress_time = None
            if self.ua.no_reply_time != None:
                if self.ua.no_reply_time < 32:
                    self.ua.no_reply_time += event.rtime
                    if self.ua.expire_time != None and self.ua.no_reply_time >= self.ua.expire_time:
                        self.ua.no_reply_time = None
                    elif self.ua.no_progress_time != None and self.ua.no_reply_time >= self.ua.no_progress_time:
                        self.ua.no_reply_time = None
                else:
                        self.ua.no_reply_time = None
            if self.ua.no_reply_time != None:
                self.ua.no_reply_timer = TimeoutAbs(self.ua.no_reply_expires, self.ua.no_reply_time)
            elif self.ua.no_progress_time != None:
                self.ua.no_progress_timer = TimeoutAbs(self.ua.no_progress_expires, self.ua.no_progress_time)
            elif self.ua.expire_time != None:
                self.ua.expire_timer = TimeoutAbs(self.ua.expires, self.ua.expire_time)
            return (UacStateTrying,)
        if isinstance(event, CCEventFail) or isinstance(event, CCEventRedirect) or isinstance(event, CCEventDisconnect):
            return (UaStateDead, self.ua.disc_cbs, event.rtime, event.origin)
        return None

if not globals().has_key('UacStateTrying'):
    from UacStateTrying import UacStateTrying
if not globals().has_key('UaStateDead'):
    from UaStateDead import UaStateDead
