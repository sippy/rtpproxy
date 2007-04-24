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
# For a license to use the ser software under conditions
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

class UasStateTrying(UaStateGeneric):
    sname = 'Trying(UAS)'

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
            self.ua.sendUasResponse(code, reason, body)
            if self.ua.no_progress_timer != None:
                self.ua.no_progress_timer.cancel()
                self.ua.no_progress_timer = None
            return (UasStateRinging, self.ua.ring_cbs, event.rtime, code)
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
            if self.ua.no_progress_timer != None:
                self.ua.no_progress_timer.cancel()
                self.ua.no_progress_timer = None
            return (UaStateConnected, self.ua.conn_cbs, event.rtime)
        elif isinstance(event, CCEventRedirect):
            scode = event.getData()
            if scode == None:
                scode = (500, 'Failed', None, None)
            self.ua.sendUasResponse(scode[0], scode[1], scode[2], SipContact(address = SipAddress(url = scode[3])))
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            if self.ua.no_progress_timer != None:
                self.ua.no_progress_timer.cancel()
                self.ua.no_progress_timer = None
            return (UaStateFailed, self.ua.fail_cbs, event.rtime, scode[0])
        elif isinstance(event, CCEventFail):
            scode = event.getData()
            if scode == None:
                scode = (500, 'Failed')
            self.ua.sendUasResponse(scode[0], scode[1])
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            if self.ua.no_progress_timer != None:
                self.ua.no_progress_timer.cancel()
                self.ua.no_progress_timer = None
            return (UaStateFailed, self.ua.fail_cbs, event.rtime, scode[0])
        elif isinstance(event, CCEventDisconnect):
            #import sys, traceback
            #traceback.print_stack(file = sys.stdout)
            self.ua.sendUasResponse(500, 'Disconnected')
            if self.ua.expire_timer != None:
                self.ua.expire_timer.cancel()
                self.ua.expire_timer = None
            if self.ua.no_progress_timer != None:
                self.ua.no_progress_timer.cancel()
                self.ua.no_progress_timer = None
            return (UaStateDisconnected, self.ua.disc_cbs, event.rtime)
        #print 'wrong event %s in the Trying state' % event
        return None

    def cancel(self, rtime):
        self.ua.changeState((UaStateDisconnected, self.ua.disc_cbs, rtime))
        self.ua.emitEvent(CCEventDisconnect(rtime = rtime))

if not globals().has_key('UasStateRinging'):
    from UasStateRinging import UasStateRinging
if not globals().has_key('UaStateFailed'):
    from UaStateFailed import UaStateFailed
if not globals().has_key('UaStateConnected'):
    from UaStateConnected import UaStateConnected
if not globals().has_key('UaStateDisconnected'):
    from UaStateDisconnected import UaStateDisconnected
