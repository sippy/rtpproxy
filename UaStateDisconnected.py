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

class UaStateDisconnected(UaStateGeneric):
    sname = 'Disconnected'

    def __init__(self, ua):
        UaStateGeneric.__init__(self, ua)
        ua.on_local_sdp_change = None
        ua.on_remote_sdp_change = None
        Timeout(self.goDead, 32.0)

    def recvRequest(self, req):
        if req.getMethod() == 'BYE':
            #print 'BYE received in the Disconnected state'
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(200, 'OK'))
        else:
            self.ua.global_config['_sip_tm'].sendResponse(req.genResponse(500, 'Disconnected'))
        return None

    def goDead(self):
        #print 'Time in Disconnected state expired, going to the Dead state'
        self.ua.changeState((UaStateDead,))

if not globals().has_key('UaStateDead'):
    from UaStateDead import UaStateDead
