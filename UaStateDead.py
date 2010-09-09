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

class UaStateDead(UaStateGeneric):
    sname = 'Dead'
    dead = True

    def __init__(self, ua):
        UaStateGeneric.__init__(self, None)
        if ua.cId != None:
            ua.global_config['_sip_tm'].unregConsumer(ua, str(ua.cId))
        ua.tr = None
        ua.event_cb = None
        ua.conn_cbs = ()
        ua.disc_cbs = ()
        ua.fail_cbs = ()
        ua.on_local_sdp_change = None
        ua.on_remote_sdp_change = None
        ua.expire_timer = None
        ua.no_progress_timer = None
        ua.credit_timer = None
        # Keep this at the very end of processing
        for callback in ua.dead_cbs:
            callback(ua)
        ua.dead_cbs = ()
        ua.cleanup()
        # Break cross-ref chain
        self.ua = None
