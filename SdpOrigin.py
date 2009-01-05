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
#
# $Id: SdpOrigin.py,v 1.4 2009/01/05 20:14:00 sobomax Exp $

class SdpOrigin(object):
    username = None
    session_id = None
    version = None
    network_type = None
    address_type = None
    address = None

    def __init__(self, body = None, cself = None):
        if body != None:
            self.username, self.session_id, self.version, self.network_type, self.address_type, self.address = body.split()
        else:
            self.username = cself.username
            self.session_id = cself.session_id
            self.version = cself.version
            self.network_type = cself.network_type
            self.address_type = cself.address_type
            self.address = cself.address

    def __str__(self):
        return '%s %s %s %s %s %s' % (self.username, self.session_id, self.version, self.network_type, self.address_type, self.address)

    def getCopy(self):
        return SdpOrigin(cself = self)
