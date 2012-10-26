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

from time import time

class CCEventGeneric(object):
    data = None
    name = None
    rtime = None
    origin = None
    reason = None
    extra_header = None
    seq = 1

    def __init__(self, data = None, rtime = None, origin = None):
        self.data = data
        if rtime == None:
            self.rtime = time()
        else:
            self.rtime = rtime
        self.seq = CCEventGeneric.seq
        CCEventGeneric.seq += 1
        self.origin = origin

    def getData(self):
        return self.data

    def getCopy(self):
        cself = self.__class__(self.data, self.rtime, self.origin)
        if self.reason != None:
            cself.reason = self.reason.getCopy()
        if self.extra_header != None:
            cself.extra_header = self.extra_header.getCopy()
        return cself

    def __str__(self):
        return self.name

class CCEventTry(CCEventGeneric):
    name = 'CCEventTry'
    pass

class CCEventRing(CCEventGeneric):
    name = 'CCEventRing'
    pass

class CCEventPreConnect(CCEventGeneric):
    name = 'CCEventPreConnect'
    pass

class CCEventConnect(CCEventGeneric):
    name = 'CCEventConnect'
    pass

class CCEventUpdate(CCEventGeneric):
    name = 'CCEventUpdate'
    pass

class CCEventInfo(CCEventGeneric):
    name = 'CCEventInfo'
    pass

class CCEventDisconnect(CCEventGeneric):
    name = 'CCEventDisconnect'
    pass

class CCEventFail(CCEventGeneric):
    name = 'CCEventFail'
    challenge = None

    def getCopy(self):
        cself = CCEventGeneric.getCopy(self)
        if self.challenge != None:
            cself.challenge = self.challenge.getCopy()
        return cself

class CCEventRedirect(CCEventGeneric):
    name = 'CCEventRedirect'
    pass
