# Copyright (c) 2009 Sippy Software, Inc. All rights reserved.
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

from SipGenericHF import SipGenericHF

class SipReason(SipGenericHF):
    '''
    Class that implements RFC 3326 Reason header field.
    '''
    hf_names = ('reason',)
    protocol = None
    cause = None
    reason = None

    def __init__(self, body = None, protocol = None, cause = None, reason = None):
        SipGenericHF.__init__(self, body)
        if body == None:
            self.parsed = True
            self.protocol = protocol
            self.cause = cause
            self.reason = reason

    def parse(self):
        self.parsed = True
        protocol, reason_params = self.body.split(';', 1)
        self.protocol = protocol.strip()
        for reason_param in reason_params.split(';'):
            rp_name, rp_value = [x.strip() for x in reason_param.split('=', 1)]
            if rp_name == 'cause':
                self.cause = int(rp_value)
            elif rp_name == 'text':
                self.reason = rp_value.strip('"')
        assert(self.cause != None)

    def __str__(self):
        if not self.parsed:
            return self.body
        if self.reason == None:
            return '%s; cause=%d' % (self.protocol, self.cause)
        return '%s; cause=%d; text="%s"' % (self.protocol, self.cause, self.reason)

    def getCopy(self):
        if not self.parsed:
            return SipReason(self.body)
        return SipReason(protocol = self.protocol, cause = self.cause, reason = self.reason)
