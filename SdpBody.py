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

from SdpField import SdpField
from SdpBodySection import SdpBodySection

class SdpBody:
    sections = None

    def __init__(self, body = None, cself = None):
        if cself != None:
            self.sections = map(lambda x: x.getCopy(), cself.sections)
            return
        if body != None:
            headers = map(lambda x: SdpField(x), body.strip().splitlines())
        else:
            headers = []
        self.sections = []
        current_snum = 0
        for header in tuple(headers):
            if header.isName('m'):
                # Protect against degenerative cases when SDP has no "global" secion.
                # Add fake one in such cases.
                if len(self.sections) == 0:
                    self.sections.append(SdpBodySection())
                current_snum += 1
            if len(self.sections) == current_snum:
                self.sections.append(SdpBodySection(headers = [header]))
            else:
                self.sections[current_snum].headers.append(header)
        if len(self.sections) > 1 and self.sections[0].countFs('c') > 0:
            for section in self.sections[1:]:
                # Add `c' into each section that doesn't have it using global `c'
                # This should simplify things quite a bit later when we need
                # to modify something
                if section.countFs('c') == 0:
                    iheader = section.getF('m')
                    nheader = self.sections[0].getF('c').getCopy()
                    section.insertFAfter(iheader, nheader)
            # Remove global `c' - we don't really need it if there are any
            # media sections
            self.sections[0].delFs('c')

    def __str__(self):
        return reduce(lambda x, y: str(x) + str(y), self.sections)

    def __iadd__(self, other):
        self.sections[-1] += other
        return self

    def getCopy(self):
        return SdpBody(cself = self)
