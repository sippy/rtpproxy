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
# $Id: SipMsg.py,v 1.12 2008/12/08 23:54:50 sobomax Exp $

from SipHeader import SipHeader
from SipGenericHF import SipGenericHF
from SipContentLength import SipContentLength
from SipContentType import SipContentType
from MsgBody import MsgBody
from ESipHeaderCSV import ESipHeaderCSV
from ESipHeaderIgnore import ESipHeaderIgnore

class SipMsg:
    headers = None
    body = None
    startline = None
    target = None
    source = None
    nated = False
    rtime = None
    ignorebody = False

    def __init__(self, buf = None):
        self.headers = []
        if buf == None:
            return
        # Locate a body
        mbody = None
        for bdel in ('\r\n\r\n', '\r\r', '\n\n'):
            boff = buf.find(bdel)
            if boff != -1:
                mbody = buf[boff + len(bdel):]
                buf = buf[:boff]
                if len(mbody) == 0:
                    mbody = None
                break
        # Split message into lines and put aside start line
        lines = buf.splitlines()
        self.setSL(lines[0])
        i = 2
        while i < len(lines):
            if lines[i][0] in (' ', '\t'):
                lines[i - 1] += ' ' + lines[i].strip()
                del lines[i]
            else:
                i += 1
        # Parse headers
        for line in lines[1:]:
            try:
                self.headers.append(SipHeader(line, fixname = True))
            except ESipHeaderCSV, einst:
                for body in einst.bodys:
                    self.headers.append(SipHeader(name = einst.name, bodys = body))
            except ESipHeaderIgnore:
                continue
        if self.countHFs('via') == 0:
            raise Exception('Via HF is missed')
        if self.countHFs('to') == 0:
            raise Exception('To HF is missed')
        if self.countHFs('from') == 0:
            raise Exception('From HF is missed')
        if self.countHFs('cseq') == 0:
            raise Exception('CSeq HF is missed')
        if self.ignorebody:
            self.delHFs('content-type')
            self.delHFs('content-length')
            return
        if self.countHFs('content-length') > 0:
            blen = self.getHFBody('content-length').number
            if mbody == None:
                mblen = 0
            else:
                mblen = len(mbody)
            if blen == 0:
                mbody = None
                mblen = 0
            elif mbody == None:
                # XXX: Should generate 400 Bad Request if such condition
                # happens with request
                raise Exception('Missed SIP body, %d bytes expected' % blen)
            elif blen > mblen:
                if blen - mblen < 7 and mblen > 7 and mbody[-4:] == '\r\n\r\n':
                    # XXX: we should not really be doing this, but it appears to be
                    # a common off-by-one/two/.../six problem with SDPs generates by
                    # the consumer-grade devices.
                    print 'Truncated SIP body, %d bytes expected, %d received, fixing...' % (blen, mblen)
                    blen = mblen
                elif blen - mblen == 2 and mbody[-2:] == '\r\n':
                    # Missed last 2 \r\n is another common problem.
                    print 'Truncated SIP body, %d bytes expected, %d received, fixing...' % (blen, mblen)
                    mbody += '\r\n'
                elif blen - mblen == 1 and mbody[-3:] == '\r\n\n':
                    # Another possible mishap
                    print 'Truncated SIP body, %d bytes expected, %d received, fixing...' % (blen, mblen)
                    mbody = mbody[:-3] + '\r\n\r\n'
                else:
                    # XXX: Should generate 400 Bad Request if such condition
                    # happens with request
                    raise Exception('Truncated SIP body, %d bytes expected, %d received' % (blen, mblen))
            elif blen < mblen:
                mbody = mbody[:blen]
                mblen = blen
        if mbody != None:
            ct = self.getHFs('content-type')
            if len(ct) > 0:
                self.body = MsgBody(mbody, str(ct[0].body).lower())
                self.delHFs('content-type')
                self.delHFs('content-length')
            else:
                self.body = MsgBody(mbody)

    def __str__(self):
        s = str(self.getSL()) + '\r\n'
        for header in self.headers:
            s += str(header) + '\r\n'
        if self.body != None:
            mbody = str(self.body)
            s += 'Content-Length: %d\r\n' % len(mbody)
            s += 'Content-Type: %s\r\n\r\n' % self.body.mtype
            s += mbody
        else:
            s += '\r\n'
        return s

    def compactStr(self):
        s = str(self.getSL()) + '\r\n'
        for header in self.headers:
            s += header.compactStr() + '\r\n'
        if self.body != None:
            mbody = str(self.body)
            s += 'l: %d\r\n' % len(mbody)
            s += 'c: %s\r\n\r\n' % self.body.mtype
            s += mbody
        else:
            s += '\r\n'
        return s

    def setSL(self, startline):
        self.startline = startline

    def getSL(self):
        return self.startline

    def getHFs(self, name):
        return [x for x in self.headers if x.isName(name)]

    def countHFs(self, name):
        return len([x for x in self.headers if x.isName(name)])

    def delHFs(self, name):
        self.headers = [x for x in self.headers if not x.isName(name)]

    def getHF(self, name):
        return [x for x in self.headers if x.isName(name)][0]

    def getHFBodys(self, name):
        return [x.getBody() for x in self.headers if x.isName(name)]

    def getHFBody(self, name, idx = 0):
        return [x for x in self.headers if x.isName(name)][idx].getBody()

    def replaceHeader(self, oheader, nheader):
        self.headers[self.headers.index(oheader)] = nheader

    def removeHeader(self, header):
        self.headers.remove(header)

    def appendHeader(self, header):
        self.headers.append(header)

    def appendHeaders(self, headers):
        self.headers.extend(headers)

    def insertHeaderAfter(self, iheader, header):
        self.headers.insert(self.headers.index(iheader) + 1, header)

    def insertHeaderBefore(self, iheader, header):
        self.headers.insert(self.headers.index(iheader), header)

    def getBody(self):
        return self.body

    def setBody(self, body):
        self.body = body

    def getTarget(self):
        return self.target

    def setTarget(self, address):
        self.target = address

    def getSource(self):
        return self.source

    def setSource(self, address):
        self.source = address

    def getTId(self, wCSM = False, wBRN = False):
        cseq = self.getHFBody('cseq')
        rval = [str(self.getHFBody('call-id')), self.getHFBody('from').getTag(), cseq.getCSeqNum()]
        if wCSM:
            rval.append(cseq.getCSeqMethod())
        if wBRN:
            rval.append(self.getHFBody('via').getBranch())
        return tuple(rval)

    def getTIds(self):
        call_id = str(self.getHFBody('call-id'))
        ftag = self.getHFBody('from').getTag()
        cseq, method = self.getHFBody('cseq').getCSeq()
        rval = []
        for via in self.getHFBodys('via'):
            rval.append((call_id, ftag, cseq, method, via.getBranch()))
        return tuple(rval)
