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
# $Id: RadiusAccounting.py,v 1.2 2008/02/18 19:49:45 sobomax Exp $

from time import time, strftime, gmtime
from Timeout import Timeout

def ftime(t):
    gt = gmtime(t)
    day = strftime('%d', gt)
    if day[0] == '0':
        day = day[1]
    return strftime('%%H:%%M:%%S.000 GMT %%a %%b %s %%Y' % day, gt)

sipErrToH323Err = {400:('7f', 'Interworking, unspecified'), 401:('39', 'Bearer capability not authorized'), \
  402:('15', 'Call rejected'), 403:('39', 'Bearer capability not authorized'), 404:('1', 'Unallocated number'), \
  405:('7f', 'Interworking, unspecified'), 406:('7f', 'Interworking, unspecified'), 407:('15', 'Call rejected'), \
  408:('66', 'Recover on Expires timeout'), 409:('29', 'Temporary failure'), 410:('1', 'Unallocated number'), \
  411:('7f', 'Interworking, unspecified'), 413:('7f', 'Interworking, unspecified'), 414:('7f', 'Interworking, unspecified'), \
  415:('4f', 'Service or option not implemented'), 420:('7f', 'Interworking, unspecified'), 480:('12', 'No user response'), \
  481:('7f', 'Interworking, unspecified'), 482:('7f', 'Interworking, unspecified'), 483:('7f', 'Interworking, unspecified'), \
  484:('1c', 'Address incomplete'), 485:('1', 'Unallocated number'), 486:('11', 'User busy'), 487:('12', 'No user responding'), \
  488:('7f', 'Interworking, unspecified'), 500:('29', 'Temporary failure'), 501:('4f', 'Service or option not implemented'), \
  502:('26', 'Network out of order'), 503:('3f', 'Service or option unavailable'), 504:('66', 'Recover on Expires timeout'), \
  505:('7f', 'Interworking, unspecified'), 580:('2f', 'Resource unavailable, unspecified'), 600:('11', 'User busy'), \
  603:('15', 'Call rejected'), 604:('1',  'Unallocated number'), 606:('3a', 'Bearer capability not presently available')}

class RadiusAccounting:
    global_config = None
    drec = None
    crec = None
    iTime = None
    cTime = None
    credit_time = None
    sip_cid = None
    origin = None
    lperiod = None
    el = None
    send_start = None
    complete = False
    origin = None
    username = None
    caller = None
    callee = None
    h323_cid = None
    sip_cid = None
    remote_ip = None
    user_agent = None

    def __init__(self, global_config, origin, lperiod = None, send_start = False, itime = None):
        if itime == None:
            self.iTime = time()
        else:
            self.iTime = itime
        self.global_config = global_config
        self.origin = origin
        self.drec = False
        self.crec = False
        self.origin = origin
        self.lperiod = lperiod
        self.send_start = send_start

    def setParams(self, username, caller, callee, h323_cid, sip_cid, remote_ip, \
      credit_time = None, h323_in_cid = None):
        if caller == None:
            caller = ''
        self.username = username
        self.caller = caller
        self.callee = callee
        self.h323_cid = h323_cid
        self.sip_cid = sip_cid
        self.remote_ip = remote_ip
        self.credit_time = credit_time
        self.sip_cid = str(sip_cid)
        self.complete = True

    def conn(self, ua, rtime, origin):
        if self.crec:
            return
        self.crec = True
        self.cTime = rtime
        if self.send_start:
            self.asend('Start', rtime)
        if self.lperiod != None:
            self.el = Timeout(self.asend, self.lperiod, -1, 'Alive')

    def disc(self, ua, rtime, origin, result = 0):
        if self.drec:
            return
        self.drec = True
        if self.el != None:
            self.el.cancel()
            self.el = None
        self.user_agent = ua.user_agent
        self.asend('Stop', rtime, result)

    def asend(self, type, rtime = None, result = 0):
        if not self.complete:
            return
        if rtime == None:
            rtime = time()
        if type != 'Start':
            if self.cTime != None:
                duration = rtime - self.cTime
                delay = self.cTime - self.iTime
            else:
                duration = 0
                delay = rtime - self.iTime
            if self.credit_time != None and duration > self.credit_time and duration < self.credit_time + 10:
                duration = self.credit_time
            if result >= 400:
                try:
                    dc = sipErrToH323Err[result][0]
                except:
                    dc = '7f'
            elif result < 200:
                dc = '10'
            else:
                dc = '0'
        self.global_config['_cstats'].update(self.remote_ip, duration)
        self.global_config['_radius_client'].do_acct(self.username, self.caller, self.callee, \
          self.h323_cid, self.sip_cid, self.remote_ip, type, duration, self.origin, dc, self.user_agent)
