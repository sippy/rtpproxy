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

from time import time, strftime, gmtime
from Timeout import Timeout

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

class RadiusAccounting(object):
    global_config = None
    drec = None
    crec = None
    iTime = None
    cTime = None
    sip_cid = None
    origin = None
    lperiod = None
    el = None
    send_start = None
    complete = False
    ms_precision = False
    user_agent = None
    p1xx_ts = None
    p100_ts = None

    def __init__(self, global_config, origin, lperiod = None, send_start = False):
        self.global_config = global_config
        self._attributes = [('h323-call-origin', origin), ('h323-call-type', 'VoIP'), \
          ('h323-session-protocol', 'sipv2')]
        self.drec = False
        self.crec = False
        self.origin = origin
        self.lperiod = lperiod
        self.send_start = send_start

    def setParams(self, username, caller, callee, h323_cid, sip_cid, remote_ip, \
      h323_in_cid = None):
        if caller == None:
            caller = ''
        self._attributes.extend((('User-Name', username), ('Calling-Station-Id', caller), \
          ('Called-Station-Id', callee), ('h323-conf-id', h323_cid), ('call-id', sip_cid), \
          ('Acct-Session-Id', sip_cid), ('h323-remote-address', remote_ip)))
        if h323_in_cid != None and h323_in_cid != h323_cid:
            self._attributes.append(('h323-incoming-conf-id', h323_in_cid))
        self.sip_cid = str(sip_cid)
        self.complete = True

    def conn(self, ua, rtime, origin):
        if self.crec:
            return
        self.crec = True
        self.iTime = ua.setup_ts
        self.cTime = ua.connect_ts
        if ua.user_agent != None and self.user_agent == None:
            self.user_agent = ua.user_agent
        if ua.p1xx_ts != None:
            self.p1xx_ts = ua.p1xx_ts
        if ua.p100_ts != None:
            self.p100_ts = ua.p100_ts
        if self.send_start:
            self.asend('Start', rtime, origin, ua)
        self._attributes.extend((('h323-voice-quality', 0), ('Acct-Terminate-Cause', 'User-Request')))
        if self.lperiod != None and self.lperiod > 0:
            self.el = Timeout(self.asend, self.lperiod, -1, 'Alive')

    def disc(self, ua, rtime, origin, result = 0):
        if self.drec:
            return
        self.drec = True
        if self.el != None:
            self.el.cancel()
            self.el = None
        if self.iTime == None:
            self.iTime = ua.setup_ts
        if self.cTime == None:
            self.cTime = rtime
        if ua.user_agent != None and self.user_agent == None:
            self.user_agent = ua.user_agent
        if ua.p1xx_ts != None:
            self.p1xx_ts = ua.p1xx_ts
        if ua.p100_ts != None:
            self.p100_ts = ua.p100_ts
        self.asend('Stop', rtime, origin, result, ua)

    def asend(self, type, rtime = None, origin = None, result = 0, ua = None):
        if not self.complete:
            return
        if rtime == None:
            rtime = time()
        if ua != None:
            duration, delay, connected = ua.getAcct()[:3]
        else:
            # Alive accounting
            duration = rtime - self.cTime
            delay = self.cTime - self.iTime
            connected = True
        if not(self.ms_precision):
            duration = round(duration)
            delay = round(delay)
        attributes = self._attributes[:]
        if type != 'Start':
            if result >= 400:
                try:
                    dc = sipErrToH323Err[result][0]
                except:
                    dc = '7f'
            elif result < 200:
                dc = '10'
            else:
                dc = '0'
            attributes.extend((('h323-disconnect-time', self.ftime(self.iTime + delay + duration)), \
              ('Acct-Session-Time', '%d' % round(duration)), ('h323-disconnect-cause', dc)))
        if type == 'Stop':
            if origin == 'caller':
                release_source = '2'
            elif origin == 'callee':
                release_source = '4'
            else:
                release_source = '8'
            attributes.append(('release-source', release_source))
        attributes.extend((('h323-connect-time', self.ftime(self.iTime + delay)), ('h323-setup-time', self.ftime(self.iTime)), \
          ('Acct-Status-Type', type)))
        if self.user_agent != None:
            attributes.append(('h323-ivr-out', 'sip_ua:' + self.user_agent))
        if self.p1xx_ts != None:
            attributes.append(('Acct-Delay-Time', round(self.p1xx_ts)))
        if self.p100_ts != None:
            attributes.append(('provisional-timepoint', self.ftime(self.p100_ts)))
        pattributes = ['%-32s = \'%s\'\n' % (x[0], str(x[1])) for x in attributes]
        pattributes.insert(0, 'sending Acct %s (%s):\n' % (type, self.origin.capitalize()))
        self.global_config['_sip_logger'].write(call_id = self.sip_cid, *pattributes)
        self.global_config['_radius_client'].do_acct(attributes, self._process_result, self.sip_cid, time())

    def ftime(self, t):
        gt = gmtime(t)
        day = strftime('%d', gt)
        if day[0] == '0':
            day = day[1]
        if self.ms_precision:
            msec = (t % 1) * 1000
        else:
            msec = 0
        return strftime('%%H:%%M:%%S.%.3d GMT %%a %%b %s %%Y' % (msec, day), gt)

    def _process_result(self, results, sip_cid, btime):
        delay = time() - btime
        rcode = results[1]
        if rcode in (0, 1):
            if rcode == 0:
                message = 'Acct/%s request accepted (delay is %.3f)\n' % (self.origin, delay)
            else:
                message = 'Acct/%s request rejected (delay is %.3f)\n' % (self.origin, delay)
        else:
            message = 'Error sending Acct/%s request (delay is %.3f)\n' % (self.origin, delay)
        self.global_config['_sip_logger'].write(message, call_id = sip_cid)
