#!/usr/local/bin/python
#
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

#import sys
#sys.path.append('..')

from sippy.Timeout import Timeout
from sippy.Signal import Signal
from sippy.SipFrom import SipFrom
from sippy.SipTo import SipTo
from sippy.SipCiscoGUID import SipCiscoGUID
from sippy.UA import UA
from sippy.CCEvents import CCEventRing, CCEventConnect, CCEventDisconnect, CCEventTry, CCEventUpdate, CCEventFail
from sippy.UasStateTrying import UasStateTrying
from sippy.UasStateRinging import UasStateRinging
from sippy.UaStateDead import UaStateDead
from sippy.SipConf import SipConf
from sippy.SipHeader import SipHeader
from sippy.RadiusAuthorisation import RadiusAuthorisation
from sippy.RadiusAccounting import RadiusAccounting
from sippy.FakeAccounting import FakeAccounting
from sippy.SipLogger import SipLogger
from sippy.Rtp_proxy_session import Rtp_proxy_session
from sippy.Rtp_proxy_client import Rtp_proxy_client
from signal import SIGHUP, SIGPROF, SIGUSR1, SIGUSR2
from twisted.internet import reactor
from urllib import unquote
from sippy.Cli_server_local import Cli_server_local
from sippy.SipTransactionManager import SipTransactionManager
from sippy.SipCallId import SipCallId
import gc, getopt, os, sys
from re import sub
from time import time
from urllib import quote
from hashlib import md5
from sippy.MyConfigParser import MyConfigParser

def re_replace(ptrn, s):
    s = s.split('#', 1)[0]
    ptrn = ptrn.split('/')
    while len(ptrn) > 0:
        op, p, r, mod = ptrn[:4]
        mod = mod.strip()
        if len(mod) > 0 and mod[0] != ';':
            ptrn[3] = mod[1:]
            mod = mod[0].lower()
        else:
            ptrn[3] = mod
        if 'g' in mod:
            s = sub(p, r, s)
        else:
            s = sub(p, r, s, 1)
        if len(ptrn) == 4 and ptrn[3] == '':
            break
        ptrn = ptrn[3:]
    return s

class CCStateIdle(object):
    sname = 'Idle'
class CCStateWaitRoute(object):
    sname = 'WaitRoute'
class CCStateARComplete(object):
    sname = 'ARComplete'
class CCStateConnected(object):
    sname = 'Connected'
class CCStateDead(object):
    sname = 'Dead'
class CCStateDisconnecting(object):
    sname = 'Disconnecting'

class CallController(object):
    id = 1
    uaA = None
    uaO = None
    state = None
    cId = None
    cld = None
    eTry = None
    routes = None
    remote_ip = None
    source = None
    acctA = None
    acctO = None
    global_config = None
    rtp_proxy_session = None
    huntstop_scodes = None
    pass_headers = None
    auth_proc = None
    proxied = False
    challenge = None

    def __init__(self, remote_ip, source, global_config, pass_headers):
        self.id = CallController.id
        CallController.id += 1
        self.global_config = global_config
        self.uaA = UA(self.global_config, event_cb = self.recvEvent, conn_cbs = (self.aConn,), disc_cbs = (self.aDisc,), \
          fail_cbs = (self.aDisc,), dead_cbs = (self.aDead,))
        self.uaA.kaInterval = self.global_config['keepalive_ans']
        self.state = CCStateIdle
        self.uaO = None
        self.routes = []
        self.remote_ip = remote_ip
        self.source = source
        self.pass_headers = pass_headers

    def recvEvent(self, event, ua):
        if ua == self.uaA:
            if self.state == CCStateIdle:
                if not isinstance(event, CCEventTry):
                    # Some weird event received
                    self.uaA.recvEvent(CCEventDisconnect(rtime = event.rtime))
                    return
                self.cId, cGUID, self.cli, self.cld, body, auth, self.caller_name = event.getData()
                self.cGUID = cGUID.hexForm()
                if self.cld == None:
                    self.uaA.recvEvent(CCEventFail((500, 'Internal Server Error (1)'), rtime = event.rtime))
                    self.state = CCStateDead
                    return
                if body == None:
                    self.uaA.recvEvent(CCEventFail((500, 'Body-less INVITE is not supported'), rtime = event.rtime))
                    self.state = CCStateDead
                    return
                if self.global_config.has_key('_allowed_pts'):
                    try:
                        body.parse()
                    except:
                        self.uaA.recvEvent(CCEventFail((400, 'Malformed SDP Body'), rtime = event.rtime))
                        self.state = CCStateDead
                        return
                    allowed_pts = self.global_config['_allowed_pts']
                    mbody = body.content.sections[0].m_header
                    if mbody.transport.lower() == 'rtp/avp':
                        mbody.formats = [x for x in mbody.formats if x in allowed_pts]
                        if len(mbody.formats) == 0:
                            self.uaA.recvEvent(CCEventFail((488, 'Not Acceptable Here')))
                            self.state = CCStateDead
                            return
                if self.cld.startswith('nat-'):
                    self.cld = self.cld[4:]
                    body.content += 'a=nated:yes\r\n'
                    event.data = (self.cId, cGUID, self.cli, self.cld, body, auth, self.caller_name)
                if self.global_config.has_key('static_tr_in'):
                    self.cld = re_replace(self.global_config['static_tr_in'], self.cld)
                    event.data = (self.cId, cGUID, self.cli, self.cld, body, auth, self.caller_name)
                if self.global_config.has_key('_rtp_proxy_clients'):
                    self.rtp_proxy_session = Rtp_proxy_session(self.global_config, call_id = self.cId, \
                      notify_socket = global_config['b2bua_socket'], \
                      notify_tag = quote('r %s' % str(self.id)))
                    self.rtp_proxy_session.callee_raddress = (self.remote_ip, 5060)
                self.eTry = event
                self.state = CCStateWaitRoute
                if not self.global_config['auth_enable']:
                    self.username = self.remote_ip
                    self.rDone(((), 0))
                elif auth == None or auth.username == None or len(auth.username) == 0:
                    self.username = self.remote_ip
                    self.auth_proc = self.global_config['_radius_client'].do_auth(self.remote_ip, self.cli, self.cld, self.cGUID, \
                      self.cId, self.remote_ip, self.rDone)
                else:
                    self.username = auth.username
                    self.auth_proc = self.global_config['_radius_client'].do_auth(auth.username, self.cli, self.cld, self.cGUID, 
                      self.cId, self.remote_ip, self.rDone, auth.realm, auth.nonce, auth.uri, auth.response)
                return
            if self.state not in (CCStateARComplete, CCStateConnected, CCStateDisconnecting) or self.uaO == None:
                return
            self.uaO.recvEvent(event)
        else:
            if (isinstance(event, CCEventFail) or isinstance(event, CCEventDisconnect)) and self.state == CCStateARComplete and \
              (isinstance(self.uaA.state, UasStateTrying) or isinstance(self.uaA.state, UasStateRinging)) and len(self.routes) > 0:
                if isinstance(event, CCEventFail):
                    code = event.getData()[0]
                else:
                    code = None
                if code == None or code not in self.huntstop_scodes:
                    self.placeOriginate(self.routes.pop(0))
                    return
            self.uaA.recvEvent(event)

    def rDone(self, results):
        # Check that we got necessary result from Radius
        if len(results) != 2 or results[1] != 0:
            if isinstance(self.uaA.state, UasStateTrying):
                if self.challenge != None:
                    event = CCEventFail((401, 'Unauthorized'))
                    event.extra_header = self.challenge
                else:
                    event = CCEventFail((403, 'Auth Failed'))
                self.uaA.recvEvent(event)
                self.state = CCStateDead
            return
        if self.global_config['acct_enable']:
            self.acctA = RadiusAccounting(self.global_config, 'answer', \
              send_start = self.global_config['start_acct_enable'], lperiod = \
              self.global_config.getdefault('alive_acct_int', None))
            self.acctA.ms_precision = self.global_config.getdefault('precise_acct', False)
            self.acctA.setParams(self.username, self.cli, self.cld, self.cGUID, self.cId, self.remote_ip)
        else:
            self.acctA = FakeAccounting()
        # Check that uaA is still in a valid state, send acct stop
        if not isinstance(self.uaA.state, UasStateTrying):
            self.acctA.disc(self.uaA, time(), 'caller')
            return
        cli = [x[1][4:] for x in results[0] if x[0] == 'h323-ivr-in' and x[1].startswith('CLI:')]
        if len(cli) > 0:
            self.cli = cli[0]
            if len(self.cli) == 0:
                self.cli = None
        caller_name = [x[1][5:] for x in results[0] if x[0] == 'h323-ivr-in' and x[1].startswith('CNAM:')]
        if len(caller_name) > 0:
            self.caller_name = caller_name[0]
            if len(self.caller_name) == 0:
                self.caller_name = None
        credit_time = [x for x in results[0] if x[0] == 'h323-credit-time']
        if len(credit_time) > 0:
            global_credit_time = int(credit_time[0][1])
        else:
            global_credit_time = None
        if not self.global_config.has_key('static_route'):
            routing = [x for x in results[0] if x[0] == 'h323-ivr-in' and x[1].startswith('Routing:')]
            if len(routing) == 0:
                self.uaA.recvEvent(CCEventFail((500, 'Internal Server Error (2)')))
                self.state = CCStateDead
                return
            routing = [x[1][8:].split(';') for x in routing]
        else:
            routing = [self.global_config['static_route'].split(';')]
        rnum = 0
        for route in routing:
            rnum += 1
            if route[0].find('@') != -1:
                cld, host = route[0].split('@')
                if len(cld) == 0:
                    # Allow CLD to be forcefully removed by sending `Routing:@host' entry,
                    # as opposed to the Routing:host, which means that CLD should be obtained
                    # from the incoming call leg.
                    cld = None
            else:
                cld = self.cld
                host = route[0]
            credit_time = global_credit_time
            expires = None
            no_progress_expires = None
            forward_on_fail = False
            user = None
            passw = None
            cli = self.cli
            parameters = {}
            parameters['extra_headers'] = self.pass_headers[:]
            for a, v in [x.split('=') for x in route[1:]]:
                if a == 'credit-time':
                    credit_time = int(v)
                    if credit_time < 0:
                        credit_time = None
                elif a == 'expires':
                    expires = int(v)
                    if expires < 0:
                        expires = None
                elif a == 'hs_scodes':
                    parameters['huntstop_scodes'] = tuple([int(x) for x in v.split(',') if len(x.strip()) > 0])
                elif a == 'np_expires':
                    no_progress_expires = int(v)
                    if no_progress_expires < 0:
                        no_progress_expires = None
                elif a == 'forward_on_fail':
                    forward_on_fail = True
                elif a == 'auth':
                    user, passw = v.split(':', 1)
                elif a == 'cli':
                    cli = v
                    if len(cli) == 0:
                        cli = None
                elif a == 'cnam':
                    caller_name = unquote(v)
                    if len(caller_name) == 0:
                        caller_name = None
                    parameters['caller_name'] = caller_name
                elif a == 'ash':
                    ash = SipHeader(unquote(v))
                    parameters['extra_headers'].append(ash)
                elif a == 'rtpp':
                    parameters['rtpp'] = (int(v) != 0)
                elif a == 'gt':
                    timeout, skip = v.split(',', 1)
                    parameters['group_timeout'] = (int(timeout), rnum + int(skip))
                else:
                    parameters[a] = v
            if self.global_config.has_key('max_credit_time'):
                if credit_time == None or credit_time > self.global_config['max_credit_time']:
                    credit_time = self.global_config['max_credit_time']
            if credit_time == 0 or expires == 0:
                continue
            self.routes.append((rnum, host, cld, credit_time, expires, no_progress_expires, forward_on_fail, user, \
              passw, cli, parameters))
            #print 'Got route:', host, cld
        if len(self.routes) == 0:
            self.uaA.recvEvent(CCEventFail((500, 'Internal Server Error (3)')))
            self.state = CCStateDead
            return
        self.state = CCStateARComplete
        self.placeOriginate(self.routes.pop(0))

    def placeOriginate(self, args):
        cId, cGUID, cli, cld, body, auth, caller_name = self.eTry.getData()
        rnum, host, cld, credit_time, expires, no_progress_expires, forward_on_fail, user, passw, cli, \
          parameters = args
        self.huntstop_scodes = parameters.get('huntstop_scodes', ())
        if self.global_config.has_key('static_tr_out'):
            cld = re_replace(self.global_config['static_tr_out'], cld)
        if host == 'sip-ua':
            host = self.source[0]
            port = self.source[1]
        else:
            if host.startswith('['):
                # IPv6
                host = host.split(']', 1)
                port = host[1].split(':', 1)
                host = host[0] + ']'
                if len(port) > 1:
                    port = int(port[1])
                else:
                    port = SipConf.default_port
            else:
                # IPv4
                host = host.split(':', 1)
                if len(host) > 1:
                    port = int(host[1])
                else:
                    port = SipConf.default_port
                host = host[0]
        if not forward_on_fail and self.global_config['acct_enable']:
            self.acctO = RadiusAccounting(self.global_config, 'originate', \
              send_start = self.global_config['start_acct_enable'], lperiod = \
              self.global_config.getdefault('alive_acct_int', None))
            self.acctO.ms_precision = self.global_config.getdefault('precise_acct', False)
            self.acctO.setParams(parameters.get('bill-to', self.username), parameters.get('bill-cli', cli), \
              parameters.get('bill-cld', cld), self.cGUID, self.cId, host)
        else:
            self.acctO = None
        self.acctA.credit_time = credit_time
        conn_handlers = [self.oConn]
        disc_handlers = []
        if not forward_on_fail and self.global_config['acct_enable']:
            disc_handlers.append(self.acctO.disc)
        self.uaO = UA(self.global_config, self.recvEvent, user, passw, (host, port), credit_time, tuple(conn_handlers), \
          tuple(disc_handlers), tuple(disc_handlers), dead_cbs = (self.oDead,), expire_time = expires, \
          no_progress_time = no_progress_expires, extra_headers = parameters.get('extra_headers', None))
        if self.rtp_proxy_session != None and parameters.get('rtpp', True):
            self.uaO.on_local_sdp_change = self.rtp_proxy_session.on_caller_sdp_change
            self.uaO.on_remote_sdp_change = self.rtp_proxy_session.on_callee_sdp_change
            self.rtp_proxy_session.caller_raddress = (host, port)
            body = body.getCopy()
            body.content += 'a=nortpproxy:yes\r\n'
            self.proxied = True
        self.uaO.kaInterval = self.global_config['keepalive_orig']
        if parameters.has_key('group_timeout'):
            timeout, skipto = parameters['group_timeout']
            Timeout(self.group_expires, timeout, 1, skipto)
        if self.global_config.getdefault('hide_call_id', False):
            cId = SipCallId(md5(str(cId)).hexdigest() + ('-b2b_%d' % rnum))
        else:
            cId += '-b2b_%d' % rnum
        event = CCEventTry((cId, cGUID, cli, cld, body, auth, \
          parameters.get('caller_name', self.caller_name)))
        event.reason = self.eTry.reason
        self.uaO.recvEvent(event)

    def disconnect(self, rtime = None):
        self.uaA.disconnect(rtime = rtime)

    def oConn(self, ua, rtime, origin):
        if self.acctO != None:
            self.acctO.conn(ua, rtime, origin)

    def aConn(self, ua, rtime, origin):
        self.state = CCStateConnected
        self.acctA.conn(ua, rtime, origin)

    def aDisc(self, ua, rtime, origin, result = 0):
        if self.state == CCStateWaitRoute and self.auth_proc != None:
            self.auth_proc.cancel()
            self.auth_proc = None
        if self.uaO != None and self.state != CCStateDead:
            self.state = CCStateDisconnecting
        else:
            self.state = CCStateDead
        if self.acctA != None:
            self.acctA.disc(ua, rtime, origin, result)
        self.rtp_proxy_session = None

    def aDead(self, ua):
        if (self.uaO == None or isinstance(self.uaO.state, UaStateDead)):
            if self.global_config['_cmap'].debug_mode:
                print 'garbadge collecting', self
            self.acctA = None
            self.acctO = None
            self.global_config['_cmap'].ccmap.remove(self)

    def oDead(self, ua):
        if ua == self.uaO and isinstance(self.uaA.state, UaStateDead):
            if self.global_config['_cmap'].debug_mode:
                print 'garbadge collecting', self
            self.acctA = None
            self.acctO = None
            self.global_config['_cmap'].ccmap.remove(self)

    def group_expires(self, skipto):
        if self.state != CCStateARComplete or len(self.routes) == 0 or self.routes[0][0] > skipto or \
          (not isinstance(self.uaA.state, UasStateTrying) and not isinstance(self.uaA.state, UasStateRinging)):
            return
        # When the last group in the list has timeouted don't disconnect
        # the current attempt forcefully. Instead, make sure that if the
        # current originate call leg fails no more routes will be
        # processed.
        if skipto == self.routes[-1][0] + 1:
            self.routes = []
            return
        while self.routes[0][0] != skipto:
            self.routes.pop(0)
        self.uaO.disconnect()

class CallMap(object):
    ccmap = None
    el = None
    debug_mode = False
    safe_restart = False
    global_config = None
    #rc1 = None
    #rc2 = None

    def __init__(self, global_config):
        self.global_config = global_config
        self.ccmap = []
        self.el = Timeout(self.GClector, 60, -1)
        Signal(SIGHUP, self.discAll, SIGHUP)
        Signal(SIGUSR2, self.toggleDebug, SIGUSR2)
        Signal(SIGPROF, self.safeRestart, SIGPROF)
        #gc.disable()
        #gc.set_debug(gc.DEBUG_STATS)
        #gc.set_threshold(0)
        #print gc.collect()

    def recvRequest(self, req):
        if req.getHFBody('to').getTag() != None:
            # Request within dialog, but no such dialog
            return (req.genResponse(481, 'Call Leg/Transaction Does Not Exist'), None, None)
        if req.getMethod() == 'INVITE':
            # New dialog
            if req.countHFs('via') > 1:
                via = req.getHFBody('via', 1)
            else:
                via = req.getHFBody('via', 0)
            remote_ip = via.getTAddr()[0]
            source = req.getSource()

            # First check if request comes from IP that
            # we want to accept our traffic from
            if self.global_config.has_key('_accept_ips') and \
              not source[0] in self.global_config['_accept_ips']:
                resp = req.genResponse(403, 'Forbidden')
                return (resp, None, None)

            challenge = None
            if self.global_config['auth_enable']:
                # Prepare challenge if no authorization header is present.
                # Depending on configuration, we might try remote ip auth
                # first and then challenge it or challenge immediately.
                if self.global_config['digest_auth'] and \
                  req.countHFs('authorization') == 0:
                    challenge = SipHeader(name = 'www-authenticate')
                    challenge.getBody().realm = req.getRURI().host
                # Send challenge immediately if digest is the
                # only method of authenticating
                if challenge != None and self.global_config.getdefault('digest_auth_only', False):
                    resp = req.genResponse(401, 'Unauthorized')
                    resp.appendHeader(challenge)
                    return (resp, None, None)

            pass_headers = []
            for header in self.global_config['_pass_headers']:
                hfs = req.getHFs(header)
                if len(hfs) > 0:
                    pass_headers.extend(hfs)
            cc = CallController(remote_ip, source, self.global_config, pass_headers)
            cc.challenge = challenge
            rval = cc.uaA.recvRequest(req)
            self.ccmap.append(cc)
            return rval
        if req.getMethod() in ('NOTIFY', 'PING'):
            # Whynot?
            return (req.genResponse(200, 'OK'), None, None)
        return (req.genResponse(501, 'Not Implemented'), None, None)

    def discAll(self, signum = None):
        if signum != None:
            print 'Signal %d received, disconnecting all calls' % signum
        for cc in tuple(self.ccmap):
            cc.disconnect()

    def toggleDebug(self, signum):
        if self.debug_mode:
            print 'Signal %d received, toggling extra debug output off' % signum
        else:
            print 'Signal %d received, toggling extra debug output on' % signum
        self.debug_mode = not self.debug_mode

    def safeRestart(self, signum):
        print 'Signal %d received, scheduling safe restart' % signum
        self.safe_restart = True

    def GClector(self):
        print 'GC is invoked, %d calls in map' % len(self.ccmap)
        if self.debug_mode:
            print self.global_config['_sip_tm'].tclient, self.global_config['_sip_tm'].tserver
            for cc in tuple(self.ccmap):
                try:
                    print cc.uaA.state, cc.uaO.state
                except AttributeError:
                    print None
        else:
            print '%d client, %d server transactions in memory' % \
              (len(self.global_config['_sip_tm'].tclient), len(self.global_config['_sip_tm'].tserver))
        if self.safe_restart:
            if len(self.ccmap) == 0:
                self.global_config['_sip_tm'].userv.close()
                os.chdir(self.global_config['_orig_cwd'])
                argv = [sys.executable,]
                argv.extend(self.global_config['_orig_argv'])
                os.execv(sys.executable, argv)
                # Should not reach this point!
            self.el.ival = 1
        #print gc.collect()
        if len(gc.garbage) > 0:
            print gc.garbage

    def recvCommand(self, clim, cmd):
        args = cmd.split()
        cmd = args.pop(0).lower()
        if cmd == 'q':
            clim.close()
            return False
        if cmd == 'l':
            res = 'In-memory calls:\n'
            total = 0
            for cc in self.ccmap:
                res += '%s: %s (' % (cc.cId, cc.state.sname)
                if cc.uaA != None:
                    res += '%s %s:%d %s %s -> ' % (cc.uaA.state, cc.uaA.getRAddr0()[0], \
                      cc.uaA.getRAddr0()[1], cc.uaA.getCLD(), cc.uaA.getCLI())
                else:
                    res += 'N/A -> '
                if cc.uaO != None:
                    res += '%s %s:%d %s %s)\n' % (cc.uaO.state, cc.uaO.getRAddr0()[0], \
                      cc.uaO.getRAddr0()[1], cc.uaO.getCLI(), cc.uaO.getCLD())
                else:
                    res += 'N/A)\n'
                total += 1
            res += 'Total: %d\n' % total
            clim.send(res)
            return False
        if cmd == 'd':
            if len(args) != 1:
                clim.send('ERROR: syntax error: d <call-id>\n')
                return False
            if args[0] == '*':
                self.discAll()
                clim.send('OK\n')
                return False
            dlist = [x for x in self.ccmap if str(x.cId) == args[0]]
            if len(dlist) == 0:
                clim.send('ERROR: no call with id of %s has been found\n' % args[0])
                return False
            for cc in dlist:
                cc.disconnect()
            clim.send('OK\n')
            return False
        if cmd == 'r':
            if len(args) != 1:
                clim.send('ERROR: syntax error: r [<id>]\n')
                return False
            idx = int(args[0])
            dlist = [x for x in self.ccmap if x.id == idx]
            if len(dlist) == 0:
                clim.send('ERROR: no call with id of %d has been found\n' % idx)
                return False
            for cc in dlist:
                if cc.state == CCStateConnected and cc.proxied:
                    cc.disconnect(time() - 60)
            clim.send('OK\n')
            return False
        clim.send('ERROR: unknown command\n')
        return False

def reopen(signum, logfile):
    print 'Signal %d received, reopening logs' % signum
    fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    os.dup2(fd, sys.__stdout__.fileno())
    os.dup2(fd, sys.__stderr__.fileno())
    os.close(fd)

def usage(global_config, brief = False):
    print 'usage: b2bua.py [--option1=value1] [--option2=value2] ... [--optionN==valueN]'
    if not brief:
        print '\navailable options:\n'
        global_config.options_help()
    sys.exit(1)

if __name__ == '__main__':
    global_config = MyConfigParser()
    global_config['digest_auth'] = True
    global_config['start_acct_enable'] = False
    global_config['keepalive_ans'] = 0
    global_config['keepalive_orig'] = 0
    global_config['auth_enable'] = True
    global_config['acct_enable'] = True
    global_config['_pass_headers'] = []
    global_config['_orig_argv'] = sys.argv[:]
    global_config['_orig_cwd'] = os.getcwd()
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'fDl:p:d:P:L:s:a:t:T:k:m:A:ur:F:R:h:c:M:HC:W:',
          global_config.get_longopts())
    except getopt.GetoptError:
        usage(global_config)
    global_config['foreground'] = False
    global_config['pidfile'] = '/var/run/b2bua.pid'
    global_config['logfile'] = '/var/log/b2bua.log'
    global_config['b2bua_socket'] = '/var/run/b2bua.sock'
    global_config['_sip_address'] = SipConf.my_address
    global_config['_sip_port'] = SipConf.my_port
    rtp_proxy_clients = []
    writeconf = None
    for o, a in opts:
        if o == '-f':
            global_config['foreground'] = True
            continue
        if o == '-l':
            global_config.check_and_set('sip_address', a)
            continue
        if o == '-p':
            global_config.check_and_set('sip_port', a)
            continue
        if o == '-P':
            global_config.check_and_set('pidfile', a)
            continue
        if o == '-L':
            global_config.check_and_set('logfile', a)
            continue
        if o == '-s':
            global_config.check_and_set('static_route', a)
            continue
        if o == '-a':
            global_config.check_and_set('accept_ips', a)
            continue
        if o == '-D':
            global_config['digest_auth'] = False
            continue
        if o == '-A':
            acct_level = int(a.strip())
            if acct_level == 0:
                global_config['acct_enable'] = False
                global_config['start_acct_enable'] = False
            elif acct_level == 1:
                global_config['acct_enable'] = True
                global_config['start_acct_enable'] = False
            elif acct_level == 2:
                global_config['acct_enable'] = True
                global_config['start_acct_enable'] = True
            else:
                sys.__stderr__.write('ERROR: -A argument not in the range 0-2\n')
                usage(global_config, True)
            continue
        if o == '-t':
            global_config.check_and_set('static_tr_in', a)
            continue
        if o == '-T':
            global_config.check_and_set('static_tr_out', a)
            continue
        if o == '-k':
            ka_level = int(a.strip())
            if ka_level == 0:
                pass
            elif ka_level == 1:
                global_config['keepalive_ans'] = 32
            elif ka_level == 2:
                global_config['keepalive_orig'] = 32
            elif ka_level == 3:
                global_config['keepalive_ans'] = 32
                global_config['keepalive_orig'] = 32
            else:
                sys.__stderr__.write('ERROR: -k argument not in the range 0-3\n')
                usage(global_config, True)
        if o == '-m':
            global_config.check_and_set('max_credit_time', a)
            continue
        if o == '-u':
            global_config['auth_enable'] = False
            continue
        if o == '-r':
            global_config.check_and_set('rtp_proxy_client', a)
            continue
        if o == '-F':
            global_config.check_and_set('allowed_pts', a)
            continue
        if o == '-R':
            global_config.check_and_set('radiusclient.conf', a)
            continue
        if o == '-h':
            for a in a.split(','):
                global_config.check_and_set('pass_header', a)
            continue
        if o == '-c':
            global_config.check_and_set('b2bua_socket', a)
            continue
        if o == '-M':
            global_config.check_and_set('max_radiusclients', a)
            continue
        if o == '-H':
            global_config['hide_call_id'] = True
            continue
        if o in ('-C', '--config'):
            global_config.read(a.strip())
            continue
        if o.startswith('--'):
            global_config.check_and_set(o[2:], a)
            continue
        if o == '-W':
            writeconf = a.strip()
            continue

    if global_config.has_key('_rtp_proxy_clients'):
        for a in global_config['_rtp_proxy_clients']:
            if a.startswith('udp:'):
                a = a.split(':', 2)
                if len(a) == 2:
                    rtp_proxy_address = (a[1], 22222)
                else:
                    rtp_proxy_address = (a[1], int(a[2]))
                rtp_proxy_clients.append(rtp_proxy_address)
            else:
                rtp_proxy_clients.append(a)

    if not global_config['auth_enable'] and not global_config.has_key('static_route'):
        sys.__stderr__.write('ERROR: static route should be specified when Radius auth is disabled\n')
        usage(global_config, True)

    if writeconf != None:
        global_config.write(open(writeconf, 'w'))

    if not global_config['foreground']:
        #print 'foobar'
        # Fork once
        if os.fork() != 0:
            os._exit(0)
        # Create new session
        os.setsid()
        if os.fork() != 0:
            os._exit(0)
        os.chdir('/')
        fd = os.open('/dev/null', os.O_RDONLY)
        os.dup2(fd, sys.__stdin__.fileno())
        os.close(fd)
        fd = os.open(global_config['logfile'], os.O_WRONLY | os.O_CREAT | os.O_APPEND)
        os.dup2(fd, sys.__stdout__.fileno())
        os.dup2(fd, sys.__stderr__.fileno())
        os.close(fd)

    global_config['_sip_logger'] = SipLogger('b2bua')

    if len(rtp_proxy_clients) > 0:
        global_config['_rtp_proxy_clients'] = []
        for address in rtp_proxy_clients:
            global_config['_rtp_proxy_clients'].append(Rtp_proxy_client(global_config, address))

    if global_config['auth_enable'] or global_config['acct_enable']:
        global_config['_radius_client'] = RadiusAuthorisation(global_config)
    SipConf.my_uaname = 'Sippy B2BUA (RADIUS)'

    global_config['_cmap'] = CallMap(global_config)

    global_config['_sip_tm'] = SipTransactionManager(global_config, global_config['_cmap'].recvRequest)

    cmdfile = global_config['b2bua_socket']
    if cmdfile.startswith('unix:'):
        cmdfile = cmdfile[5:]
    cli_server = Cli_server_local(global_config['_cmap'].recvCommand, cmdfile)

    if not global_config['foreground']:
        file(global_config['pidfile'], 'w').write(str(os.getpid()) + '\n')
        Signal(SIGUSR1, reopen, SIGUSR1, global_config['logfile'])

    reactor.run(installSignalHandlers = True)
