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
from Udp_server import Udp_server
from SipHeader import SipHeader
from SipResponse import SipResponse
from SipRequest import SipRequest
from SipAddress import SipAddress
from SipRoute import SipRoute
from SipHeader import SipHeader
from datetime import datetime
from hashlib import md5
from traceback import print_exc
from time import time
import sys, socket

class NETS_1918(object):
    nets = (('10.0.0.0', 0xffffffffl << 24), ('172.16.0.0',  0xffffffffl << 20), ('192.168.0.0', 0xffffffffl << 16))
    nets = [(reduce(lambda z, v: (int(z) << 8l) | int(v), x[0].split('.', 4)) & x[1], x[1]) for x in nets]

def check1918(addr):
    try:
        addr = reduce(lambda x, y: (int(x) << 8l) | int(y), addr.split('.', 4))
        for naddr, mask in NETS_1918.nets:
            if addr & mask == naddr:
                return True
    except:
        pass
    return False

class SipTransaction(object):
    tout = None
    tid = None
    address = None
    data = None
    checksum = None

    def cleanup(self):
        self.ack = None
        self.cancel = None
        self.resp_cb = None
        self.cancel_cb = None
        self.noack_cb = None
        self.r487 = None
        self.address = None
        self.teA = self.teB = self.teC = self.teD = self.teE = self.teF = None
        self.tid = None
        self.userv = None
        self.r408 = None

# Symbolic states names
class SipTransactionState(object):
    pass
class TRYING(SipTransactionState):
    # Request sent, but no reply received at all
    pass
class RINGING(SipTransactionState):
    # Provisional reply has been received
    pass
class COMPLETED(SipTransactionState):
    # Transaction already ended with final reply
    pass
class CONFIRMED(SipTransactionState):
    # Transaction already ended with final reply and ACK received (server-only)
    pass
class TERMINATED(SipTransactionState):
    # Transaction ended abnormally (request timeout and such)
    pass

class local4remote(object):
    global_config = None
    cache_r2l = None
    cache_r2l_old = None
    cache_l2s = None
    skt = None
    handleIncoming = None
    fixed = False

    def __init__(self, global_config, handleIncoming):
        self.global_config = global_config
        self.cache_r2l = {}
        self.cache_r2l_old = {}
        self.cache_l2s = {}
        self.handleIncoming = handleIncoming
        try:
            # Python can be compiled with IPv6 support, but if kernel
            # has not we would get exception creating the socket.
            # Workaround that by trying create socket and checking if
            # we get an exception.
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        except:
            socket.has_ipv6 = False
        if 'my' in dir(global_config['_sip_address']):
            if socket.has_ipv6:
                laddresses = (('0.0.0.0', global_config['_sip_port']), ('[::]', global_config['_sip_port']))
            else:
                laddresses = (('0.0.0.0', global_config['_sip_port']),)
        else:
            laddresses = ((global_config['_sip_address'], global_config['_sip_port']),)
            self.fixed = True
        for laddress in laddresses:
            server = Udp_server(laddress, handleIncoming)
            self.cache_l2s[laddress] = server

    def getServer(self, address, is_local = False):
        if self.fixed:
            return self.cache_l2s.items()[0][1]
        if not is_local:
            laddress = self.cache_r2l.get(address[0], None)
            if laddress == None:
                laddress = self.cache_r2l_old.get(address[0], None)
                if laddress != None:
                    self.cache_r2l[address[0]] = laddress
            if laddress != None:
                #print 'local4remot-1: local address for %s is %s' % (address[0], laddress[0])
                return self.cache_l2s[laddress]
            if address[0].startswith('['):
                family = socket.AF_INET6
                lookup_address = address[0][1:-1]
            else:
                family = socket.AF_INET
                lookup_address = address[0]
            self.skt = socket.socket(family, socket.SOCK_DGRAM)
            ai = socket.getaddrinfo(lookup_address, None, family)
            if family == socket.AF_INET:
                _address = (ai[0][4][0], address[1])
            else:
                _address = (ai[0][4][0], address[1], ai[0][4][2], ai[0][4][3])
            self.skt.connect(_address)
            if family == socket.AF_INET:
                laddress = (self.skt.getsockname()[0], self.global_config['_sip_port'])
            else:
                laddress = ('[%s]' % self.skt.getsockname()[0], self.global_config['_sip_port'])
            self.cache_r2l[address[0]] = laddress
        else:
            laddress = address
        server = self.cache_l2s.get(laddress, None)
        if server == None:
            server = Udp_server(laddress, self.handleIncoming)
            self.cache_l2s[laddress] = server
        #print 'local4remot-2: local address for %s is %s' % (address[0], laddress[0])
        return server

    def rotateCache(self):
        self.cache_r2l_old = self.cache_r2l
        self.cache_r2l = {}

class SipTransactionManager(object):
    global_config = None
    l4r = None
    tclient = None
    tserver = None
    req_cb = None
    l1rcache = None
    l2rcache = None
    nat_traversal = False
    req_consumers = None
    provisional_retr = 0

    def __init__(self, global_config, req_cb = None):
        self.global_config = global_config
        self.l4r = local4remote(global_config, self.handleIncoming)
        self.tclient = {}
        self.tserver = {}
        self.req_cb = req_cb
        self.l1rcache = {}
        self.l2rcache = {}
        self.req_consumers = {}
        Timeout(self.rCachePurge, 32, -1)

    def handleIncoming(self, data, address, server):
        if len(data) < 32:
            return
        rtime = time()
        self.global_config['_sip_logger'].write('RECEIVED message from %s:%d:\n' % address, data, ltime = rtime)
        checksum = md5(data).digest()
        retrans = self.l1rcache.get(checksum, None)
        if retrans == None:
            retrans = self.l2rcache.get(checksum, None)
        if retrans != None:
            userv, data, address = retrans
            if data == None:
                return
            self.transmitData(userv, data, address)
            return
        if data.startswith('SIP/2.0 '):
            try:
                resp = SipResponse(data)
                tid = resp.getTId(True, True)
            except Exception, exception:
                print datetime.now(), 'can\'t parse SIP response from %s:%d: %s:' % (address[0], address[1], str(exception))
                print '-' * 70
                print_exc(file = sys.stdout)
                print '-' * 70
                print data
                print '-' * 70
                sys.stdout.flush()
                self.l1rcache[checksum] = (None, None, None)
                return
            if resp.getSCode()[0] < 100 or resp.getSCode()[0] > 999:
                print datetime.now(), 'invalid status code in SIP response from %s:%d:' % address
                print data
                sys.stdout.flush()
                self.l1rcache[checksum] = (None, None, None)
                return
            resp.rtime = rtime
            if not self.tclient.has_key(tid):
                #print 'no transaction with tid of %s in progress' % str(tid)
                self.l1rcache[checksum] = (None, None, None)
                return
            t = self.tclient[tid]
            if self.nat_traversal and resp.countHFs('contact') > 0 and not check1918(t.address[0]):
                curl = resp.getHFBody('contact').getUrl()
                if check1918(curl.host):
                    curl.host, curl.port = address
            resp.setSource(address)
            self.incomingResponse(resp, t, checksum)
        else:
            if self.req_cb == None:
                return
            try:
                req = SipRequest(data)
                tids = req.getTIds()
            except Exception, exception:
                print datetime.now(), 'can\'t parse SIP request from %s:%d: %s:' % (address[0], address[1], str(exception))
                print '-' * 70
                print_exc(file = sys.stdout)
                print '-' * 70
                print data
                print '-' * 70
                sys.stdout.flush()
                self.l1rcache[checksum] = (None, None, None)
                return
            req.rtime = rtime
            via0 = req.getHFBody('via')
            ahost, aport = via0.getAddr()
            rhost, rport = address
            if self.nat_traversal and rport != aport and check1918(ahost):
                req.nated = True
            if ahost != rhost:
                via0.params['received'] = rhost
            if via0.params.has_key('rport') or req.nated:
                via0.params['rport'] = str(rport)
            if self.nat_traversal and req.countHFs('contact') > 0 and req.countHFs('via') == 1:
                curl = req.getHFBody('contact').getUrl()
                if check1918(curl.host):
                    curl.host, curl.port = address
                    req.nated = True
            req.setSource(address)
            self.incomingRequest(req, checksum, tids, server)

    # 1. Client transaction methods
    def newTransaction(self, msg, resp_cb = None, laddress = None, userv = None):
        t = SipTransaction()
        t.tid = msg.getTId(True, True)
        if self.tclient.has_key(t.tid):
            raise ValueError('BUG: Attempt to initiate transaction with the same TID as existing one!!!')
        t.tout = 0.5
        t.fcode = None
        t.address = msg.getTarget()
        if userv == None:
            if laddress == None:
                t.userv = self.l4r.getServer(t.address)
            else:
                t.userv = self.l4r.getServer(laddress, is_local = True)
        else:
            t.userv = userv
        t.data = msg.localStr(t.userv.laddress[0], t.userv.laddress[1])
        try:
            t.expires = msg.getHFBody('expires').getNum()
            if t.expires <= 0:
                t.expires = 300
        except IndexError:
            t.expires = 300
        if msg.getMethod() == 'INVITE':
            t.needack = True
            t.ack = msg.genACK()
            t.cancel = msg.genCANCEL()
        else:
            t.needack = False
            t.ack = None
            t.cancel = None
        t.cancelPending = False
        t.resp_cb = resp_cb
        t.teA = Timeout(self.timerA, t.tout, 1, t)
        if resp_cb != None:
            t.r408 = msg.genResponse(408, 'Request Timeout')
        t.teB = Timeout(self.timerB, 32.0, 1, t)
        t.teC = None
        t.state = TRYING
        self.tclient[t.tid] = t
        self.transmitData(t.userv, t.data, t.address)
        return t

    def cancelTransaction(self, t, reason = None):
        # If we got at least one provisional reply then (state == RINGING)
        # then start CANCEL transaction, otherwise deffer it
        if t.state != RINGING:
            t.cancelPending = True
        else:
            if reason != None:
                t.cancel.appendHeader(SipHeader(body = reason))
            self.newTransaction(t.cancel, userv = t.userv)

    def incomingResponse(self, msg, t, checksum):
        # In those two states upper level already notified, only do ACK retransmit
        # if needed
        if t.state == TERMINATED:
            return

        if t.state == TRYING:
            # Stop timers
            if t.teA != None:
                t.teA.cancel()
                t.teA = None

        if t.state in (TRYING, RINGING):
            if t.teB != None:
                t.teB.cancel()
                t.teB = None

            if msg.getSCode()[0] < 200:
                # Privisional response - leave everything as is, except that
                # change state and reload timeout timer
                if t.state == TRYING:
                    t.state = RINGING
                    if t.cancelPending:
                        self.newTransaction(t.cancel, userv = t.userv)
                        t.cancelPending = False
                t.teB = Timeout(self.timerB, t.expires, 1, t)
                self.l1rcache[checksum] = (None, None, None)
                if t.resp_cb != None:
                    t.resp_cb(msg)
            else:
                # Final response - notify upper layer and remove transaction
                if t.needack:
                    # Prepare and send ACK if necessary
                    fcode = msg.getSCode()[0]
                    tag = msg.getHFBody('to').getTag()
                    if tag != None:
                        t.ack.getHFBody('to').setTag(tag)
                    rAddr = None
                    if msg.getSCode()[0] >= 200 and msg.getSCode()[0] < 300:
                        # Some hairy code ahead
                        if msg.countHFs('contact') > 0:
                            rTarget = msg.getHFBody('contact').getUrl().getCopy()
                        else:
                            rTarget = None
                        routes = [x.getCopy() for x in msg.getHFBodys('record-route')]
                        routes.reverse()
                        if len(routes) > 0:
                            if not routes[0].getUrl().lr:
                                if rTarget != None:
                                    routes.append(SipRoute(address = SipAddress(url = rTarget)))
                                rTarget = routes.pop(0).getUrl()
                                rAddr = rTarget.getAddr()
                            else:
                                rAddr = routes[0].getAddr()
                        elif rTarget != None:
                            rAddr = rTarget.getAddr()
                        if rTarget != None:
                            t.ack.setRURI(rTarget)
                        if rAddr != None:
                            t.ack.setTarget(rAddr)
                        t.ack.delHFs('route')
                        t.ack.appendHeaders([SipHeader(name = 'route', body = x) for x in routes])
                    if fcode >= 200 and fcode < 300:
                        t.ack.getHFBody('via').genBranch()
                    if rAddr == None:
                        rAddr = t.address
                    self.transmitMsg(t.userv, t.ack, rAddr, checksum)
                else:
                    self.l1rcache[checksum] = (None, None, None)
                if t.resp_cb != None:
                    t.resp_cb(msg)
                del self.tclient[t.tid]
                t.cleanup()

    def timerA(self, t):
        #print 'timerA', t
        self.transmitData(t.userv, t.data, t.address)
        t.tout *= 2
        t.teA = Timeout(self.timerA, t.tout, 1, t)

    def timerB(self, t):
        #print 'timerB', t
        t.teB = None
        if t.teA != None:
            t.teA.cancel()
            t.teA = None
        t.state = TERMINATED
        #print '2: Timeout(self.timerC, 32.0, 1, t)', t
        t.teC = Timeout(self.timerC, 32.0, 1, t)
        if t.resp_cb == None:
            return
        t.r408.rtime = time()
        t.resp_cb(t.r408)
        #try:
        #    t.resp_cb(SipRequest(t.data).genResponse(408, 'Request Timeout'))
        #except:
        #    print 'SipTransactionManager: unhandled exception when processing response!'

    def timerC(self, t):
        #print 'timerC', t
        #print self.tclient
        t.teC = None
        del self.tclient[t.tid]
        t.cleanup()

    # 2. Server transaction methods
    def incomingRequest(self, msg, checksum, tids, server):
        for tid in tids:
            if self.tclient.has_key(tid):
                resp = msg.genResponse(482, 'Loop Detected')
                self.transmitMsg(server, resp, resp.getHFBody('via').getTAddr(), checksum)
                return
        tid = msg.getTId()
        # Fasten seatbelts - bumpy transaction matching code ahead!
        if msg.getMethod() in ('INVITE', 'CANCEL', 'ACK'):
            btid = msg.getTId(wBRN = True)
            t = self.tserver.get(btid, None)
            if t == None:
                t = self.tserver.get(tid, None)
                if t != None and t.branch != btid[3]:
                    if msg.getMethod() == 'INVITE':
                        # Different branch on transaction to which no final reply
                        # has been sent yet - merge requests
                        resp = msg.genResponse(482, 'Loop Detected')
                        self.transmitMsg(server, resp, resp.getHFBody('via').getTAddr(), checksum)
                        return
                    elif msg.getMethod() == 'CANCEL':
                        # CANCEL, but with branch that doesn't match any existing
                        # transactions
                        resp = msg.genResponse(481, 'Call Leg/Transaction Does Not Exist')
                        self.transmitMsg(server, resp, resp.getHFBody('via').getTAddr(), checksum)
                        return
        else:
            t = self.tserver.get(tid, None)
        if t != None:
            #print 'existing transaction'
            if msg.getMethod() == t.method:
                # Duplicate received, check that we have sent any response on this
                # request already
                if t.data != None:
                    self.transmitData(t.userv, t.data, t.address, checksum)
                return
            elif msg.getMethod() == 'CANCEL':
                # RFC3261 says that we have to reply 200 OK in all cases if
                # there is such transaction
                resp = msg.genResponse(200, 'OK')
                self.transmitMsg(t.userv, resp, resp.getHFBody('via').getTAddr(), checksum)
                if t.state in (TRYING, RINGING):
                    self.doCancel(t, msg.rtime, msg)
            elif msg.getMethod() == 'ACK' and t.state == COMPLETED:
                t.state = CONFIRMED
                if t.teA != None:
                    t.teA.cancel()
                    t.teA = None
                t.teD.cancel()
                # We have done with the transaction, no need to wait for timeout
                del self.tserver[t.tid]
                t.cleanup()
                self.l1rcache[checksum] = (None, None, None)
        elif msg.getMethod() == 'ACK':
            # Some ACK that doesn't match any existing transaction.
            # Drop and forget it - upper layer is unlikely to be interested
            # to seeing this anyway.
            print datetime.now(), 'unmatched ACK transaction - ignoring'
            sys.stdout.flush()
            self.l1rcache[checksum] = (None, None, None)
        elif msg.getMethod() == 'CANCEL':
            resp = msg.genResponse(481, 'Call Leg/Transaction Does Not Exist')
            self.transmitMsg(server, resp, resp.getHFBody('via').getTAddr(), checksum)
        else:
            #print 'new transaction', msg.getMethod()
            t = SipTransaction()
            t.tid = tid
            t.state = TRYING
            t.teA = None
            t.teD = None
            t.teE = None
            t.teF = None
            t.method = msg.getMethod()
            t.data = None
            t.address = None
            t.noack_cb = None
            t.cancel_cb = None
            t.checksum = checksum
            if server.laddress[0] not in ('0.0.0.0', '[::]'):
                t.userv = server
            else:
                # For messages received on the wildcard interface find
                # or create more specific server.
                t.userv = self.l4r.getServer(msg.getSource())
            if msg.getMethod() == 'INVITE':
                t.r487 = msg.genResponse(487, 'Request Terminated')
                t.needack = True
                t.branch = msg.getHFBody('via').getBranch()
                try:
                    e = msg.getHFBody('expires').getNum()
                    if e <= 0:
                        e = 300
                except IndexError:
                    e = 300
                t.teE = Timeout(self.timerE, e, 1, t)
            else:
                t.r487 = None
                t.needack = False
                t.branch = None
            self.tserver[t.tid] = t
            for consumer in self.req_consumers.get(t.tid[0], ()):
                consumer = consumer.isYours(msg)
                if consumer != None:
                    rval = consumer.recvRequest(msg)
                    break
            else:
                rval = self.req_cb(msg)
            if rval == None:
                if t.teA != None or t.teD != None or t.teE != None or t.teF != None:
                    return
                if self.tserver.has_key(t.tid):
                    del self.tserver[t.tid]
                t.cleanup()
                return
            resp, cancel_cb, noack_cb = rval
            t.cancel_cb = cancel_cb
            t.noack_cb = noack_cb
            if resp != None:
                self.sendResponse(resp, t)

    def regConsumer(self, consumer, call_id):
        self.req_consumers.setdefault(call_id, []).append(consumer)

    def unregConsumer(self, consumer, call_id):
        # Usually there will be only one consumer per call_id, so that
        # optimize management for this case
        consumers = self.req_consumers.pop(call_id)
        if len(consumers) > 1:
            consumers.remove(consumer)
            self.req_consumers[call_id] = consumers

    def sendResponse(self, resp, t = None, retrans = False):
        #print self.tserver
        if t == None:
            tid = resp.getTId()
            t = self.tserver[tid]
        if t.state not in (TRYING, RINGING) and not retrans:
            raise ValueError('BUG: attempt to send reply on already finished transaction!!!')
        scode = resp.getSCode()[0]
        toHF = resp.getHFBody('to')
        if scode > 100 and toHF.getTag() == None:
            toHF.genTag()
        t.data = resp.localStr(t.userv.laddress[0], t.userv.laddress[1])
        t.address = resp.getHFBody('via').getTAddr()
        self.transmitData(t.userv, t.data, t.address, t.checksum)
        if scode < 200:
            t.state = RINGING
            if self.provisional_retr > 0 and scode > 100:
                if t.teF != None:
                    t.teF.cancel()
                t.teF = Timeout(self.timerF, self.provisional_retr, 1, t)
        else:
            t.state = COMPLETED
            if t.teE != None:
                t.teE.cancel()
                t.teE = None
            if t.teF != None:
                t.teF.cancel()
                t.teF = None
            if t.needack:
                # Schedule removal of the transaction
                t.teD = Timeout(self.timerD, 32.0, 1, t)
                if scode >= 300:
                    # Black magick to allow proxy send us another INVITE with diffetent branch
                    del self.tserver[t.tid]
                    t.tid = list(t.tid)
                    t.tid.append(t.branch)
                    t.tid = tuple(t.tid)
                    self.tserver[t.tid] = t
                # Install retransmit timer if necessary
                t.tout = 0.5
                t.teA = Timeout(self.timerA, t.tout, 1, t)
            else:
                # We have done with the transaction
                del self.tserver[t.tid]
                t.cleanup()

    def doCancel(self, t, rtime = None, req = None):
        if rtime == None:
            rtime = time()
        if t.r487 != None:
            self.sendResponse(t.r487, t, True)
        if t.cancel_cb != None:
            t.cancel_cb(rtime, req)

    def timerD(self, t):
        #print 'timerD'
        t.teD = None
        if t.teA != None:
            t.teA.cancel()
            t.teA = None
        if t.noack_cb != None and t.state != CONFIRMED:
            t.noack_cb()
        del self.tserver[t.tid]
        t.cleanup()

    def timerE(self, t):
        #print 'timerE'
        t.teE = None
        if t.teF != None:
            t.teF.cancel()
            t.teF = None
        if t.state in (TRYING, RINGING):
            if t.r487 != None:
                t.r487.reason = 'Request Expired'
            self.doCancel(t)

    # Timer to retransmit the last provisional reply every
    # 2 seconds
    def timerF(self, t):
        #print 'timerF', t.state
        t.teF = None
        if t.state == RINGING and self.provisional_retr > 0:
            self.transmitData(t.userv, t.data, t.address)
            t.teF = Timeout(self.timerF, self.provisional_retr, 1, t)

    def rCachePurge(self):
        self.l2rcache = self.l1rcache
        self.l1rcache = {}
        self.l4r.rotateCache()

    def transmitMsg(self, userv, msg, address, cachesum, compact = False):
        data = msg.localStr(userv.laddress[0], userv.laddress[1], compact)
        self.transmitData(userv, data, address, cachesum)

    def transmitData(self, userv, data, address, cachesum = None):
        userv.send_to(data, address)
        self.global_config['_sip_logger'].write('SENDING message to %s:%d:\n' % address, data)
        if cachesum != None:
            self.l1rcache[cachesum] = (userv, data, address)
