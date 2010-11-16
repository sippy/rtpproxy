from Timeout import Timeout
from VoIPCom_accounting import ftime
from threading import Thread, Condition, Lock
from twisted.internet import reactor
import mx.ODBC.unixODBC as mx
from time import time, sleep
from datetime import datetime
import sys

MAX_WORKERS = 10

class Counter:
    id = 0

class _VCOMWorker(Thread):
    id = None
    cursor = None
    db = None
    master = None

    def __init__(self, master):
        Thread.__init__(self)
        self.master = master
        if Counter.id > 240:
            print 'too many threads (%d) started, exiting' % Counter.id
            sys.exit(100)
        self.id = Counter.id
        Counter.id += 1
        self.setDaemon(True)
        self.start()

    def connect(self):
        while True:
            try:
                #self.db = mx.DriverConnect('DSN=asterisk', clear_auto_commit = 0)
                self.db = mx.DriverConnect('DSN=MSSQLasterisk;UID=asterisk211;PWD=vulcans58ORGANIANS', clear_auto_commit = 0)
                self.cursor = self.db.cursor()
                print 'started DB thread', self.id
                break
            except Exception, e:
                print str(e)
                sleep(5)

    def run(self):
        self.master.at_lock.acquire()
        self.master.at += 1
        self.master.at_lock.release()
        self.connect()
        while True:
            self.master.work_available.acquire()
            while (self.id % 2 == 0 or len(self.master.work) == 0) and len(self.master.work_hp) == 0:
                self.master.work_available.wait()
            if len(self.master.work_hp) == 0:
                queue = self.master.work
            else:
                queue = self.master.work_hp
            query, deadline, result_callback, callback_parameters = queue.pop(0)
            self.master.work_available.release()
            if deadline != None and time() > deadline:
                print 'timeout executing statement: %s' % query
                reactor.callFromThread(result_callback, (('Timeout',),), *callback_parameters)
                continue
            print 'sending', self.id, query
            try:
                self.cursor.execute(query)
                #if self.cursor.rowcount > 0:
                result = self.cursor.fetchall()
            except mx.OperationalError, exception:
                if exception[0] == 'HY000':
                    print datetime.now(), 'non-fatal database exception \'%s\' executing statement: %s, returning failure' % (str(exception), query)
                    reactor.callFromThread(result_callback, (('DB Exception',),), *callback_parameters)
                    continue
                else:
                    print datetime.now(), 'database exception \'%s\' executing statement: %s, thread is dead now' % (str(exception), query)
                self.master.work_available.acquire()
                queue.insert(0, (query, deadline, result_callback, callback_parameters))
                self.master.work_available.notify()
                self.master.work_available.release()
                self.master.at_lock.acquire()
                self.master.at -= 1
                self.master.at_lock.release()
                # R.I.P.
                while True:
                    sleep(10000000)
            except Exception, exception:
                result = ()
                print datetime.now(), 'exception \'%s\' executing statement: %s' % (str(exception), query)
            #self.db.commit()
            #print 'result is', result
            reactor.callFromThread(result_callback, tuple(result), *callback_parameters)

class RadiusAuthorisation:
    global_config = None
    cc_ips = None
    cc_routes = None

    def __init__(self, global_config):
        self.global_config = global_config
        self.work_available = Condition()
        self.work = []
        self.work_hp = []
        self.at = 0
        self.at_lock = Lock()
        for i in range(0, MAX_WORKERS):
            _VCOMWorker(self)
        self.cc_ips = []
        self.update_cc_aaa()

    def update_cc_aaa(self):
        query = 'exec [usp_sip_incoming_get_b2bua_ips]'
        self.work_available.acquire()
        self.work.append((query, None, self.update_cc_aaa_result, ()))
        self.work_available.notify()
        self.work_available.release()

    def update_cc_aaa_result(self, results):
        self.cc_ips = [x[0] for x in results]
        query = 'exec [usp_sip_incoming_get_b2bua_cc_outbound_routing]'
        self.work_available.acquire()
        self.work.append((query, None, self.update_cc_rtn_result, ()))
        self.work_available.notify()
        self.work_available.release()

    def update_cc_rtn_result(self, results):
        self.cc_routes = results
        Timeout(self.update_cc_aaa, 60.0)

    def dummy(self, *args):
        pass

    def do_auth(self, username, caller, callee, h323_cid, sip_cid, remote_ip, res_cb, \
          realm = None, nonce = None, uri = None, response = None, extra_attributes = None,
          user_agent = None, to_username = None, rtime = None):
        results_cb = self._process_result
        if remote_ip in self.cc_ips and self.cc_routes != None:
            cc_routes = []
            for route in self.cc_routes:
                route = list(route)
                if callee.startswith('1'):
                    _callee = callee[1:]
                else:
                    _callee = callee
                route[1] = route[1].replace('[[Number]]', _callee)
                route[1] = route[1].replace('[[CLI]]', caller)
                cc_routes.append(tuple(route))
            self._process_result(tuple(cc_routes), res_cb, sip_cid, time())
            results_cb = self.dummy
        self.at_lock.acquire()
        for i in range(self.at, MAX_WORKERS):
            _VCOMWorker(self)
        self.at_lock.release()
        if user_agent == None:
            user_agent = ''
        if response != None:
            query = "exec [usp_sip_outgoing_get_b2bua_auth] '%s', '%s', '', '', '%s', '%s', '%s', " \
              "'64.34.245.218', '', 'Outgoing', '', '%s' , '', '', 1, '%s', '', '%s'" % \
              (username, callee, str(sip_cid), caller, callee, remote_ip, response, user_agent)
        else:
            if to_username == None:
                to_username = ''
            query = "exec [usp_sip_incoming_get_b2bua] '%s', '%s', 0, 1, '%s', '%s', '%s', '%s', '%s'" % \
              (callee, caller, str(sip_cid), remote_ip, user_agent, to_username, ftime(rtime))
        #print query
        now = time()
        self.work_available.acquire()
        self.work_hp.append((query, now + 15, results_cb, (res_cb, sip_cid, now)))
        self.work_available.notify()
        self.work_available.release()
        message = 'sending AAA request:\n' + query
        self.global_config['_sip_logger'].write(message, call_id = sip_cid)

    def do_acct(self, username, caller, callee, h323_cid, sip_cid, remote_ip, \
      status_type, session_time, origin, disconnect_cause, user_agent):
        self.at_lock.acquire()
        for i in range(self.at, MAX_WORKERS):
            _VCOMWorker(self)
        self.at_lock.release()
        if user_agent == None:
            user_agent = ''
        query = "exec [usp_cdr_update] '%s', '%s', '%s', '64.34.245.218', '%s', '%s', '%d', '%s', '%s', '', '', '%s'" % \
            (username, callee, str(sip_cid), remote_ip, status_type, session_time, origin, disconnect_cause, user_agent)
        now = time()
        self.work_available.acquire()
        self.work.append((query, None, self._acct_result, (origin, sip_cid, now)))
        self.work_available.notify()
        self.work_available.release()
        message = 'sending Acct/%s request:\n%s' % (origin, query)
        self.global_config['_sip_logger'].write(message, call_id = sip_cid)

    def _process_result(self, results, res_cb, sip_cid, btime):
        print results
        delay = time() - btime
        rcode = 0
        if len(results) == 0 or (len(results) == 1 and len(results[0]) == 1):
            rcode = 1
        if rcode in (0, 1):
            if rcode == 0:
                message = 'AAA request accepted (delay is %.3f), processing response:\n' % delay
            else:
                if len(results) == 1 and len(results[0]) == 1:
                    message = 'AAA request rejected with error "%s" (delay is %.3f), processing response:\n' % \
                      (results[0][0], delay)
                else:
                    message = 'AAA request rejected (delay is %.3f), processing response:\n' % delay
            if len(results) > 0 and len(results[0]) > 1:
                message += reduce(lambda x, y: x + y, map(lambda x: '%-32s = \'%s\'\n' % x, results))
        else:
            message = 'Error sending AAA request (delay is %.3f)\n' % delay
        self.global_config['_sip_logger'].write(message, call_id = sip_cid)
        res_cb([results, rcode])

    def _acct_result(self, results, origin, sip_cid, btime):
        delay = time() - btime
        self.global_config['_sip_logger'].write('Acct/%s request accepted (delay is %.3f)' % \
          (origin, delay), call_id = sip_cid)
