from twisted.internet import reactor
from urllib import FancyURLopener
from Timeout import Timeout
from time import time

from threading import Thread, Condition

class _CNAMWorker(Thread):
    userv = None

    def __init__(self, userv):
        Thread.__init__(self)
        self.userv = userv
        self.setDaemon(True)
        self.start()

    def lookup(self, cli, sipuser):
        print 'looking up %s for %s' % (cli, sipuser)
        opener = FancyURLopener({})
        try:
            caller_name = opener.open('http://www.voip.com/services/cnam/CNAM.asp?phone=%s&sipuser=%s' % \
              (cli, sipuser)).read().strip()
            if caller_name == '':
                caller_name = None
            if len(caller_name) > 50:
                print 'lookup result length (%d) exceeds max. length, ignoring' % len(caller_name)
                caller_name = None
            if caller_name.startswith('CNAM='):
                caller_name = caller_name[5:]
        except:
            caller_name = None
        print 'lookup\'s been done, result is %s' % caller_name
        return caller_name

    def run(self):
        while True:
            self.userv.wi_available.acquire()
            while len(self.userv.wi) == 0:
                self.userv.wi_available.wait()
            wi = self.userv.wi.pop(0)
            if wi == None:
                # Shutdown request, relay it further
                self.userv.wi.append(None)
                self.userv.wi_available.notify()
            self.userv.wi_available.release()
            if wi == None:
                break
            cli, sipuser, result_cb = wi
            caller_name = self.lookup(cli, sipuser)
            reactor.callFromThread(result_cb, caller_name)
            
class Result_callback:
    result_cb = None
    cb_args = None
    called = False

    def __init__(self, timeout, result_cb, *cb_args):
        self.result_cb = result_cb
        self.cb_args = cb_args
        Timeout(self.done, timeout, 1, None)

    def done(self, result):
        if not self.called:
            self.called = True
            self.result_cb(result, *self.cb_args)

class VoIPCom_cnam_client:
    wi_available = None
    wi = None

    def __init__(self):
        self.wi_available = Condition()
        self.wi = []
        for i in range(1, 30):
            _CNAMWorker(self)

    def lookup(self, cli, sipuser, result_cb, *cb_args):
        self.wi_available.acquire()
        self.wi.append((cli, sipuser, Result_callback(0.5, result_cb, *cb_args).done))
        self.wi_available.notify()
        self.wi_available.release()

if __name__ == '__main__':
    def cnam_received(*args):
        print args
        reactor.stop()

    c = VoIPCom_cnam_client()
    c.lookup('3056779572', 'voip87065p42686', cnam_received, 1, 2, 3)
    reactor.run(installSignalHandlers = 0)
