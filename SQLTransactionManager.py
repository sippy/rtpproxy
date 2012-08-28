# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006 Sippy Software, Inc. All rights reserved.
#
# Warning: This computer program is protected by copyright law and
# international treaties. Unauthorized reproduction or distribution of this
# program, or any portion of it, may result in severe civil and criminal
# penalties, and will be prosecuted under the maximum extent possible under
# law.

from threading import Thread, Condition, Lock, local
from datetime import datetime
from time import time, sleep
from twisted.internet import reactor
import sys

class SqlDSN(object):
    driver = None
    user = None
    password = None
    host = None
    database = None

    def __init__(self, dsn):
        driver, uri = dsn.split('://', 1)
        self.driver = driver.lower()
        parts = uri.split('@', 1)
        self.user = None
        self.password = None
        if len(parts) > 1:
            up = parts[0].split(':', 1)
            if len(up) > 1:
                self.password = up[1]
            self.user = up[0]
            ht = parts[1]
        else:
            ht = parts[0]
        spos = ht.rindex('/')
        self.host = ht[:spos]
        self.database = ht[spos + 1:]

class SQLTransactionManager(object):
    workers = None
    localdata = None
    __dsn = None
    cnct_timeout = None
    no_reconnect = False

    def __init__(self, dsn, nworkers = 1, cnct_timeout = None, lazy_connect = False):
        self.localdata = local()
        self.__dsn = SqlDSN(dsn)
        self.cnct_timeout = cnct_timeout
        self.workers = []
        while nworkers != 0:
            self.workers.append(Worker(self, self.__dsn, lazy_connect))
            nworkers -= 1

    def sendQueries(self, items, res_cb = None, tier = 0, sync = False, arraysize = None, *callback_parameters):
        items = tuple(items)
        if sync:
            try:
                handler = self.localdata.handler
            except:
                self.localdata.handler = SQLSyncHandler(self.__dsn, self.cnct_timeout)
                self.localdata.handler.no_reconnect = self.no_reconnect
                handler = self.localdata.handler
            ress, eps = handler.runQueries(items, arraysize)
            if res_cb != None:
                res_cb(ress, eps, *callback_parameters)
            return (ress, eps)
        return self.workers[tier].enqueue(items, res_cb, arraysize, *callback_parameters)

    def sendQuery(self, item, res_cb = None, tier = 0, sync = False, arraysize = None, *callback_parameters):
        return self.sendQueries((item,), res_cb, tier, sync, arraysize, *callback_parameters)

    def shutdown(self, join_timeout = None):
        self.localdata = None
        for worker in self.workers:
            worker.shutdown(join_timeout)

    def shutdownSync(self):
       self.localdata.handler.cx.close()
       del self.localdata.handler

    def getQueueStats(self):
       res = []
       for x in range(0, len(self.workers)):
           res.append((x, self.workers[x].queue_len()))
       return res

class SQLSyncHandler(object):
    __dsn = None
    needcommit = None
    OE = None
    cu = None
    cx = None
    timeout = None
    no_reconnect = False

    def __init__(self, dsn, timeout = None, lazy_connect = False):
        self.__dsn = dsn
        if not lazy_connect:
            self.connectDb(timeout)
            self.timeout = timeout

    def runQueries(self, items, arraysize = None):
        ress = []
        eps = []
        if self.cu == None:
            try:
                self.connectDb(self.timeout)
            except Exception, ep:
                eps.append(ep)
                return (tuple(ress), tuple(eps))
        for item in items:
            #print 'trying', item
            exec_args = (item, )
            if isinstance(item, tuple):
                exec_args = item
            try:
                try:
                    self.cu.execute(*exec_args)
                except self.OE, e:
                    #print 'exception', e, type(e), '_ssp' in str(e)
                    if '_ssp' in str(e) or self.no_reconnect:
                        raise e
                    # If OperationError has been rised try to re-connect and
                    # re-send the query again. This allows us to survive DB
                    # server restart
                    if self.__dsn.driver != 'mysql' or e[0] != 2006:
                        # Ignore (2006, 'MySQL server has gone away')
                        sleep(5)
                    self.connectDb(self.timeout)
                    self.cu.execute(*exec_args)
                if exec_args[0].strip().upper().startswith('SELECT'):
                    if arraysize == None:
                        arraysize = 1000
                        dosleep = False
                    else:
                        dosleep = True
                    res = []
                    while True:
                        r = [tuple(x) for x in self.cu.fetchmany(arraysize)]
                        if len(r) == 0:
                            break
                        res.extend(r)
                        if len(r) < arraysize:
                            break
                        if dosleep:
                            sleep(1)
                    ress.append(tuple(res))
                else:
                    ress.append(None)
                eps.append(None)
            except Exception, ep:
                ress.append(None)
                eps.append(ep)
        if self.needcommit:
            self.cx.commit()
        return (tuple(ress), tuple(eps))

    def connectDb(self, timeout = None):
        #print 'connectDb', self.__dsn.host
        dbc = DBConnector(self.__dsn)
        res = dbc.connect(timeout)
        if res == None:
            raise Exception('DB connection timeout')
        #print 'connectDb ok'
        self.cx, self.cu, self.OE, self.needcommit = res

    def disconnectDb(self):
        self.cx = None
        self.cu = None
        self.OE = None
        self.needcommit = None

class DBConnector(Thread):
    def __init__(self, dsn):
        Thread.__init__(self)
        self.setDaemon(True)
        self.__dsn = dsn

    def connect(self, timeout):
        self.complete = False
        self.cv = Condition()
        self.exception = None
        self.cx = None
        self.cv.acquire()
        self.start()
        self.cv.wait(timeout)
        self.cv.release()
        if self.exception != None:
            raise self.exception
        if self.cx == None:
            return None
        return (self.cx, self.cu, self.OE, self.needcommit)

    def run(self):
        try:
            self._run()
        except Exception, e:
            self.exception = e
        self.cv.acquire()
        self.cv.notify()
        self.cv.release()

    def _run(self):
        if self.__dsn.driver == 'postgres':
            from pyPgSQL import PgSQL
            if self.__dsn.user != None and self.__dsn.password != None:
                self.cx = PgSQL.connect(user = self.__dsn.user, password = self.__dsn.password, host = self.__dsn.host, database = self.__dsn.database)
            elif self.__dsn.user != None and self.__dsn.password == None:
                self.cx = PgSQL.connect(user = self.__dsn.user, host = self.__dsn.host, database = self.__dsn.database)
            elif self.__dsn.user == None and self.__dsn.password != None:
                self.cx = PgSQL.connect(password = self.__dsn.password, host = self.__dsn.host, database = self.__dsn.database)
            else:
                self.cx = PgSQL.connect(host = self.__dsn.host, database = self.__dsn.database)
            self.OE = PgSQL.OperationalError
            self.cx.autocommit = True
            self.needcommit = False
        elif self.__dsn.driver == 'mysql':
            import MySQLdb
            if self.__dsn.user != None and self.__dsn.password != None:
                self.cx = MySQLdb.Connection(user = self.__dsn.user, passwd = self.__dsn.password, host = self.__dsn.host, db = self.__dsn.database)
            elif self.__dsn.user != None and self.__dsn.password == None:
                self.cx = MySQLdb.Connection(user = self.__dsn.user, host = self.__dsn.host, db = self.__dsn.database)
            elif self.__dsn.user == None and self.__dsn.password != None:
                self.cx = MySQLdb.Connection(passwd = self.__dsn.password, host = self.__dsn.host, db = self.__dsn.database)
            else:
                self.cx = MySQLdb.Connection(host = self.__dsn.host, db = self.__dsn.database)
            self.OE = MySQLdb.OperationalError
            self.needcommit = True
        elif self.__dsn.driver == 'sybase':
            import Sybase
            self.cx = Sybase.connect(self.__dsn.host, self.__dsn.user, self.__dsn.password, self.__dsn.database, auto_commit = 1)
            self.OE = Sybase.OperationalError
            self.needcommit = False
        else:
            self.exception = ValueError('unsupported DB driver: ' + self.__dsn.driver)
            return
        self.cu = self.cx.cursor()

class Worker(Thread):
    wi_available = None
    wi_queue = None
    cie_available = None
    cie = None
    # The following two members should only be accessed form the main thread.
    # No locking is performed on them.
    res_cbs = None
    i_res_cb = 0
    max_queue_len = 0
    lazy_connect = None

    def __init__(self, owner, dsn, lazy_connect):
        self.wi_queue = []
        self.__owner = owner
        self.__dsn = dsn
        self.res_cbs = {}
        self.lazy_connect = lazy_connect

        Thread.__init__(self)
        self.wi_available = Condition()
        self.cie_available = Condition()
        self.setDaemon(True)
        self.start()
        # Wait until connection to the DB completes and result is available
        # Unfortunately not all backends allow connection opened in one
        # thread to be used in another thread.
        self.cie_available.acquire()
        while self.cie == None:
            self.cie_available.wait()
        self.cie_available.release()
        if len(self.cie) != 0:
            raise self.cie[0]

    # Called from the main thread. The enquete/dispatch is a little
    # hairy to workaround bug present at leat in python 2.5, which
    # causes reference count of the bounded instance method to become
    # incorrect if the reference is passed back and forth from one
    # thread to another. Instead, keep the reference in the caller's
    # thread in dictionary, passing only integer index around.
    def enqueue(self, items, res_cb, arraysize, *callback_parameters):
        self.i_res_cb += 1
        self.res_cbs[self.i_res_cb] = (res_cb, callback_parameters)
        self.wi_available.acquire()
        self.wi_queue.append((items, self.i_res_cb, arraysize, time()))
        if len(self.wi_queue) > self.max_queue_len:
            self.max_queue_len = len(self.wi_queue)
        self.wi_available.notify()
        self.wi_available.release()

    def queue_len(self):
        self.wi_available.acquire()
        res = len(self.wi_queue)
        self.wi_available.release()
        return (res, self.max_queue_len)

    # Called from the main thread
    def dispatch(self, i_res_cb, ress, eps):
        res_cb, callback_parameters = self.res_cbs[i_res_cb]
        del self.res_cbs[i_res_cb]
        if res_cb != None:
            res_cb(ress, eps, *callback_parameters)

    # Worker thread
    def run(self):
        self.cie_available.acquire()
        self.cie = ()
        try:
            handler = SQLSyncHandler(self.__dsn, lazy_connect = self.lazy_connect)
        except Exception, e:
            self.cie = (e,)
        self.cie_available.notify()
        self.cie_available.release()
        if len(self.cie) > 0:
            return

        while True:
            self.wi_available.acquire()
            while len(self.wi_queue) == 0:
                self.wi_available.wait()
            items, i_res_cb, arraysize, stime = self.wi_queue.pop(0)
            self.wi_available.release()
            if items == None:
                # Shutdown request
                return
            ress, eps = handler.runQueries(items, arraysize)
            #print datetime.now(), 'queue duration:', time() - stime
            reactor.callFromThread(self.dispatch, i_res_cb, ress, eps)

    def shutdown(self, join_timeout):
        # Should be called from the main thread
        self.wi_available.acquire()
        wi_queue = self.wi_queue
        self.wi_queue = []
        self.wi_available.release()
        # Should be called from the main thread
        self.enqueue(None, None, None)
        self.join(join_timeout)
        # Callback everybody who is waiting, tell them the bad news
        for items, i_res_cb, arraysize, stime in wi_queue:
            if i_res_cb == None:
                continue
            res_cb, callback_parameters = self.res_cbs[i_res_cb]
            del self.res_cbs[i_res_cb]
            if res_cb != None:
                eps = [Exception('Database client shutting down') for x in items]
                res_cb([], eps, *callback_parameters)
        # Make sure we don't create circular reference
        self.__owner = None
