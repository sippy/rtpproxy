# b2bua_radius - this script starts and stops the b2bua_radius daemon
#
# chkconfig:   - 85 15
# description:  b2bua_radius is RADIUS-enabled SIP
#		B2BUA
# processname: b2bua_radius
# config:      /etc/sysconfig/b2bua_radius
# pidfile:     /var/run/b2bua_radius.pid

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ "$NETWORKING" = "no" ] && exit 0

b2bua_radius="/home/maxim/b2bua/sippy/b2bua_radius.py"
prog=$(basename $b2bua_radius)

sysconfig="/etc/sysconfig/$prog"
lockfile="/var/lock/subsys/b2bua_radius"
pidfile="/var/run/${prog}.pid"

B2BUA_OPTIONS="--digest_auth=off --accept_ips=202.85.245.137 \
  -A 0 -s 202.85.243.19 --auth_enable=off -P ${pidfile} \
  --pass_headers=Remote-Party-ID,Allow,Supported"

[ -f $sysconfig ] && . $sysconfig


start() {
    [ -x $b2bua_radius ] || exit 5
    echo -n $"Starting $prog: "
    daemon python2.6 $b2bua_radius ${B2BUA_OPTIONS}
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
    return $retval
}

stop() {
    echo -n $"Stopping $prog: "
    killproc -p $pidfile $prog
    retval=$?
    echo
    [ $retval -eq 0 ] && rm -f $lockfile
    return $retval
}

restart() {
    configtest_q || return 6
    stop
    start
}

reload() {
    configtest_q || return 6
    echo -n $"Reloading $prog: "
    killproc -p $pidfile $prog -HUP
    echo
}

rh_status() {
    status $prog
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}

# Upgrade the binary with no downtime.
upgrade() {
    local oldbin_pidfile="${pidfile}.oldbin"

    configtest_q || return 6
    echo -n $"Upgrading $prog: "
    killproc -p $pidfile $prog -USR2
    retval=$?
    sleep 1
    if [[ -f ${oldbin_pidfile} && -f ${pidfile} ]];  then
        killproc -p $oldbin_pidfile $prog -QUIT
        success $"$prog online upgrade"
        echo 
        return 0
    else
        failure $"$prog online upgrade"
        echo
        return 1
    fi
}

# Tell b2bua_radius to reopen logs
reopen_logs() {
    configtest_q || return 6
    echo -n $"Reopening $prog logs: "
    killproc -p $pidfile $prog -USR1
    retval=$?
    echo
    return $retval
}

case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart|configtest|reopen_logs)
        $1
        ;;
    force-reload|upgrade) 
        rh_status_q || exit 7
        upgrade
        ;;
    reload)
        rh_status_q || exit 7
        $1
        ;;
    status|status_q)
        rh_$1
        ;;
    condrestart|try-restart)
        rh_status_q || exit 7
        restart
        ;;
    *)
        echo $"Usage: $0 {start|stop|reload|configtest|status|force-reload|upgrade|restart|reopen_logs}"
        exit 2
esac
