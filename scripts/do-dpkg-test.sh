#!/usr/bin/env bash

set -euo pipefail
set -x

start_systemd() {
  find /lib/systemd/system/sysinit.target.wants -mindepth 1 -maxdepth 1 \! -name systemd-tmpfiles-setup.service | xargs rm -f
  rm -f /lib/systemd/system/multi-user.target.wants/\*
  rm -f /etc/systemd/system/\*.wants/\*
  rm -f /lib/systemd/system/local-fs.target.wants/\*
  rm -f /lib/systemd/system/sockets.target.wants/\*udev\*
  rm -f /lib/systemd/system/sockets.target.wants/\*initctl\*
  rm -f /lib/systemd/system/basic.target.wants/\*
  rm -f /lib/systemd/system/anaconda.target.wants/\*

  unshare --pid --fork --mount-proc /lib/systemd/systemd --system-unit=basic.target --system &
  sleep 1
}

start_systemd
systemd_pid=`ps -C systemd -o pid=`

NSRUN="nsenter -t ${systemd_pid} -a"

${NSRUN} systemctl daemon-reload
${NSRUN} systemctl enable --now rtpproxy.socket
${NSRUN} systemctl start rtpproxy.service
${NSRUN} systemctl status --no-pager rtpproxy.service
${NSRUN} systemctl restart rtpproxy.service
${NSRUN} systemctl status --no-pager rtpproxy.service
${NSRUN} systemctl stop rtpproxy.service
${NSRUN} systemctl status --no-pager rtpproxy.service || true
${NSRUN} systemctl disable rtpproxy.socket
${NSRUN} systemctl is-enabled rtpproxy.socket || true
${NSRUN} systemctl status --no-pager rtpproxy.socket || true
