#!/bin/sh

set -e

uname -a
which ${CC}
${CC} --version
python3 --version
sudo iptables -L OUTPUT
sudo iptables -L INPUT
sudo sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6'
echo -n "/proc/sys/kernel/core_pattern: "
cat /proc/sys/kernel/core_pattern

sudo DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confnew" \
 install -y xsltproc fop

./configure
make -C doc clean all

COMMITTER_EMAIL="`git log -1 ${TRAVIS_COMMIT} --pretty="%cE"`"
AUTHOR_NAME="`git log -1 ${TRAVIS_COMMIT} --pretty="%aN"`"

DDP_REPO_SLUG=sobomax/rtptestdoc
DDP_SDIR=docdeploy
DDP_GIT="git -C ${DDP_SDIR}"
DDP_PDIR="doc/${TRAVIS_BRANCH}"
git clone https://${GITHUB_TOKEN}@github.com/${DDP_REPO_SLUG}.git ${DDP_SDIR}
for f in doc/*.html
do
  dname="`basename ${f}`"
  DDP_PTH="${DDP_PDIR}/${dname}"
  DDP_TGT="${DDP_SDIR}/${DDP_PTH}"
  DDP_TGTDIR="${DDP_SDIR}/${DDP_PDIR}"
  if [ -e "${DDP_TGT}" ]
  then
    ${DDP_GIT} rm "${DDP_PTH}"
  fi
  if [ ! -e "${DDP_TGTDIR}" ]
  then
    mkdir -p "${DDP_TGTDIR}"
  fi
  cp ${f} "${DDP_TGT}"
  ${DDP_GIT} add "${DDP_PTH}"
done
${DDP_GIT} commit -m "Re-gen by job {TRAVIS_BUILD_ID} from ${TRAVIS_COMMIT}." \
 --author="${AUTHOR_NAME} <${COMMITTER_EMAIL}>" ${DDP_PDIR}
${DDP_GIT} push
