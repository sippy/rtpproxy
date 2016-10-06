#!/bin/sh

set -e

SLITE_LIST=`cat python/sippy_lite.list`
git checkout sippy_git_master
git pull
git branch -D sippy_git_master_toplevel
git subtree split --prefix=sippy --branch=sippy_git_master_toplevel
git checkout sippy_git_master_toplevel
mkdir -p python/sippy_lite/Math
mkdir -p python/sippy_lite/Time
for f in ${SLITE_LIST}
do
  git mv ${f} python/sippy_lite/sippy/${f}
done
git rm .gitignore dictionary *.py
git commit -m "Move files in place."
git checkout master
git pull
git merge sippy_git_master_toplevel
#git add python/sippy_lite/.gitignore rtp_cluster_client.py LICENSE
#git commit
#git push
