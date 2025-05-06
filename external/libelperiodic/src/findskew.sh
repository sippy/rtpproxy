#!/bin/sh

set -e

freq=20000
min_good=0
max_bad=0
direction=0
missed=0
TS_ARGS="-qS ${@}"
while [ ${max_bad} -eq 0 -o ${missed} -eq 0 ]
do
  missed=`./testskew ${TS_ARGS} ${freq} 1 | sed 's|^-||'`
  if [ ${missed} -lt 1000 ]
  then
    freq=$((${freq} * 2))
  else
    max_bad=${freq}
    break
  fi
done
while [ ${min_good} -eq 0 -o ${max_bad} -eq 0 -o $((${max_bad} - ${min_good})) -gt 100 ]
do
  missed=`./testskew ${TS_ARGS} ${freq} 1 | sed 's|^-||'`
  if [ ${missed} -lt 1000 ]
  then
    if [ ${direction} -eq 0 ]
    then
      direction=1
    fi
    min_good=${freq}
    freq=$((${min_good} + (${max_bad} - ${min_good}) / 2))
  else
    if [ ${direction} -eq 1 ]
    then
      direction=0
    fi
    max_bad=${freq}
    freq=$((${min_good} + (${max_bad} - ${min_good}) / 2))
  fi
done
echo ${min_good} "-" ${max_bad}
