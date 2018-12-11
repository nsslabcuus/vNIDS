#!/bin/bash

if [[ -z $2 ]]; then
    echo "Usage: $0 <controller-ip> <interval> <switch-id>"
    echo "e.g. $0 10.10.1.4 5 00:00:74:a0:2f:5f:17:e4"
    exit 1
fi

ip=$1
interval=$2
switch_id=$3
if [[ -z $switch_id ]]; then 
    switch_id="00:00:74:a0:2f:5f:17:e4"
fi

curl http://$ip:8080/wm/core/switch/$switch_id/port/json | python -m json.tool





