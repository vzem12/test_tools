#!/bin/bash

HOST=`ifconfig eth0 | grep 'inet ' | awk '{{print $2}}'`
while true
    do
        TIME=`date +%m.%d.%y--%T`
        PING=`ping 8.8.8.8 -c 3 | grep "=2"`
        PINGR=$?        
        if [[ $PINGR != "0" ]]; then
                echo "$HOST [$TIME] Unreachable code $PINGR" >> ClientEmulator/ping.log
                tail -n 1 ClientEmulator/ping.log
            fi
        sleep 3
    done
        
