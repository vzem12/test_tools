#!/bin/bash
docker network create -d macvlan --subnet=192.168.1.0/24 --gateway=192.168.1.1 -o parent=enp3s0f1 macvlan0
docker run -tdi --net macvlan0 --ip=192.168.1.51 --name if1 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.52 --name if2 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.53 --name if3 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.54 --name if4 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.55 --name if5 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.56 --name if6 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.57 --name if7 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.58 --name if8 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.59 --name if9 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.60 --name if10 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.61 --name if11 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.62 --name if12 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.63 --name if13 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.64 --name if14 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.65 --name if15 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.66 --name if16 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.67 --name if17 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.68 --name if18 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.69 --name if19 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.70 --name if20 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.71 --name if21 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.72 --name if22 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.73 --name if23 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.74 --name if24 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.75 --name if25 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.76 --name if26 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.77 --name if27 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.78 --name if28 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.79 --name if29 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.80 --name if30 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.81 --name if31 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.82 --name if32 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.83 --name if33 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.84 --name if34 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator
docker run -tdi --net macvlan0 --ip=192.168.1.85 --name if35 -v '/root/FOR_SQM/ClientEmulator(35clients):/ClientEmulator' clientemulator

