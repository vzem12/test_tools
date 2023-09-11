#!/bin/bash
docker network create -d macvlan --subnet=192.168.0.0/24 --gateway=192.168.0.1 -o parent=enp3s0f1 macvlan0
docker run -tdi --net macvlan0 --ip=192.168.0.51 --name if1 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.52 --name if2 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.53 --name if3 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.54 --name if4 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.55 --name if5 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.56 --name if6 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.57 --name if7 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
docker run -tdi --net macvlan0 --ip=192.168.0.58 --name if8 -v '/root/WebClientEmulator:/WebClientEmulator' webclientemulator
