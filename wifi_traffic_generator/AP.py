#!/usr/bin/env python

from time import sleep
from socket import *
import os, sys
import random
from threading import Thread
from random import randint

prefix = '36'
octet2 = '36'
interface = 'enp5s0f0'
numbers = ['11','12','13', '21', '22', '23', '31', '32', '33', '41', '42', '43', '51', '52', '53', '61']
serf_port = 3659
yutb_port = 3660
game_port = 3661

jobs = list()

def packet_serf():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [5,1,1,1,92])
    return packet[0]
    
def packet_yutb():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [10,6,2,2,980])
    return packet[0]
    
def packet_game():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]],
    weights = [1,4,5,76,14])
    return packet[0]

print('Starting. \nPleace, wait ...')

for number in numbers:
    os.popen(f'ip link add link {interface} name AP_{prefix+number} type vlan id {prefix+number}')
    os.popen(f'ip addr add 10.{octet2}.{number}.1/24 brd 10.{octet2}.{number}.255 dev AP_{prefix+number}')
    os.popen(f'ip link set dev AP_{prefix+number} up')

def listen_socket(number, port):
    Socket = socket(AF_INET, SOCK_DGRAM)
    address = (f'10.{octet2}.{number}.1', port)
#    Socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
#    Socket.setsockopt(IPPROTO_TCP, TCP_WINDOW_CLAMP, 3000)
    Socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 10000)
    Socket.bind(address)
#    Socket.listen(1)    
#    while True:
#        connection, client_address = Socket.accept()
#        try:
#            print('Подключено к:', client_address)
    while True:
        data, address_client = Socket.recvfrom(9000)
        if data:
            try:
                if 'SERF' in data.decode():
                    mtu_range = packet_serf()
                    mtu = randint(mtu_range[0], mtu_range[1])
                    dop = 'A'*mtu
                    payload = 'SERF'+dop
                    packet = payload.encode()
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                if 'YUTB' in data.decode():
                    mtu_range = packet_yutb()
                    mtu = randint(mtu_range[0], mtu_range[1])
                    dop = 'A'*mtu
                    payload = 'YUTB'+dop
                    packet = payload.encode()
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                if 'GAME' in data.decode():
                    mtu_range = packet_game()
                    mtu = randint(mtu_range[0], mtu_range[1])
                    dop = 'A'*mtu
                    payload = 'GAME'+dop
                    packet = payload.encode()
                    Socket.sendto(packet,address_client)
            except:
                pass
#                     pass
        else:
            print('Нет данных от:', client_address)
            break
   
            
serf_number = list()
yutb_number = list()
game_number = list()
    
for number in numbers:
    if number[1:] == '1':
        serf_number.append(number)
    if number[1:] == '2':
        yutb_number.append(number)
    if number[1:] == '3':
        game_number.append(number)
            
for n in serf_number:
    jobs.append(Thread(target=listen_socket, args=(n,serf_port,)))
for n in yutb_number:
    jobs.append(Thread(target=listen_socket, args=(n,yutb_port,)))
for n in game_number:
    jobs.append(Thread(target=listen_socket, args=(n,game_port,)))
for job in jobs:
    job.start()
print('Runing')
for job in jobs:
    job.join()
