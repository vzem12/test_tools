#!/usr/bin/env python

from time import sleep
from socket import *
import os, sys
import random
from threading import Thread
from random import randint
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(description="WiFi Client Traffic Generator for SQM p.5.7.3 - Server Part", formatter_class=RawTextHelpFormatter)
parser.add_argument('-t','--type', type=int, default=1, help=f"Type of traffic.\n"
                                                                        "1-PC Serfing;\n"
                                                                        "2-Mobile Serfing;\n"
                                                                        "3-Online Video;\n"
                                                                        "4-Online Game")
args = parser.parse_args()
traffic_type = args.type
                                                                   
numbers = ['11','12','13', '21', '22', '23', '31', '32', '33', '41', '42', '43', '51', '52', '53', '61']
prefix = '36'
octet2 = '36'
interface = 'enp5s0f0'

jobs = list()

for number in numbers:
    os.popen(f'ip link add link {interface} name AP_{prefix+number} type vlan id {prefix+number}')
    os.popen(f'ip addr add 10.{octet2}.{number}.1/24 brd 10.{octet2}.{number}.255 dev AP_{prefix+number}')
    os.popen(f'ip link set dev AP_{prefix+number} up')
    
def packet_serf_mobile():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [2,1,1,1,95])
    return packet[0]


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
    

def listen_socket(number):
    Socket = socket(AF_INET, SOCK_DGRAM)
    address = (f'10.36.{number}.1', int('204'+number))
    Socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 10000)
    Socket.bind(address)
    while True:
        data, address_client = Socket.recvfrom(9000)
        if data:
            try:
                if traffic_type == 1:
                    mtu_range = packet_serf()
                elif traffic_type == 2:
                    mtu_range = packet_serf_mobile()
                elif traffic_type == 3:
                    mtu_range = packet_yutb()
                elif traffic_type == 4:
                    mtu_range = packet_game()
                mtu = randint(mtu_range[0], mtu_range[1])
                dop = 'A'*mtu
                payload = 'RESP'+dop
                packet = payload.encode()
                if traffic_type == 1:
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                elif traffic_type == 2:
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                elif traffic_type == 3:
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                    Socket.sendto(packet,address_client)
                elif traffic_type == 4:
                    Socket.sendto(packet,address_client)
            except:
                pass
        else:
            print('Нет данных от:', client_address)
            break
            
            
def ping_listen(number):
    Socket = socket(AF_INET, SOCK_STREAM)
    Socket.setsockopt(SOL_SOCKET, 43, 1)
    address = (f'10.36.{number}.1', int('205'+number))
    Socket.bind(address)
    Socket.listen(5)
    while True:
        connection, client_address = Socket.accept()
        try:
            print('Подключено к:', client_address)
            while True:
                try:
                    data = connection.recv(4600)
                    if data:
                        try:    
                            connection.sendall(data+'_RESP'.encode())
                        except:
                            pass
                
                    else:
                        print('Нет данных от:', client_address)
                        break
                except ConnectionResetError:
                    pass

        finally:
            connection.close()
        
        
for number in numbers:
    jobs.append(Thread(target=listen_socket, args=(number,)))
    jobs.append(Thread(target=ping_listen, args=(number,)))
    
for job in jobs:
    job.start()
print('Runing')
for job in jobs:
    job.join()
