#!/usr/bin/env python

from scapy.all import *
from time import sleep
from socket import *
import os, sys
import random
from random import randint
from threading import Thread
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser()
parser.add_argument('-n','--number', type=int, default=3, help="Count of AP")
parser.add_argument('-ap', type=int, help="AP number")
args = parser.parse_args()
num = args.number
ap = args.ap

prefix = '38'
octet2 = '36'
interface = 'enp4s0f0'
numbers1 = ['11','12','13', '21', '22', '23', '31', '32', '33']
numbers = list()

if ap is None:
    for i in range(3*num):
        numbers.append(numbers1[i])
else:
    for i in range(3):
        numbers.append(numbers1[((ap-1)*3)+i])
    
jobs = list()
sended = list()
random.seed()

state = True

def status():
    os.system('cls')
    print(f'\nVlan\t\tSended packets')
    for number in numbers:
        print(f'{prefix+number}\t\t{sended[number]}')
        
def packet_serf(number):
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [90,4,3,1,2])
    return packet[0]

def packet_serf_inter():
    inters = [[5000, 10000], [250, 9999], [5, 6]]
    inter = random.choices(inters, weights = [50,2,48])
    return inter[0]
    
def packet_yutb(number):
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [930,50,5,5,10])
    return packet[0]

def packet_yutb_inter():
    inters = [[1000, 10000], [100, 9999], [10, 20]]
    inter = random.choices(inters, weights = [50,20,30])
    return inter[0]
    
def packet_game(number):
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [9,55,34,1,1])
    return packet[0]

def packet_game_inter():
    inters = [[140, 10000], [110, 139], [80, 109]]
    inter = random.choices(inters, weights = [1,98,1])
    return inter[0]

print('Starting. \nPleace, wait ...')
print(numbers)
try:
    for number in numbers:
        os.popen(f'ip link add link {interface} name CL_{prefix+number} type vlan id {prefix+number}', mode='r', buffering=-1)
        os.popen(f'ip addr add 10.{octet2}.{number}.2/24 brd 10.{octet2}.{number}.255 dev CL_{prefix+number}', mode='r', buffering=-1)
        os.popen(f'ip link set dev CL_{prefix+number} up', mode='r', buffering=-1)
      
    
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
    print(serf_number)
    print(yutb_number)
    print(game_number)
    def serf_send(number):
        Socket = socket(AF_INET, SOCK_DGRAM)
#        Socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
#        Socket.setsockopt(IPPROTO_TCP, TCP_WINDOW_CLAMP, 10000)
        Socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 10000)
        Socket.bind((f'10.{octet2}.{number}.2', 3679))
        address = (f'10.{octet2}.{number}.1', 3659)
#        Socket.connect(address)
        while True:
            if not state: break
            inter_range = packet_serf_inter()
            interval = random.randint(inter_range[0], inter_range[1])/10000
            mtu_range = packet_serf(number)
            mtu = randint(mtu_range[0], mtu_range[1])-79
            dop = 'A'*mtu
            payload = 'SERF'+dop
            packet = payload.encode()
            count = round(1/interval)
            for i in range(count):
                Socket.sendto(packet, address)
                sleep(interval)
        Socket.close()
            

    def yutb_send(number):
        Socket = socket(AF_INET, SOCK_DGRAM)
        address = (f'10.{octet2}.{number}.1', 3660)
#        Socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
#        Socket.setsockopt(IPPROTO_TCP, TCP_WINDOW_CLAMP, 10000)
        Socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 10000)
        Socket.bind((f'10.{octet2}.{number}.2', 3680))
#        Socket.connect(address)
        while True:
            if not state: break
            inter_range = packet_yutb_inter()
            interval = random.randint(inter_range[0], inter_range[1])/10000
            mtu_range = packet_yutb(number)
            mtu = randint(mtu_range[0], mtu_range[1])-79
            packet = ('SERF'+('A'*mtu)).encode()
            count = round(1/interval)
            for i in range(count):
                Socket.sendto(packet, address)
                sleep(interval)
        Socket.close()
            
            
    def game_send(number):
        Socket = socket(AF_INET, SOCK_DGRAM)
        address = (f'10.{octet2}.{number}.1', 3661)
#        Socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
#        Socket.setsockopt(IPPROTO_TCP, TCP_WINDOW_CLAMP, 10000)
        Socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 10000)
        Socket.bind((f'10.{octet2}.{number}.2', 3681))
#        Socket.connect(address)
        while True:
            if not state: break
            inter_range = packet_game_inter()
            interval = random.randint(inter_range[0], inter_range[1])/10000
            mtu_range = packet_game(number)
            mtu = randint(mtu_range[0], mtu_range[1])-79
            packet = ('SERF'+('A'*mtu)).encode()
            count = round(1/interval)
            for i in range(count):
                Socket.sendto(packet,address)
                sleep(interval)
        Socket.close()


    for n in serf_number:
        jobs.append(Thread(target=serf_send, args=(n,)))
    for n in yutb_number:
        jobs.append(Thread(target=yutb_send, args=(n,)))
    for n in game_number:
        jobs.append(Thread(target=game_send, args=(n,)))
    for job in jobs:
        job.start()
    print('Runing')
    for job in jobs:
        job.join()
except KeyboardInterrupt:
    print('\nStopping. \nPleace, wait...')
    state = False
#    for number in numbers:
#        os.popen(f'ip link set dev CL_{prefix+number} down')
#        os.popen(f'ip link delete CL_{prefix+number}')
        

