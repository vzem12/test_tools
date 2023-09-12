#!/usr/bin/env python

from scapy.all import *
from time import sleep
from socket import *
import os, sys
import random
from random import randint
from threading import Thread
import time
import argparse
from argparse import RawTextHelpFormatter
import re

parser = argparse.ArgumentParser(description="WiFi Client Traffic Generator for SQM p.5.7.3 - Client Part", formatter_class=RawTextHelpFormatter)
parser.add_argument('-n','--number', type=int, default=16, help="Number of clients")
parser.add_argument('-t','--type', type=int, default=1, help=f"Type of traffic.\n"
                                                                        "1-PC Serfing;\n"
                                                                        "2-Mobile Serfing;\n"
                                                                        "3-Online Video;\n"
                                                                        "4-Online Game")
parser.add_argument('-d','--duration', type=int, default=300, help="Duration of the test")
parser.add_argument('-p','--ping', action="store_true", help="Only Ping (without traffic)")
args = parser.parse_args()
num = args.number
only_ping = args.ping
traffic_type = args.type

ping_timeout = 6 #sec
test_interval = args.duration
prefix = '38'
octet2 = '36'
interface = 'enp4s0f0'
numbers_all = ['11','12','13', '21', '22', '23', '31', '32', '33', '41', '42', '43', '51', '52', '53', '61']

numbers = list()
for i in range(num):
    numbers.append(numbers_all[i])
    
ping_result = dict()
max_delay = dict()
min_delay = dict()
loss = dict()
ping_send = dict()
ping_send_ok = dict()
status = dict()
delay_sum = dict()

jobs_1 = list()
jobs_2 = list()
sended = list()
random.seed()

state = True

def packet_serf():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [90,4,3,1,2])
    return packet[0]

def packet_serf_inter():
    inters = [[5000, 10000], [250, 9999], [5, 6]]
    inter = random.choices(inters, weights = [50,2,48])
    return inter[0]
    
def packet_yutb():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [930,50,5,5,10])
    return packet[0]

def packet_yutb_inter():
    inters = [[1000, 10000], [100, 9999], [10, 20]]
    inter = random.choices(inters, weights = [50,20,30])
    return inter[0]
    
def packet_game():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [9,55,34,1,1])
    return packet[0]

def packet_game_inter():
    inters = [[140, 10000], [110, 139], [80, 109]]
    inter = random.choices(inters, weights = [1,98,1])
    return inter[0]

def packet_serf_mobile():
    packet = random.choices([[79,79], [80,159], [160,639],[640,1279],[1280, 1500]], 
    weights = [86,9,2,1,2])
    return packet[0]

def packet_serf_mobile_inter():
    inters = [[30, 1000], [6, 20], [3, 5], [1, 2]]
    inter = random.choices(inters, weights = [85,6,5,4])
    return inter[0]
    
print('Starting. \nPleace, wait ...')
try:
    for number in numbers:
        os.popen(f'ip link add link {interface} name CL_{prefix+number} type vlan id {prefix+number}', mode='r', buffering=-1)
        os.popen(f'ip addr add 10.{octet2}.{number}.2/24 brd 10.{octet2}.{number}.255 dev CL_{prefix+number}', mode='r', buffering=-1)
        os.popen(f'ip link set dev CL_{prefix+number} up', mode='r', buffering=-1)
        
    for number in numbers:
        ping_result[number] = 1
        status[number] = 'OFF'
        ping_send[number] = 0
        min_delay[number]  = 99999
        delay_sum[number] = 0
        ping_send_ok[number] = 0
        
    def serf_send(number):
        while True:
            if not state: break
            if traffic_type == 1:
                inter_range = packet_serf_inter()
                mtu_range = packet_serf()
            elif traffic_type == 2:
                inter_range = packet_serf_mobile_inter()
                mtu_range = packet_serf_mobile()
            elif traffic_type == 3:
                inter_range = packet_yutb_inter()
                mtu_range = packet_yutb()
            elif traffic_type == 4:
                inter_range = packet_game_inter()
                mtu_range = packet_game()
            interval = random.randint(inter_range[0], inter_range[1])/1000
            mtu = randint(mtu_range[0], mtu_range[1])-79
            dop = 'A'*mtu
            payload = 'REQQ'+dop
            packet = Ether()/IP(dst=f'10.36.{number}.1', src=f'10.36.{number}.2')/UDP(sport=int('204'+number), dport=int('204'+number))/Raw(load=payload)
            count = round(1/interval)
            sendp(packet, inter=interval, iface=f'CL_{prefix+number}', count=count, verbose=False)
        Socket.close()
        
        
    def alive_test(number):
        global max_delay, loss, ping_result
        SEQ = 0
        connected = False
        max_delay[number] = 0
        loss[number] = 0
        Socket = socket(AF_INET, SOCK_STREAM)
        Socket.settimeout(ping_timeout)
        Socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 10000)
        connected = False
        while not connected:
            try:
                Socket.connect((f'10.36.{number}.1', int(f'205{number}')))
                connected = True
                status[number] = 'ON'
            except:
                sleep(1)
        
        while True:
            if not state:
                break
            try:
                SEQ += 1 
                current_time = time.time()
                Socket.sendall(f"\t{SEQ}\t".encode())
                ping_send[number] += 1
                data = Socket.recv(4600)
                SEQ_IN = int((re.search(r'\t\d+\t', data.decode()))[0].strip())
                if SEQ_IN != SEQ:
                    data = Socket.recv(4600)
                dt = round((time.time() - current_time)*1000)
                delay_sum[number] += dt
                if max_delay[number] < dt:
                    max_delay[number] = dt
                if min_delay[number] > dt:
                    min_delay[number] = dt
                ping_result[number] = 0
                ping_send_ok[number] += 1
            except:
                loss[number] += 1
                ping_result[number] = 1
            sleep(0.5)
        Socket.close()
            
    
    def draw_table():
        print()
        t = time.time()
        while True:
            os.system('clear')
            dt = round((time.time() - t), 4)
            print(f'TIME\t{dt} sec')
            print(f'PING TIMEOUT = {ping_timeout} sec')
            print("#"*153)
            print('CLIENT\t\t\t', end='')
            for number in numbers:
                print(f'| CL-{number}\t', end='')
            print('|')
            print("#"*153)
            print('CONNECTION  \t\t', end='')
            for number in numbers:
                print(f'| {status[number]}\t', end='')
            print('|')
            print('PING STATUS  \t\t', end='')
            for number in numbers:
                print('| OK \t' if ping_result[number] == 0 else '| X \t', end='')
            print('|')
            print("-"*153)
            print('MIN DELAY (ms)\t\t', end='')
            for number in numbers:
                print(f'| {min_delay[number]} \t' if min_delay[number] != 99999 else '| - \t', end='')
            print('|')
            print('MAX DELAY (ms)\t\t', end='')
            for number in numbers:
                print(f'| {max_delay[number]}\t' if max_delay[number] > 0 else '| - \t', end='')
            print('|')
            print('AVERAGE DELAY (ms)\t', end='')
            for number in numbers:
                print(f'| {round(delay_sum[number]/ping_send_ok[number])}\t' if delay_sum[number] > 0 else '| - \t', end='')
            print('|')
            print("-"*153)
            print('PING SEND (pkts)\t', end='')
            for number in numbers:
                print(f'| {ping_send[number]} \t', end='')
            print('|')
            print('PING LOSS (pkts)\t', end='')
            for number in numbers:
                print(f'| {loss[number]} \t', end='')
            print('|')
            print("-"*153)
            if dt >= test_interval:
                state = False
                sleep(2)
                pname = os.path.basename(sys.argv[0])
                os.system(f"pkill -f {pname}")
                break
            sleep(1)
        
    
    if not only_ping:     
        for number in numbers:
            jobs_1.append(Thread(target=serf_send, args=(number,)))
    for number in numbers:
        jobs_2.append(Thread(target=alive_test, args=(number,)))
    
    if not only_ping:  
        for job in jobs_1:
            job.start()
    for job in jobs_2:
        job.start()
        
    draw = Thread(target=draw_table)
    draw.start()
    draw.join()
    
    if not only_ping: 
        for job in jobs_1:
            job.join()
    for job in jobs_2:
        job.join()
except KeyboardInterrupt:
    state = False
