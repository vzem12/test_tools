#!/usr/bin/env python

from scapy.all import *
from time import sleep
import time
from socket import *
import os, sys
import random
from random import randint
from threading import Thread
import argparse
from argparse import RawTextHelpFormatter

interface = 'enp3s0f0'
pingServer = '8.8.8.8'
pingInterval = 3
clientsNum = 10
pingTimeout = 5
conf.iface = interface
my_mac = Ether().src

parser = argparse.ArgumentParser(description='\033[33m\033[1mDHCP client emulator with ping\033[0m')
parser.add_argument('-n','--number', type=int, default=clientsNum, help=f"Count of Clients (default {clientsNum})")
parser.add_argument('-s','--server', type=str, default=pingServer, help=f"Ping server ip (default {pingServer})")
parser.add_argument('-i','--interval', type=str, default=pingInterval, help=f"Interval between pings (default {pingInterval} sec)")
parser.add_argument('-t','--timeout', type=str, default=pingTimeout, help=f"Ping timeout (default {pingTimeout} sec)")

args = parser.parse_args()
num = args.number
pingServer = args.server
pingInterval = args.interval
pingTimeout = args.timeout

state = True

arp_jobs = list()
ping_jobs = list()

pingStatus = dict()
pingMissing = dict()
pingCounter = dict()
ipClients = dict()
macClients = list()
ipServers = dict()
macServers = dict()

random.seed()

def mac_to_byte(mac):
    byte_mac = b''
    for i in range(6):
        byte_mac += bytes([int(mac[i*2:i*2+2], 16)])
    return byte_mac
 
 
def draw():
    while state:
        os.system('clear')
        print()
        print('\033[36m\033[1mClient IP\t\tPing Status\tPing Missing\tPing Counter\033[0m')
        for mac in macClients:
            print(f'\033[34m\033[1m{ipClients[mac]}\033[0m\t\t', end='')
            print('\033[32m\033[1mOK\033[0m\t\t' if pingStatus[mac] else '\033[31m\033[1m\033[6mX\033[0m\t\t', end='')
            print(f'\033[32m\033[1m{pingMissing[mac]}\033[0m\t\t' if pingMissing[mac]==0 else f'\033[31m\033[1m{pingMissing[mac]}\033[0m\t\t', end='')
            print(f'\033[34m\033[1m{pingCounter[mac]}\033[0m\t\t')
        sleep(1)
       
    
def macgen():
    vendors = ['80:4e:70', '00:30:48', '2c:fd:a1', '00:25:90']
    vendor = random.choices(vendors, weights = [25,25,25,25])
    mac = RandMAC()
    l = mac.split(':')
    lmac = vendor[0] + ":{}:{}:{}".format(l[0], l[1], l[2])
    return lmac
    
    
def arp_reply(ipClient, ipServer, macServer, macClient):
    try:
        while state:
            arp_pkt = sniff(filter=f"arp dst host {ipClient}", count=1, stop_filter=not state, timeout=2)
            try:
                arp_rep = Ether(dst=arp_pkt[0]['Ether'].src, src=macClient)/\
                            ARP(op=2, hwdst=arp_pkt[0]['ARP'].hwsrc, pdst=arp_pkt[0]['ARP'].psrc, hwsrc=macClient,      
                            psrc=ipClient)
                sendp(arp_rep, verbose=0)
            except IndexError:
                pass
    except KeyboardInterrupt:
        pass

def ping(ipClient, ipServer, macServer, macClient):
    global pingMissing
    global pingStatus
    global pingCounter
    seq = 0
    pingID = randint(0,65025)
    ethernet = Ether(dst=macServer, src=macClient, type=0x800) 
    ip = IP(src=ipClient, dst=pingServer)
    icmp = ICMP(id=pingID)      
    load = Raw('0¥ !"'+"#$%&'()*+,-./01234567")
    pingPacket = ethernet/ip/icmp/load 
    pingPacket['IP'].id = randint(0,65025)
    while state:
        pingCounter[macClient] += 1
        if seq < 65025:
            seq += 1
        else:
            seq = 1
        pingPacket['ICMP'].seq = seq
        try:
            ans = srp1(pingPacket, timeout=pingTimeout, verbose=0)
            if ans[0]['ICMP'].seq == seq:
                pingStatus[macClient] = True
            else:
                pingStatus[macClient] = False
                pingMissing[macClient] += 1
            sleep(pingInterval)
        except Exception:
            pingMissing[macClient] += 1
            pingStatus[macClient] = False
            sleep(pingInterval)
         
try:        
    for i in range(num):
        macClients.append(macgen())

    for macClient in macClients:
        macClient_byte = mac_to_byte(macClient.replace(':',''))
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=macClient, type=0x800) 
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=macClient_byte, xid=0)
        discover_dhcp = DHCP(options=[("message-type","discover"),("end")])
        discover =  ethernet/ip/udp/bootp/discover_dhcp
        ok = False

        while not ok:
            okDiscover = False
            while not okDiscover:
                xid = randint(0,4000000000)
                discover['BOOTP'].xid = xid
                sendp(discover, verbose=0)
                pkt = sniff(filter=f'(udp port 68) and (ether dst host {macClient})', count=1, timeout=3)
                try:
                    ipClient = pkt[0]['BOOTP'].yiaddr
                    ipServer = pkt[0]['BOOTP'].siaddr if pkt[0]['BOOTP'].siaddr != '0.0.0.0' else pkt[0]['IP'].src
                    macServer = pkt[0]['Ether'].src
                    transaction = pkt[0]['BOOTP'].xid
                    okDiscover = True
                    if xid != transaction:
                        okDiscover = False
                except IndexError:
                    pass

            request_dhcp = DHCP(options=[("message-type","request"), ('server_id',ipServer), 
                                            ('hostname', macClient), ('requested_addr', ipClient), ("end")])    
            request =  ethernet/ip/udp/bootp/request_dhcp
            request['BOOTP'].xid = xid
            sendp(request, verbose=0)
            pkt = sniff(filter=f'(udp port 68) and (ether dst host {macClient})', count=1, timeout=3)
            try:
                ipClient = pkt[0]['BOOTP'].yiaddr
                ipServer = pkt[0]['BOOTP'].siaddr if pkt[0]['BOOTP'].siaddr != '0.0.0.0' else pkt[0]['IP'].src
                transaction = pkt[0]['BOOTP'].xid
                ok = True
                if xid != transaction:
                    ok = False
            except IndexError:
                pass
        ipClients[macClient] = ipClient
        ipServers[macClient] = ipServer
        macServers[macClient] = macServer
        pingStatus[macClient] = False
        pingMissing[macClient] = 0
        pingCounter[macClient] = 0
        print(f'Client \033[36m{macClient} \033[32m\033[1mconnected\033[0m with ip: \033[36m{ipClient}\033[0m')
        arp_jobs.append(Thread(target=arp_reply, args=(ipClient, ipServer, macServer, macClient,)))
        ping_jobs.append(Thread(target=ping, args=(ipClient, ipServer, macServer, macClient,)))

    for job in arp_jobs:
        job.start()
        sleep(0.3)
    for job in ping_jobs:
        job.start()
        sleep(0.3)
    
    start_time = time.time()
    
    draw_job = Thread(target=draw)
    draw_job.start()

    for job in arp_jobs:
        job.join()
    for job in ping_jobs:
        job.join()
    draw_job.join()
except OSError:
    print(f'\033[31m\033[1mInterface {interface} down\033[0m')
except KeyboardInterrupt:
    state = False
    stop_time = time.time()
    delta_time = round(stop_time - start_time)
    time_str = time.strftime('%Hh %Mm %Ss', time.gmtime(delta_time))
    print(f'\rTime ellapsed: {time_str}')
    print('Pleace, wait...\r', end='')
    sleep(2)
    print('                                             ')
else:
    pass
finally:
    pass
