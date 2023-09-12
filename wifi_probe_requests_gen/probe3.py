#Probe Requests wifi generator
#by Zemtsov VA

#Sould be installed:
#Python 3.6.7-1~18.04
#Scapy 2.4.3
#aircrack-ng

#BEFORE START, ENTER THE WIFI INTERFACE NAME IN THE intf VARIABLE

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import random


intf = "wlp2s0"         #name of phy wlan interface
vendors = ['04:92:26', '00:e0:4c', '54:27:58', 'd0:9c:7a', '90:4f:70']      #list of vendors mac id (first 3 octets of mac address)
dst = "ff:ff:ff:ff:ff:ff"       #destination mac
rtr = "ff:ff:ff:ff:ff:ff"       #router mac





def MAC_gen():
  	mac = RandMAC()
  	l = mac.split(':')
  	lmac = vendors[random.randint(1,len(vendors)-1)] + ":{}:{}:{}".format(l[0], l[1], l[2])
  	return lmac

ratess = "\x0c\x12\x18\x24\x30\x48\x60\x6c"
ssid_lst = ['One', 'Two', 'Three', '']
channels_lst = ['\x01','\x02','\x03','\x04','\x05','\x06','\x07','\x08','\x09','\x0a','\x0b','\x0c']
frequency_lst = ['\x6c\x09','\x71\x09','\x76\x09','\x7b\x09','\x80\x09','\x85\x09','\x8a\x09','\x8f\x09','\x94\x09','\x99\x09','\x9e\x09','\xa3\x09']
freq_lst = [2412, 2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467]
channels=[]
frequency=[]
channels_int=[]
conf.iface = intf
print("IF: ", conf.iface)

SC=0
intfmon = intf + 'mon'

os.system('airmon-ng start %s && airmon-ng check kill' % (intf))
#os.system('service network-manager stop && ifconfig %s down && iwconfig %s mode monitor && ifconfig %s up' % (intfmon,intf,intf)) 

_ssid = input("Enter a list of SSID (One,Two,Three def - DEFAULT) []: ")
if _ssid != "":
    if _ssid == 'def' or _ssid == 'Def' or _ssid == 'DEF' or _ssid == 'deF' or _ssid == 'DeF':
        ssid_lst=ssid_lst
    else:
        if "," in _ssid:
            ssid_lst = _ssid.split(',')
        else:
            ssid_lst=[]
            ssid_lst.append(_ssid)
else:
    ssid_lst=[]
    ssid_lst.append('')
    
chan = input('Enter a list of channels (1,2,5,7 or 1-12) [1]: ')
if "," in chan:
    channels_num = chan.split(',')
    for s in range(len(channels_num)):
        channels.append(channels_lst[int(channels_num[s])-1])
        frequency.append(frequency_lst[int(channels_num[s])-1])
        channels_int.append(int(chan))
elif "-" in chan:
    channels_num = chan.split('-')
    for s in range(int(channels_num[0]),int(channels_num[1])+1):
        channels.append(channels_lst[s-1])
        frequency.append(frequency_lst[s-1])
        channels_int.append(s)
elif chan != '':
    channels.append(channels_lst[int(chan)-1])
    frequency.append(frequency_lst[int(chan)-1])
    channels_int.append(int(chan))
else:
    chan = '1'
    channels = ['\x01']
    frequency = ['\x6c\x09']
    channels_int.append(int(chan))
 
count = 1
try:
    inter = Decimal(input('Enter packet sending interval [0.1]: '))
except:
    inter = 0.1
try:
    mac_sum = int(input('Enter the number of MAC addresses [3000]: '))  
except:
    mac_sum = 3000

if len(ssid_lst) == 1 and ssid_lst[0] == '':
    ssidss = "''"
else:
    ssidss = ','.join(ssid_lst)
    ssidss = ssidss[0:len(ssidss)-1]

print('')
print('Start sending %d MAC addresses with interval %.2f on channels %s SSID list %s' % (mac_sum, inter, chan, ssidss))
print('')

try:
    for i in range(mac_sum):
        src = MAC_gen()

        for chanel in range(len(channels)):
            os.system('iwconfig %s channel %s' % (intfmon,channels_int[chanel]))
            for n in range(len(ssid_lst)):
                for m in range(3):
                    ssid = ssid_lst[n]
                    param = Dot11ProbeReq()
                    essid = Dot11Elt(ID='SSID',info=ssid)
                    rates  = Dot11Elt(ID='Rates', info=ratess)
                    vendor = Dot11Elt(ID=221, len=8, info=(b'\x00\x00\xf0\x0c\x00\x00\x01\x01'))
                    RadioTP = RadioTap(version=0, pad=0, present="A_MPDU+Rate+Channel+dBm_AntSignal+TXFlags+Flags", dBm_AntSignal = -54,
                    ChannelFlags='2GHz+CCK', Rate=2, ChannelFrequency=freq_lst[chanel])
                    dsset = Dot11Elt(ID='DSset', info=channels[chanel])
                    pkt = RadioTP/Dot11(type=0,subtype=4,addr1=dst,addr2=src,addr3=rtr,SC=SC)/param/essid/dsset/rates/vendor
                    sendp(pkt, count=count, inter=inter, verbose=False, iface=intfmon)

                    if SC == 65520:
                        SC=0 
                    else:               
                        SC=SC+16

                    print ('MAC: %s, SSID: %s, chanel: %s, SC: %s' % (src, ssid, channels_lst.index(channels[chanel])+1, int(SC/16)))
    
    os.system('airmon-ng stop %s && service network-manager start' % (intfmon))    
    #os.system('service network-manager start && ifconfig %s down && iwconfig %s mode managed && ifconfig %s up' % (intf,intf,intf))
    print ("")    
    print ('Total sent %d mac-addresses' % (i+1))

except KeyboardInterrupt:
    os.system('airmon-ng stop %s && service network-manager start' % (intfmon))    
    #os.system('service network-manager start && ifconfig %s down && iwconfig %s mode managed && ifconfig %s up' % (intf,intf,intf))
    print ("")    
    print ('Total sent %d mac-addresses' % (i+1))


#
