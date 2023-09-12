from scapy.all import *
from pbkdf2 import PBKDF2
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5
import binascii, sys, hmac, hashlib, multiprocessing, time, random, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Generator:
	def __init__(self, snd, rtr, intf, SSID, PSK, SC, PWD, wpa_type, debug_p):
		self.debug_p = debug_p
		self.SC = SC
		self.PSK = PSK
		self.ratess = b"\x02\x04\x0b\x16\x0c\x12\x18\x24"
		self.exRates = b'\x30\x48\x60\x6c'
		self.sChah = b'\x24\x04\x34\x04\x95\x04\xa5\x01'
		self.SSID = SSID
		self.intf = intf         #name of phy wlan interface
		self.snd = snd.lower()      #sender mac
		self.rtr = rtr.lower()      #router mac
		conf.iface = self.intf
		self.auth_found = False
		self.assoc_found = False
		self.hs1_found = False
		self.hs3_found = False
		self.action_found = "No"
		self.PWD = PWD
		self.ipaddr = ""
		self.ipaddr_s = ""
		self.checkIPaddr = False
		self.packet = Raw(b'00')
		self.checkDHCPAck = False
		self.xid = 0
		self.ff = False

		if wpa_type == "WPA":
			self.wpa = True
		else:
			self.wpa = False

		self.stMac = a2b_hex(snd.lower().replace(":",""))
		self.apMac = a2b_hex(rtr.lower().replace(":",""))
		self.aNonce = a2b_hex("00")
		self.sNonce = a2b_hex("2c469627f2900042226b25030e2203c81c0aa82cb102d5349062605eeef87f4c")
		self.data = a2b_hex("00")

		self.SC_HS = 0

		print("########## " + "\033[1m\033[4m{}\033[0m".format(snd.upper()) + " ##########")


	def PRF(self, key, A, B):
		#Number of bytes in the PTK
		nByte = 64
		i = 0
		R = b''
		#Each iteration produces 160-bit value and 512 bits are required
		while(i <= ((nByte * 8 + 159) / 160)):
			hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
			R = R + hmacsha1.digest()
			i += 1
		return R[0:nByte]

	def MakeMIC(self, data):
		pmk = pbkdf2_hmac('sha1', self.PWD.encode('ascii'), self.SSID.encode('ascii'), 4096, 32)
		A = b"Pairwise key expansion"
		B = min(self.apMac, self.stMac) + max(self.apMac, self.stMac) + min(
		self.aNonce, self.sNonce) + max(self.aNonce, self.sNonce)
		ptk = self.PRF(pmk, A, B)
		hmacFunc = md5 if self.wpa else sha1
		mic = hmac.new(ptk[0:16], data, hmacFunc).digest()
		mic = b2a_hex(mic).decode()[:-8]
		return (mic)


	def Auth_req(self):
		self.SC = self.SC + 16
		RadioTP = RadioTap(version=0, pad=0, present="A_MPDU+Rate+Channel+dBm_AntSignal+TXFlags+Flags",
		 	dBm_AntSignal = -54, ChannelFlags='2GHz+CCK', Rate=2)
		packet = RadioTP/Dot11(addr1=self.rtr,addr2=self.snd,addr3=self.rtr,SC=self.SC)/Dot11Auth(
		algo=0,seqnum=0x0001,status=0x0000)
		sendp(packet, inter=0.001, verbose=False)
		self.Send_ACK()


	def Check_Auth(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3
		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver:
			self.auth_found = True
		return self.auth_found

	def Auth_resp(self, mp_queue):
		sniff(iface=self.intf, lfilter=lambda x: x.haslayer(Dot11Auth),
			stop_filter=self.Check_Auth, timeout=2)
		mp_queue.put(self.auth_found)
		mp_queue.put(self.SC)


	def Assoc_req(self):
		self.SC = self.SC + 32
		RadioTP = RadioTap(version=0, pad=0, present="TSFT+A_MPDU+Rate+Channel+dBm_AntSignal+TXFlags+Flags",
		 	dBm_AntSignal = -54, ChannelFlags='2GHz+CCK', Rate=2)
		if self.PSK == False:
			packet = RadioTP/Dot11(addr1=self.rtr,addr2=self.snd,addr3=self.rtr,SC=self.SC)/Dot11AssoReq(
				cap=0x2104, listen_interval=0x0002) / Dot11Elt(
				ID='SSID', info="{}".format(self.SSID))/ Dot11Elt(
				ID='Rates', info=self.ratess)/Dot11Elt(ID=50, info=self.exRates)/Dot11Elt(
				ID=36, len=8, info=self.sChah)/Dot11Elt(ID=45, len=26, info=(
				a2b_hex('721103ff00000001000000000000000100000001000000000000')))/Dot11Elt(
				ID=127,len=1,info=(b'\x00'))/Dot11Elt(ID=221, len=7, info=(a2b_hex('0050f202000100')))
		if self.PSK == True:
			packet = RadioTP/Dot11(addr1=self.rtr,addr2=self.snd,addr3=self.rtr,SC=self.SC)/Dot11AssoReq(
				cap=0x3104, listen_interval=0x0002) / Dot11Elt(
				ID='SSID', info="{}".format(self.SSID))/ Dot11Elt(
				ID='Rates', info=self.ratess)/Dot11Elt(ID=50, info=self.exRates)/Dot11Elt(
				ID=36, len=8, info=self.sChah)/Dot11Elt(ID=45, len=26, info=(
				a2b_hex('721103ff00000001000000000000000100000001000000000000')))/Dot11Elt(
				ID=48, len=20, info=(a2b_hex('0100000fac040100000fac040100000fac020000')))/Dot11Elt(
				ID=127,len=1,info=(b'\x00'))/Dot11Elt(ID=221, len=7, info=(a2b_hex('0050f202000100')))
		sendp(packet, inter=0.001, verbose=False)
		self.Send_ACK()


	def Check_Assoc(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3

		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver:
			self.assoc_found = True
		return self.assoc_found

	def Assoc_resp(self, mp_queue):
		sniff(iface=self.intf, lfilter=lambda x: x.haslayer(Dot11AssoResp),
			stop_filter=self.Check_Assoc, timeout=2)
		mp_queue.put(self.assoc_found)
		mp_queue.put(self.SC)

	def Send_Auth(self):
		auth = False
		jobs = list()
		result_queue = multiprocessing.Queue()
		receive_process = multiprocessing.Process(target=self.Auth_resp, args=(result_queue,))
		jobs.append(receive_process)
		send_process = multiprocessing.Process(target=self.Auth_req)
		jobs.append(send_process)


		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		if result_queue.get():
			print("\033[32m{}\033[0m".format("Authenticated"))
			auth = True
		else:
			print("\033[1m\033[6m\033[31m{}\033[0m".format("Authentication Fail"))
		self.SC = result_queue.get()
		return auth

	def Send_Assoc(self):
		assoc = False
		jobs = list()
		result_queue = multiprocessing.Queue()
		# handshake_proc = multiprocessing.Process(target=self.Handshake)
		# jobs.append(handshake_proc)
		receive_process = multiprocessing.Process(target=self.Assoc_resp, args=(result_queue,))
		jobs.append(receive_process)
		send_process = multiprocessing.Process(target=self.Assoc_req)
		jobs.append(send_process)

		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		if result_queue.get():
			print("\033[32m{}\033[0m".format("Associated"))
			assoc = True
		else:
			print("\033[1m\033[6m\033[31m{}\033[0m".format("Association Fail"))
		self.SC = result_queue.get()
		return assoc

	def Send_ACK(self):
		packet = a2b_hex('000018002e4000a02008000000027109c000ed000000ed00d4000000') + self.apMac
		# print(b2a_hex(bytes(packet)).decode())
		sendp(packet,verbose=False, inter=0.001, iface=self.intf)

	def Send_action(self):
		self.SC = self.SC+48
		packet=RadioTap()/Dot11(type=0,subtype=13,addr1=self.rtr,addr2=self.snd,addr3=self.rtr, SC=self.SC)/Raw(
			a2b_hex("030100000002030000"))
		sendp(packet,verbose=False, inter=0.001, iface=self.intf)

	def Send_Hand2(self):
		HS3 = False
		jobs = list()
		result_queue = multiprocessing.Queue()
		# handshake_proc = multiprocessing.Process(target=self.Handshake)
		# jobs.append(handshake_proc)
		receive_process = multiprocessing.Process(target=self.Handshake_S3, args=(result_queue,))
		jobs.append(receive_process)
		send_process = multiprocessing.Process(target=self.Send_HS2_Full)
		jobs.append(send_process)

		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		if result_queue.get():
			print("\033[32m{}\033[0m".format("Handshake 3 received"))
			HS3 = True
		else:
			print("\033[1m\033[6m\033[31m{}\033[0m".format("Handshake 3 Not Received"))
		return HS3

	def Send_DHCP_DSC(self):
		Offer = False
		jobs = list()
		result_queue = multiprocessing.Queue()
		# handshake_proc = multiprocessing.Process(target=self.Handshake)
		# jobs.append(handshake_proc)
		send_process = multiprocessing.Process(target=self.DHCP_DSC)
		jobs.append(send_process)
		receive_process = multiprocessing.Process(target=self.Offer, args=(result_queue,))
		jobs.append(receive_process)
		act_process = multiprocessing.Process(target=self.Action_r, args=(result_queue,))
		jobs.append(act_process)

		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		g = result_queue.get()

		if isinstance(g, bool):
			if g:
				print("\033[32m{}\033[0m".format("DHCP Offer received"))
				Offer = True
			else:
				print("\033[1m\033[6m\033[31m{}\033[0m".format("DHCP Offer Not Received"))
			self.ipaddr = result_queue.get()
			self.ipaddr_s = result_queue.get()
			self.SC = result_queue.get()
			g = result_queue.get()
			if g == "Yes":
				print("\033[32m{}\033[0m".format("Action received"))
				self.Send_action()
				self.Send_Null()
			elif g == "No":
				Offer = False
				print("\033[1m\033[6m\033[31m{}\033[0m".format("Action Not Received"))
		else:
			if g == "Yes":
				print("\033[32m{}\033[0m".format("Action received"))
				self.Send_action()
				self.Send_Null()
				if result_queue.get():
					print("\033[32m{}\033[0m".format("DHCP Offer received"))
					Offer = True
					self.ipaddr = result_queue.get()
					self.ipaddr_s = result_queue.get()
					self.SC = result_queue.get()
				else:
					print("\033[1m\033[6m\033[31m{}\033[0m".format("DHCP Offer Not Received"))
			elif g == "No":
				Offer = False
				print("\033[1m\033[6m\033[31m{}\033[0m".format("Action Not Received"))

		return Offer

	def Send_DHCP_Req(self):
		ACK = False
		jobs = list()
		result_queue = multiprocessing.Queue()
		# handshake_proc = multiprocessing.Process(target=self.Handshake)
		# jobs.append(handshake_proc)
		receive_process = multiprocessing.Process(target=self.DHCP_ACK, args=(result_queue,))
		jobs.append(receive_process)
		send_process = multiprocessing.Process(target=self.DHCP_Req)
		jobs.append(send_process)

		for job in jobs:
			job.start()
		for job in jobs:
			job.join()

		if result_queue.get():
			print("\033[32m{}\033[0m".format("DHCP ACK received"))
			ACK = True
		else:
			print("\033[1m\033[6m\033[31m{}\033[0m".format("DHCP ACK Not Received"))
		self.SC = result_queue.get()
		return ACK

	def sNonce_gen(self):
		nonce = list()
		for i in range(6):
			nonce.append(RandMAC().replace(":",""))
		sNonce = "".join(nonce)[:-8]
		sNonce = a2b_hex(sNonce)
		return sNonce

	def Send_HS2_Full(self):
		self.Send_HS_2()
		while not self.hs3_found:
			self.Send_HS_2R()


	def Send_HS_2R(self):
		pack = a2b_hex('00001a002f480000f37c113a0000000010027109a000d3000000880a3a01')+self.apMac+self.stMac+self.apMac+a2b_hex(
			'00000600aaaa03000000888e01030075')
		Part1 = a2b_hex('02010a00000000000000000001')
		mic = a2b_hex('00000000000000000000000000000000')
		other_keys = a2b_hex('0000000000000000000000000000000000000000000000000000000000000000')
		_eapol = a2b_hex('01030075')
		sNonce = self.sNonce
		data = a2b_hex('001630140100000fac040100000fac040100000fac020000')

		packet_mic = bytes(Raw(_eapol+Part1+sNonce+other_keys+mic+data))
		mic = a2b_hex(self.MakeMIC(packet_mic))
		data = a2b_hex('001630140100000fac040100000fac040100000fac02000000000000')
		packet = bytes(Raw(pack+Part1+sNonce+other_keys+mic+data))
		# packet.show()
		sendp(packet, inter=0.001, verbose=False)
		self.Send_ACK()
		if self.debug_p:
			print("Handshake 2 sended")
			print("\033[1m\033[36m{}\033[0m".format("MIC 2:") + " " + b2a_hex(mic).decode().upper())
		return

	def Send_HS_2(self):
		pack = a2b_hex('00001a002f480000f37c113a0000000010027109a000d300000088013a01')+self.apMac+self.stMac+self.apMac+a2b_hex(
			'00000600aaaa03000000888e01030075')
		Part1 = a2b_hex('02010a00000000000000000001')
		mic = a2b_hex('00000000000000000000000000000000')
		other_keys = a2b_hex('0000000000000000000000000000000000000000000000000000000000000000')
		_eapol = a2b_hex('01030075')
		sNonce = self.sNonce
		data = a2b_hex('001630140100000fac040100000fac040100000fac020000')

		packet_mic = bytes(Raw(_eapol+Part1+sNonce+other_keys+mic+data))
		mic = a2b_hex(self.MakeMIC(packet_mic))
		data = a2b_hex('001630140100000fac040100000fac040100000fac02000000000000')
		packet = bytes(Raw(pack+Part1+sNonce+other_keys+mic+data))
		# packet.show()
		sendp(packet, inter=0.001, verbose=False)
		self.Send_ACK()
		if self.debug_p:
			print("Handshake 2 sended")
			print("\033[1m\033[36m{}\033[0m".format("MIC 2:") + " " + b2a_hex(mic).decode().upper())
		return

	def Send_HS_4(self):
		Part1 = a2b_hex('02030a00000000000000000002')
		mic = a2b_hex('00000000000000000000000000000000')
		other_keys = a2b_hex('0000000000000000000000000000000000000000000000000000000000000000')
		_eapol = bytes(EAPOL(type=3, len=95))
		sNonce = a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")
		data = a2b_hex('0000')

		packet_mic = _eapol+Part1+sNonce+other_keys+mic+data
		mic = a2b_hex(self.MakeMIC(packet_mic))
		packet = RadioTap()/Dot11(type="Data",subtype=8,addr1=self.rtr,addr2=self.snd,addr3=self.rtr,
			FCfield="to-DS", SC=16)/Dot11QoS()/LLC()/SNAP()/EAPOL(
			type=3, len=95)/Raw(Part1+sNonce+other_keys+mic+data)
		sendp(packet, inter=0.001, verbose=False)
		self.Send_ACK()
		if self.debug_p:
			print("Handshake 4 sended")
			print("\033[1m\033[36m{}\033[0m".format("MIC 4:") + " " + b2a_hex(mic).decode().upper())
		return


	def Handshake_S1(self):
		Handshake_1 = sniff(iface=self.intf, lfilter=lambda x: x.haslayer(EAPOL),
			stop_filter=self.Check_Handshake_1, timeout=3)

		try:
			self.aNonce = Handshake_1[0][Raw].load[13:45]
			self.sNonce = self.sNonce_gen()
			print("\033[32m{}\033[0m".format("Handshake 1 received"))
			if self.hs1_found:
				print("\033[1m\033[36m{}\033[0m".format("aNonce:") + " " + b2a_hex(self.aNonce).decode().upper())
				print("\033[1m\033[36m{}\033[0m".format("sNonce:") + " " + b2a_hex(self.sNonce).decode().upper())
			return self.hs1_found
		except:
			return self.hs1_found

	def Handshake_S3(self, f):
		Handshake_1 = sniff(iface=self.intf, lfilter=lambda x: x.haslayer(EAPOL),
			stop_filter=self.Check_Handshake_3, timeout=5)
		f.put(self.hs3_found)

	def Action_r(self,f):
		self.ff = False
		Action_1 = sniff(iface=self.intf, lfilter=lambda x: x.haslayer(Dot11),
			stop_filter=self.Check_Action, timeout=10)
		f.put(self.action_found)
		return self.action_found

	def Check_Handshake_1(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3

		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver:
			self.hs1_found = True
		self.packet = packet
		return self.hs1_found

	def Check_Handshake_3(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3
		flags = bytes(packet)[63:]
		flags = flags[:2]
		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver and \
					flags == b'\x13\xca':
			self.hs3_found = True
		self.packet = packet
		return self.hs3_found

	def Check_Action(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3
		type_p = packet[Dot11].type
		subtype = packet[Dot11].subtype

		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver and \
					type_p == 0 and \
						subtype == 13:
			self.action_found = "Yes"
			self.ff = True
			print("\033[32m{}\033[0m".format("Action received"))
		self.packet = packet
		return self.ff


	def XID_gen(self):
		xid1 = RandMAC().replace(":","")
		xid1 = xid1[:-4]
		xid = a2b_hex(xid1)
		self.xid = int.from_bytes(xid,"big")
		print("Transaction " + str(self.xid))
		return self.xid


	def DHCP_DSC(self):
		self.SC = self.SC+16
		conf.checkIPaddr = False
		RadioTP = RadioTap(version=0, pad=0, present="TSFT+A_MPDU+Rate+Channel+dBm_AntSignal+TXFlags+Flags",
		 	dBm_AntSignal = -54, ChannelFlags='2GHz+CCK', Rate=2)
		dot = Dot11(type=2,subtype=8,addr3="ff:ff:ff:ff:ff:ff",addr2=self.snd,addr1=self.rtr, FCfield="to-DS", SC=80, ID=44)/Dot11QoS()
		ip = IP(src='0.0.0.0', dst='255.255.255.255',id=0x00,tos=0x10,flags="DF")
		udp = UDP (sport=68, dport=67)
		bootp = BOOTP(op=1, chaddr=self.stMac, xid=self.xid,secs=5)
		dhcp = DHCP(options=[("message-type","discover"),(61,a2b_hex('01')+self.stMac),
			(57,a2b_hex('05dc')),(60,'android-dhcp-6.0'.encode()),(12,'fake_st-'.encode()+self.snd.encode()),
			(55,a2b_hex('0103060f1a1c333a3b')),('end')])
		packet = RadioTP/dot/LLC()/SNAP()/ip/udp/bootp/dhcp
		sendp(packet, inter=0.001, verbose=False)

	def Offer(self,f):
		Off = sniff(iface=self.intf, lfilter=lambda x: x.haslayer(BOOTP),
			stop_filter=self.Check_Offer, timeout=2)
		# self.IPpacket = Off
		self.Send_ACK()
		f.put(self.checkIPaddr)
		f.put(self.ipaddr)
		f.put(self.ipaddr_s)
		f.put(self.SC)
		# return self.checkIPaddr

	def Check_Offer(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3
		mt = packet[DHCP].options[0][1]
		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver and \
					mt == 2:
			self.checkIPaddr = True
			self.ipaddr = packet[BOOTP].yiaddr
			self.ipaddr_s = packet[BOOTP].siaddr
			self.Send_ACK()
		return self.checkIPaddr

	def DHCP_Req(self):
		self.SC = self.SC+16
		self.checkDHCPAck = False
		RadioTP = RadioTap(version=0, pad=0, present="TSFT+A_MPDU+Rate+Channel+dBm_AntSignal+TXFlags+Flags",
		 	dBm_AntSignal = -54, ChannelFlags='2GHz+CCK', Rate=2)
		dot = Dot11(type=2,subtype=8,addr3="ff:ff:ff:ff:ff:ff",addr2=self.snd,addr1=self.rtr, FCfield="to-DS", SC=96)/Dot11QoS()
		ip = IP(src='0.0.0.0', dst='255.255.255.255',id=0x00,tos=0x10,flags="DF")
		udp = UDP (sport=68, dport=67)
		bootp = BOOTP(op=1, chaddr=self.stMac, xid=self.xid,secs=5)
		ipaddr = self.ipaddr.split(".")
		ip_b=b""
		ipaddr_s = self.ipaddr_s.split(".")
		ip_s_b=b""
		for i in ipaddr:
			ip_b=ip_b+bytes([int(i)])
		for i in ipaddr_s:
			ip_s_b=ip_s_b+bytes([int(i)])
		dhcp = DHCP(options=[("message-type","request"),(61,a2b_hex('01')+self.stMac),(50,ip_b),(54,ip_s_b),
		(57,a2b_hex('05dc')),(60,'android-dhcp-6.0'.encode()),(12,'fake_st-'.encode()+self.snd.encode()),
		(55,a2b_hex('0103060f1a1c333a3b')),('end')])
		packet = RadioTP/dot/LLC()/SNAP()/ip/udp/bootp/dhcp
		sendp(packet, inter=0.001, verbose=False)

	def DHCP_ACK(self, f):
		ACK = sniff(iface=self.intf, lfilter=lambda x: x.haslayer(BOOTP),
			stop_filter=self.Check_ACK, timeout=5)
		# self.IPpacket = Off
		self.Send_ACK()
		f.put(self.checkDHCPAck)
		f.put(self.SC)

	def Check_ACK(self, packet):
		seen_receiver = packet[Dot11].addr1
		seen_sender = packet[Dot11].addr2
		seen_bssid = packet[Dot11].addr3
		mt = packet[DHCP].options[0][1]
		if self.rtr == seen_bssid and \
			self.rtr == seen_sender and \
				self.snd == seen_receiver and \
					mt == 5:
			self.checkDHCPAck = True
			self.IPpacket = packet
			self.Send_ACK()
		return self.checkDHCPAck

	def Send_Null(self):
		SC = (self.SC+16).to_bytes(2,byteorder="big")
		SC = SC[1:]+SC[:1]
		packet = a2b_hex('000018002e4000a02008000000027109a000e7000000e70048113a01')+self.apMac+self.stMac+self.apMac+SC
		sendp(packet, inter=0.001, verbose=False)
		SC = (self.SC+32).to_bytes(2,byteorder="big")
		SC = SC[1:]+SC[:1]
		packet = a2b_hex('000018002e4000a02008000000027109a000e6000000e60048013a01')+self.apMac+self.stMac+self.apMac+SC
		sendp(packet, inter=0.001, verbose=False)

	def DNS_query(self):
		pass

	def ARP_Req(self):
		ipaddr = self.ipaddr.split(".")
		ip_b=b""
		ipaddr_s = self.ipaddr_s.split(".")
		ip_s_b=b""
		for i in ipaddr:
			ip_b=ip_b+bytes([int(i)])
		for i in ipaddr_s:
			ip_s_b=ip_s_b+bytes([int(i)])

		RadioTP = RadioTap(version=0, pad=0, present="TSFT+A_MPDU+Rate+Channel+dBm_AntSignal+TXFlags+Flags",
		 	dBm_AntSignal = -54, ChannelFlags='2GHz+CCK', Rate=2)
		dot = Dot11(type=2,subtype=8,addr3=self.rtr,addr2=self.snd,addr1=self.rtr, FCfield="to-DS", SC=112)/Dot11QoS()
		arp_1 = ARP(hwtype=1,ptype=0x0800,hwlen=6,plen=4,op=1,hwsrc=self.stMac,psrc=self.ipaddr,pdst=self.ipaddr_s,hwdst="00:00:00:00:00:00")
		packet=RadioTP/dot/LLC()/SNAP()/arp_1
		sendp(packet, inter=0.001, verbose=False)

def MAC_gen():
	vendors = ['04:92:26', '00:e0:4c', '54:27:58', 'd0:9c:7a', '90:4f:70']
	mac = RandMAC()
	l = mac.split(':')
	lmac = vendors[random.randint(1,len(vendors)-1)] + ":{}:{}:{}".format(l[0], l[1], l[2])
	return lmac



def main():

	interface = "wlp2s0"
	router = "EE:F0:FE:90:a1:54"
	client = "9e:a9:13:ca:75:de"
	SSID = "bubik"
	Password = ""
	max_clients = 2
	PSK = False
	wpa_type = "WPA2" #WPA or WPA2
	debug_p = True


	aNonce = a2b_hex("fe425a3643f6115f9d31609c6739b05aa6a91d22a0f9a7527890061bd1d3e0c9")
	sNonce = a2b_hex("2c469627f2900042226b25030e2203c81c0aa82cb102d5349062605eeef87f4c")
	data = a2b_hex('0103007502010a000000000000000000012c469627f2900042226b25030e2203c81c0aa82cb102d5349062605eeef87f4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000')


	# interface= input('Введите название интерфейса: ')
	# router = input('Введите мак роутреа: ')
	# max_clients = input('Введите количество клиентов: ')

	#os.system('ifconfig %s down && iwconfig %s mode monitor && ifconfig %s up' % (interface, interface, interface))
	# time.sleep(2)

	# router = router.lower()
	# SCP = random.randint(0,65520)
	# SC = SCP-(SCP%16)
	# connection = Generator(client,router,interface,SSID,PSK,SC,Password,wpa_type, debug_p)
	# connected = False
	# while connected==False:
		# connection.XID_gen()
		# if connection.Send_Auth():
			# if connection.Send_Assoc():
				# if PSK == True:
					# if connection.Handshake_S1():
						# connection.Send_Hand2()
						# if connection.Handshake_S3():
							# connection.Send_HS_4()
							# if connection.Action_r():
								# pass
							# else: print("\033[1m\033[6m\033[31m{}\033[0m".format("Action Not Received"))
							# connection.Send_action()
							# connected = True
							# print("\033[32m{}\033[0m".format("CONNECTED!"))
						# else: print("\033[1m\033[6m\033[31m{}\033[0m".format("Handshake 3 Not Received"))
					# else: print("\033[1m\033[6m\033[31m{}\033[0m".format("Handshake 1 Not Received"))
				# else:
					# if connection.Send_DHCP_DSC():
						# if connection.Send_DHCP_Req():
							# connection.ARP_Req()
							# connected = True
							# print("\033[32m{}\033[0m".format("CONNECTED!"))
	# print("#######################################")
	# print("")


	for i in range(max_clients):
		SCP = random.randint(0,65520)
		SC = SCP-(SCP%16)
		client = MAC_gen()
		connection = Generator(client,router,interface,SSID,PSK,SC,Password,wpa_type, debug_p)
		connected = False
		while connected==False:
			connection.XID_gen()
			if connection.Send_Auth():
				connection.Send_ACK()
				if connection.Send_Assoc():
					connection.Send_ACK()
					if PSK == True:
						if connection.Handshake_S1():
							connection.Send_Hand2()
							if connection.Handshake_S3():
								connection.Send_HS_4()
								if connection.Action_r():
									pass
								else: print("\033[1m\033[6m\033[31m{}\033[0m".format("Action Not Received"))
								connection.Send_action()
								connected = True
								print("\033[32m{}\033[0m".format("CONNECTED!"))
							else: print("\033[1m\033[6m\033[31m{}\033[0m".format("Handshake 3 Not Received"))
						else: print("\033[1m\033[6m\033[31m{}\033[0m".format("Handshake 1 Not Received"))
					else:
						if connection.Send_DHCP_DSC():
							if connection.Send_DHCP_Req():
								connected = True
								connection.Send_ACK()
								print("\033[32m{}\033[0m".format("CONNECTED!"))
		print("#######################################")
		print("")

	connection = Generator(client,router,interface,SSID,PSK,SC,Password, wpa_type)
	connection.aNonce = aNonce
	connection.sNonce = sNonce
	
	mic = connection.MakeMIC(data)
	
	print(mic)


if __name__ == "__main__":
	sys.exit(main())
