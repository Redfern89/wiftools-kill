import subprocess
import struct
import time
import csv
import os
import re

class WiFiHelper:
	def __init__(self):
		self.vendors_oui = { 
			"00:10:18": "Broadcom",  # Broadcom
			"00:03:7f": "AtherosC",  # Atheros Communications
			"00:13:74": "AtherosC",  # Atheros Communications
			"00:0c:43": "RalinkTe",  # Ralink Technology, Corp.
			"00:17:a5": "RalinkTe",  # Ralink Technology, Corp.
			"00:e0:4c": "RealtekS",  # Realtek Semiconductor Corp.
			"00:a0:00": "Mediatek",  # Mediatek Corp.
			"00:0c:e7": "Mediatek",  # Mediatek Corp.
			"00:1c:51": "CelenoCo",  # Celeno Communications, Inc
			"00:50:43": "MarvellS",  # Marvell Semiconductor, Inc.
			"00:26:86": "Quantenn",  # Quantenna Communications, Inc
			"00:09:86": "LantiqML",  # Lantiq/MetaLink
			"ac:85:3d": "HuaweiTe",  # Huawei Technologies Co., Ltd
			"00:e0:fc": "HuaweiTe",  # Huawei Technologies Co., Ltd
			"88:12:4e": "Qualcomm",  # Qualcomm Atheros
			"8c:fd:f0": "Qualcomm",  # Qualcomm, Inc
			"00:a0:cc": "Lite-OnC",  # Lite-On Communications, Inc
			"40:45:da": "SpreadTe",  # Spreadtrum Technology, Inc
			"18:fe:34": "Espressi",  # Espressif Inc.
			"50:ff:20": "Keenetic",  # Keenetic limited
			"00:0f:66": "AzureWav",  # AzureWave Technology Inc.
			"00:0e:2e": "AzureWav",  # AzureWave Technology Inc.
			"00:0e:2f": "AzureWav",  # AzureWave Technology Inc.
			"00:0e:2d": "AzureWav",  # AzureWave Technology Inc.
			"00:0e:2c": "AzureWav",  # AzureWave Technology Inc.
		}

	def get_ap_ssid(self, wifi_pkt):
		elt = wifi_pkt.return_Dot11Elt()
		if elt:
			for e in elt:
				if e.ID == 0:
					res = e.INFO
					if isinstance(res, bytes):
						res = res.decode('utf-8', errors='ignore')
					return res if res else "<Hidden>"
		return "<Unknown>"
	
	def get_ap_channel(self, wifi_pkt):
		elt = wifi_pkt.return_Dot11Elt()
		if elt:
			for e in elt:
				if e.ID == 3:
					return e.INFO.channel
					
		return None

	def get_ap_vendor(self, wifi_pkt):
		elt = wifi_pkt.return_Dot11Elt()
		if elt:
			for e in elt:
				if e.ID == 221:
					for ven in self.vendors_oui:
						if e.INFO.oui == ven:
							vendor = self.vendors_oui.get(ven, "Unknown")
							return vendor
		return "Unknown"
	

	def return_ap_encryptions(self, beacon, elt):
		enc_type = []
		unicast_pair_suites = []
		akm_suites = []

		# 1. Сначала собираем современные типы (WPA/WPA2/WPA3)
		if elt:
			for e in elt:
				# WPA2 / WPA3 (RSN)
				if e.ID == 48:
					enc_type.append('WPA2')
					for s in e.INFO.pair_suites: unicast_pair_suites.append(s.name)
					for s in e.INFO.akm_suites: akm_suites.append(s.name)
					if 'SAE' in akm_suites: enc_type.append('WPA3')

				# WPA (Old school)
				elif e.ID == 221 and hasattr(e.INFO, 'name') and e.INFO.name == 'WPA':
					enc_type.append('WPA')
					if hasattr(e.INFO.data, 'unicast_suites'):
						for s in e.INFO.data.unicast_suites: unicast_pair_suites.append(s.name)
					if hasattr(e.INFO.data, 'akm_suites'):
						for s in e.INFO.data.akm_suites: akm_suites.append(s.name)

		# Убираем дубликаты из списков (set -> list)
		enc_type = list(set(enc_type))
		unicast_pair_suites = list(set(unicast_pair_suites))
		akm_suites = list(set(akm_suites))

		# 2. Если ничего современного не нашли — смотрим Capabilities
		if not enc_type:
			capabilities = beacon.get('capabilities', {})
			# Если есть Privacy — это WEP, иначе OPEN
			if 'Privacy' in capabilities.values():
				enc_type = ['WEP']
			else:
				enc_type = ['OPEN']

		return enc_type, unicast_pair_suites, akm_suites


class VendorOUI:
	def __init__(self):
		self.ouiDB = {}
		self.ouiCSV_Data = None
		self.load_oui_csv()

	def load_oui_csv(self):
		with open('mac-vendors-export.csv', newline='', encoding='utf-8') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				if len(row) >= 3:
					oui = row[0].upper()
					vendor = row[1].strip()
					self.ouiDB[oui] = vendor

	def get_mac_vendor(self, mac):
		mac_prefix = mac.upper()[:8]#.replace(":", "").replace("-", "").replace(".", "")[:6]
		return self.ouiDB.get(mac_prefix, "Unknown")
	
	def get_mac_vendor_mixed(self, mac):
		if mac:
			vendor = self.get_mac_vendor(mac)
			if vendor != 'Unknown':
				vendor_cleaned = re.sub(r'[ ,.""]', '', vendor)
				return f"{vendor_cleaned[:8]}_{mac[9:].upper()}"
			else:
				return mac.upper()
		else:
			return
		

class WiFiPhyManager:
	def __init__(self):
		self.iface_types = {
			0: 'Unknown',
			1: 'Station',
			802: 'Ad-Hoc',
			803: 'Monitor',
			804: 'Mesh (802.11s)',
			805: 'P2P (Direct GO)',
			806: 'P2P Client'
		}

		self.iface_states = {
			0: 'DOWN',
			1: 'UP'
		}

	def handle_lost_phys(self):
		devices = {}
		if os.path.exists('/sys/class/ieee80211'):
			phys = os.listdir('/sys/class/ieee80211')
			for phydev in phys:
				devices[phydev] = {
					'phydev': phydev,
					'interface': self.iface_name_by_phy(phydev),
					'mac': self.get_phy_mac(phydev),
					'driver': self.get_phy_driver(phydev),
					'chipset': self.get_phy_chipset(phydev),
					'state': self.get_phy_state(phydev),
					'mode': self.get_phy_mode(phydev),
					'channels': self.get_phy_supported_channels(phydev),
				}

		return devices

	def iface_exists(self, iface):
		return os.path.exists(f"/sys/class/net/{iface}")

	def iface_name_by_phy(self, phy):
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net"):
			dir_list = os.listdir(f"/sys/class/ieee80211/{phy}/device/net")
			uevent_path = f"/sys/class/ieee80211/{phy}/device/net/{dir_list[0]}/uevent"
			if os.path.exists(uevent_path):
				with open(uevent_path, "r") as uevent:
					data = dict(line.strip().split('=') for line in uevent if "=" in line)
					return data.get('INTERFACE')
		return None

	def get_phy_state(self, phy):
		iface = self.iface_name_by_phy(phy)
		iface_data = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
		return 'UP' in iface_data.stdout

	def get_iface_state(self, iface):
		iface_data = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
		return 'UP' in iface_data.stdout


	def set_phy_link(self, phy, state):
		iface = self.iface_name_by_phy(phy)

		if state in ['up', 'down']:
			subprocess.run(['ip', 'link', 'set', iface, state])

	def get_phy_driver(self, phy):
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/uevent"):
			with open(f"/sys/class/ieee80211/{phy}/device/uevent", "r") as uevent:
				data = dict(line.strip().split('=') for line in uevent if "=" in line)
				return data.get('DRIVER')
		return None

	def get_phy_chipset(self, phy):
		iface = self.iface_name_by_phy(phy)
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/modalias"):
			modalias = open(f"/sys/class/ieee80211/{phy}/device/modalias", "r").read()			
			bus = modalias[:3] # шина

			if bus == 'pci':
				businfo = subprocess.run(['ethtool', '-i', iface], capture_output=True, text=True)
				for line in businfo.stdout.splitlines():
					match = re.search('bus-info: [0-9]{4}:(.+)', line) 
					if match:
						bus_id = match.group(1)
						if bus_id:
							lspci = subprocess.run(['lspci'], capture_output=True, text=True)
							for pcidev in lspci.stdout.splitlines():
								found_busid = pcidev[:7]
								if found_busid == bus_id:
									match = re.search(fr'{bus_id} .+: (.+)', pcidev)
									if match:
										chipset = match.group(1).replace('Wireless Adapter', '').strip()
										chipset = match.group(1).replace('Wireless Network Adapter', '').strip()
										return chipset

			if bus == 'usb':
				match = re.search(fr'{bus}:v([0-9A-Fa-f]{{4}})p([0-9A-Fa-f]{{4}})', modalias)
				if match:
					vid = match.group(1)
					pid = match.group(2)
					vid_pid = f"{vid}:{pid}".lower()
					lsusb = subprocess.run(['lsusb'], capture_output=True, text=True)
					for line in lsusb.stdout.splitlines():
						match = re.search(fr'ID {vid_pid} (.+)', line)
						if match:
							chipset = match.group(1).replace('Wireless Adapter', '').strip()
							return chipset

		return None

	def get_phy_mode(self, phy):
		iface = self.iface_name_by_phy(phy)
		if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net/{iface}/type"):
			iface_type = int(open(f"/sys/class/ieee80211/{phy}/device/net/{iface}/type", "r").read().strip())
			return int(iface_type)		
		return 0

	def set_phy_80211_monitor(self, phy):
		if self.get_phy_mode(phy) != 803:
			iface = self.iface_name_by_phy(phy)
			self.set_phy_link(phy, 'down')
			time.sleep(1)
			if self.get_phy_state(phy) == False:
				iface_index = 0
				mon_iface = f"radio{iface_index}mon"

				while self.iface_exists(mon_iface):
					mon_iface = f"radio{iface_index}mon"
					iface_index += 1

				subprocess.run(['iw', 'phy', phy, 'interface', 'add', mon_iface, 'type', 'monitor'], capture_output=True, text=True)
				subprocess.run(['iw', 'dev', iface, 'del'], capture_output=True, text=True)
				time.sleep(1)
				
				if self.get_phy_mode(phy) == 803:
					self.set_phy_link(phy, 'up')
				else:
					subprocess.run(['iw', 'dev', mon_iface, 'del'], capture_output=True, text=True)
		
	def set_phy_80211_station(self, phy):
		if self.get_phy_mode(phy) == 803:
			iface = self.iface_name_by_phy(phy)
			self.set_phy_link(phy, 'down')
			if self.get_phy_state(phy) == False:
				station_iface = iface[:-3]
				subprocess.run(['iw', 'phy', phy, 'interface', 'add', station_iface, 'type', 'station'], capture_output=True, text=True)
				time.sleep(1)
				if os.path.exists(f"/sys/class/ieee80211/{phy}/device/net"):
					for phy_iface in os.listdir(f"/sys/class/ieee80211/{phy}/device/net"):
						mac_80211_type_path = f"/sys/class/ieee80211/{phy}/device/net/{phy_iface}/type"
						if os.path.exists(mac_80211_type_path):
							mac_80211_type = int(open(mac_80211_type_path, "r").read().strip())
							if mac_80211_type == 1:
								time.sleep(1)
								subprocess.run(['iw', 'dev', iface, 'del'], capture_output=True, text=True)

	def get_phy_mac(self, phy):
		if os.path.exists(f"/sys/class/ieee80211/{phy}/macaddress"):
			return open(f"/sys/class/ieee80211/{phy}/macaddress", "r").read().strip()
		return 'Unknown'

	def switch_iface_channel(self, interface, ch):
		result = subprocess.run(["iwconfig", interface, "channel", str(ch)], capture_output=True, text=True)

	def get_phy_supported_channels(self, phydev):
		channels = []
		channels_data = subprocess.run(['iw', 'phy', phydev, 'channels'], capture_output=True, text=True).stdout
		channels_data = channels_data.split('* ')[1:]
		for channel_data in channels_data:
			match = re.search(r'(\d+) MHz \[(\d+)\]', channel_data)
			if match:
				if not 'No IR' in channel_data:
					channels.append(match.group(2))
		return channels
	

class PCAPWritter:
	def __init__(self, filename):
		self.pcap_file = open(filename, 'wb')
		header = struct.pack('<4s4s4s4s4s4s',
			b'\xD4\xC3\xB2\xA1', # Magic number (pcap format, little endian)
			b'\x02\x00\x04\x00', # Versions
			b'\x00\x00\x00\x00', # TZ
			b'\x00\x00\x00\x00', # Sigfigs
			b'\xFF\xFF\x00\x00', # Snaplen (65535)
			b'\x7F\x00\x00\x00'  # Network (127)
		)
		self.pcap_file.write(header)

	def writePacket(self, pkt):
		ts       = time.time()
		sec      = int(ts)
		usec     = int((ts - sec) * 1000000)
		caplen   = len(pkt)
		writelen = len(pkt)

		pkt_header = struct.pack('<IIII', sec, usec, caplen, writelen)
		self.pcap_file.write(pkt_header)
		self.pcap_file.write(pkt)
	
	def write(self, packets: list, is_async: bool = False):
		for pkt in packets:
			self.writePacket(pkt)
		
		if is_async:
			self.flush()

	def flush(self):
		self.pcap_file.flush()

	def close(self):
		self.pcap_file.close()