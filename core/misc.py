import os
import re
import csv
import struct
import subprocess
import time
import json

from core.defs import PHYMode, iface_types

class Helpers:

	@staticmethod
	def read_file_as_str(path: str, splitlines=False):
		if os.path.exists(path=path):
			with open(path, 'r') as file:
				if splitlines:
					return file.read().splitlines()
				else:
					return file.read().strip()

		return None
	
class IEEE80211_Utils:

	VENDORS_OUI = {
		"00:10:18": "Broadcom", # Broadcom
		"00:03:7f": "AtherosC", # Atheros Communications
		"00:13:74": "AtherosC", # Atheros Communications
		"00:0c:43": "RalinkTe", # Ralink Technology, Corp.
		"00:17:a5": "RalinkTe", # Ralink Technology, Corp.
		"00:e0:4c": "RealtekS", # Realtek Semiconductor Corp.
		"00:a0:00": "Mediatek", # Mediatek Corp.
		"00:0c:e7": "Mediatek", # Mediatek Corp.
		"00:1c:51": "CelenoCo", # Celeno Communications
		"00:50:43": "MarvellS", # Marvell Semiconductor
		"00:26:86": "Quantenn", # Quantenna Communications
		"00:09:86": "LantiqML", # Lantiq Microsystems
		"ac:85:3d": "HuaweiTe", # Huawei Technologies Co., Ltd.
		"00:e0:fc": "HuaweiTe", # Huawei Technologies Co., Ltd.
		"88:12:4e": "Qualcomm", # Qualcomm Atheros, Inc.
		"8c:fd:f0": "Qualcomm", # Qualcomm Atheros, Inc.
		"00:a0:cc": "Lite-OnC", # Lite-On Communications Inc.
		"40:45:da": "SpreadTe", # Spreadtrum Communications Inc.
		"18:fe:34": "Espressi", # Espressif Inc.
		"50:ff:20": "Keenetic", # Keenetic International Ltd.
		"00:0f:66": "AzureWav", # AzureWave Technology Inc.
		"00:0e:2e": "AzureWav", # AzureWave Technology Inc.
		"00:0e:2f": "AzureWav", # AzureWave Technology Inc.
		"00:0e:2d": "AzureWav", # AzureWave Technology Inc.
		"00:0e:2c": "AzureWav", # AzureWave Technology Inc.
		"00:1d:0f": "Tp-LinkT", # Tp-Link Technologies Co., Ltd.
		"00:90:4c": "EpigramI", # Epigram, Inc.
		"00:0c:42": "RouterBo", # RouterBOARD.com
		"00:16:32": "SamsungE", # Samsung Electronics Co., Ltd.
		"8c:be:be": "XiaomiCo", # Xiaomi Communications Co Ltd
		"f8:32:e4": "ASUSTekC", # ASUSTek COMPUTER INC.
		"00:31:92": "Tp-LinkS", # TP-Link Systems Inc
	}

	@staticmethod
	def get_ap_ssid(elt) -> str:
		for ie in elt:
			if ie.tag_type.id == 0:
				return ie.info
		
		return None
	
	@staticmethod
	def get_ap_channel(elt) -> int:
		for ie in elt:
			if ie.tag_type.id == 3:
				return ie.info
			
		return None

	@staticmethod
	def get_ap_vendor(elt):
		result = []

		for ie in elt:
			if ie.tag_type.id == 221:
				if not hasattr(ie.info, 'oui'):
					return ['Unknown']

				for vendor_oui in IEEE80211_Utils.VENDORS_OUI:
					vendor = IEEE80211_Utils.VENDORS_OUI[vendor_oui]
					if ie.info.oui == vendor_oui and vendor not in result:
						result.append(vendor)

		return list(result) if result else ['Unknown']
	
	@staticmethod
	def get_encryption_info(elt, fixed):
		enc = {'type': [], 'ciphers': [], 'akm': []}
		for ie in elt:
			# WPA
			if ie.tag_type.id == 221:
				if hasattr(ie.info, 'oui') and ie.info.oui == '00:50:f2' and ie.info.type == 1:
					enc['type'].append('WPA')
					enc['ciphers'].extend([u.type.name for u in ie.info.info.unicast_suites if u.type.name not in enc['ciphers']])
					enc['akm'].extend([a.type.name for a in ie.info.info.akm_suites if a.type.name not in enc['akm']])
			# WPA2/3
			if ie.tag_type.id == 48:
				if ie.info:
					enc['type'].append('WPA2')
					enc['ciphers'].extend([p.type.name for p in ie.info.pair_suites if p.type.name not in enc['ciphers']])
					enc['akm'].extend([a.type.name for a in ie.info.akm_suites if a.type.name not in enc['akm']])
					if 'SAE' in enc['akm']:
						enc['type'].append('WPA3')

		if not enc['type']:
			enc['type'] = ['WEP'] if 'privacy' in fixed.capabilities else ['OPEN']
		return enc

	@staticmethod
	def get_wps_info(elt):
		wps = False
		wps_version = None
		wps_locked = None
		
		for ie in elt:
			if ie.tag_type.id == 221 and hasattr(ie.info, 'oui'):
				if ie.info.oui == '00:50:f2' and ie.info.type == 4:
					wps = True
					wps_locked = False
					wps_info = ie.info.info
						
					for wps_field in wps_info:
						if wps_field.tag_type.id == 0x104a:
							wps_version = 1
						if wps_field.tag_type.id == 0x1057 and wps_field.info == 0x01:
							wps_locked = True
						if wps_field.tag_type.id == 0x1049:
							if wps_field.info.endswith(b'\x00\x01\x20'):
								wps_version = 2
		
		return {
			'enabled': wps,
			'version': wps_version,
			'locked': wps_locked
		}
	
	@staticmethod
	def handle_client(Dot11):
		# Я ЕБАЛ БЛЯТЬ! ТУТ ВСЕ СЛОЖНО! НО Я ЭТО СДЕЛАЛ!!!!
		ap_addr = None
		sta_addr = None
		if Dot11.fc.type_subtype in [0x08, 0x88]: # Data, QoS Data
			is_multicast = int(Dot11.addrs.addr1.split(':')[0], 16) & 1
			if not is_multicast and not 'MoreData' in Dot11.fc.flags:
				if 'from_ds' in Dot11.fc.flags: # Роутер -> Станция
					#is_direct = (dot11frame.addr2 == dot11frame.addr3) - без этого можно видеть связи router > ap > client
					# мб позже сделаю
					is_direct = Dot11.addrs.addr1 != 'ff:ff:ff:ff:ff:ff' # Исключаем широковещательные
					is_direct = Dot11.addrs.addr1[:8] != '01:00:5e' and is_direct # Исключаем IPv4 multicast
					is_direct = Dot11.addrs.addr1[:8] != '33:33:00' and is_direct # Исключаем IPv6 multicast
					ap_addr = Dot11.addrs.addr2 or Dot11.addrs.addr3
					sta_addr = Dot11.addrs.addr1

				elif 'to_ds' in Dot11.fc.flags: # Станция -> Роутер
					#is_direct = (dot11frame.addr1 == dot11frame.addr3)
					is_direct = Dot11.addrs.addr3 != 'ff:ff:ff:ff:ff:ff'# and is_direct # Исключаем широковещательные
					ap_addr = Dot11.addrs.addr1 or Dot11.addrs.addr3
					sta_addr = Dot11.addrs.addr2

				if ap_addr and sta_addr:
					return {
						'ap_addr': ap_addr, 
						'sta_addr': sta_addr
					}
		return None	


class VendorOUI:
	def __init__(self):
		self.ouiDB = {}
		self.ouiCSV_Data = None
		self.load_oui_csv()

	def load_oui_csv(self):
		with open('resources/csv/mac-vendors-export.csv', newline='', encoding='utf-8') as csvfile:
			reader = csv.reader(csvfile)
			for row in reader:
				if len(row) >= 3:
					oui = row[0].upper()
					vendor = row[1].strip()
					self.ouiDB[oui] = vendor

	def get_vendor_oui_name(self, oui):
		mac_prefix = oui.upper()[:8]#.replace(":", "").replace("-", "").replace(".", "")[:6]
		return self.ouiDB.get(mac_prefix, "Unknown")
	
	def get_oui_name_mixed(self, oui):
		if oui:
			oui = oui.strip()
			if len(oui) < 11:
				return oui.upper()
			vendor = self.get_vendor_oui_name(oui)
			if vendor != 'Unknown':
				vendor_cleaned = re.sub(r'[ ,.""]', '', vendor)
				return f"{vendor_cleaned[:8]}_{oui[9:].upper()}"
			else:
				return oui.upper()
		else:
			return
		
	def get_short_vendor_oui_name_short(self, oui):
		if oui:
			oui = oui.strip()
			if len(oui) < 8:
				return oui.upper()
			
			vendor = self.get_vendor_oui_name(oui)
			if vendor != 'Unknown':
				return re.sub(r'[ ,.""]', '', vendor)[:8]
			else:
				return oui.upper()
		
		return

class PCAPWritter:
	def __init__(self, filename):
		self.pcap_file = open(filename, 'wb')
		header = struct.pack('<4s4s4s4s4s4s',
			b'\xD4\xC3\xB2\xA1', # A fcuked magic number (pcap format, little endian)
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

class Settings:
	def __init__(self, filename="resources/json/settings.json"):
		self.filename = filename
		self.data = self._load()

	def _load(self):
		if os.path.exists(self.filename):
			with open(self.filename, 'r', encoding='utf-8') as f:
				return json.load(f)
		return {}
	
	def save(self):
		with open(self.filename, 'w', encoding='utf-8') as f:
			json.dump(self.data, f, indent=4)
		
	def get(self, key, default):
		return self.data.get(key, default)

	def set(self, key, value):
		self.data[key] = value
		self.save()

class Translations:
	def __init__(self, lang="EN"):
		self.filename = f"resources/json/{lang}.json"
		self.translations = self._load(self.filename)

	def _load(self, filename):
		with open(self.filename, 'r', encoding='utf-8') as f:
			return json.load(f)
	
	def gettext(self, key, **kwargs):
		template = self.translations.get(key, key)

		try:
			return template.format(**kwargs)
		except KeyError:
			return template
		
	def getlist(self, key):
		return self.translations.get(key, [])