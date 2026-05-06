#!/usr/bin/env python3

import os
import re
import time
import json
import subprocess
from dataclasses import dataclass
from core.misc import Helpers

class IEEE80211_Hardware:
	IEEE80211_DIR = '/sys/class/ieee80211'

	@staticmethod
	def get_80211_phys() -> list:
		result = []

		if os.path.exists(IEEE80211_Hardware.IEEE80211_DIR):
			phy_list = os.listdir(IEEE80211_Hardware.IEEE80211_DIR)
			for phy in phy_list:
				result.append(phy)
			
			return result

		return result
	
	@staticmethod
	def iface_name(phy: str) -> str:
		path = os.path.join(IEEE80211_Hardware.IEEE80211_DIR, phy, 'device', 'net')
		if os.path.exists(path=path):
			return os.listdir(path=path)[0]
		
		return None
	
	@staticmethod
	def iface_flags(iface: str) -> list:
		result = subprocess.run(['ip', '-j', 'link', 'show', iface], capture_output=True, text=True)

		if result.returncode != 0:
			pass
			#raise Exception(result.stderr.decode())
		else:
			iface_data = json.loads(result.stdout.strip())
			return iface_data[0]['flags']
		
		return None

	@staticmethod
	def iface_get_state(iface: str) -> bool:
		flags = IEEE80211_Hardware.iface_flags(iface=iface)
		if flags:
			return 'UP' in flags
		else:
			return False
	
	@staticmethod
	def iface_set_state(iface: str, state: int):
		states = {
			0: 'down',
			1: 'up'
		}
		state = states.get(state, 'down')
		subprocess.run(['ip', 'link', 'set', iface, state])
	
	@staticmethod
	def phy_iface_get_mode(phy, iface) -> int:
		path = os.path.join(IEEE80211_Hardware.IEEE80211_DIR, phy, 'device', 'net', iface, 'type')
		if os.path.exists(path=path):
			type = int(Helpers.read_file_as_str(path=path))
			return type
		return None
	
	@staticmethod
	def del_iface(iface: str):
		#print(f'[DEL] iface={iface}')
		result = subprocess.run(['iw', 'dev', iface, 'del'])

		if result.returncode != 0:
			pass
			#raise Exception(result.stderr)
	
	@staticmethod
	def add_iface(phy: str, iface: str, mode: str):
		result = subprocess.run(['iw', 'phy', phy, 'interface', 'add', iface, 'type', mode])
		#print(f'[ADD] iface={iface}, mode={mode}')

		if result.returncode != 0:
			pass
			#raise Exception(result.stderr.decode())

	@staticmethod
	def set_phy_iface_mode(phy: str, iface: str, mode: str):
		#print(f'[STATE] iface={iface} ({phy}) DOWN')
		IEEE80211_Hardware.iface_set_state(iface=iface, state=0)
		time.sleep(0.5)

		IEEE80211_Hardware.del_iface(iface=iface)
		time.sleep(0.5)

		IEEE80211_Hardware.add_iface(phy=phy, iface=iface, mode=mode)
		time.sleep(0.5)

		IEEE80211_Hardware.iface_set_state(iface=iface, state=1)
		#print(f'[STATE] iface={iface} ({phy}) UP')

	@staticmethod
	def get_phy_uevent(phy: str, field: str) -> str:
		path = os.path.join(IEEE80211_Hardware.IEEE80211_DIR, phy, 'device', 'uevent')
		if os.path.exists(path=path):
			uevent = Helpers.read_file_as_str(path=path, splitlines=True)
			for line in uevent:
				param, val = tuple(line.split('='))
				if param == field:
					return val
		return None


	@staticmethod
	def get_phy_driver(phy: str) -> str:
		return IEEE80211_Hardware.get_phy_uevent(phy=phy, field='DRIVER')
	
	@staticmethod
	def get_phy_chipset(phy: str) -> str:
		def clean_name(bus_addr: str, name: str) -> str:
			chipset = re.sub(bus_addr, '', name)
			chipset = re.sub(r'(^.*?: )', '', chipset)
			chipset = re.sub(r'\(PCI-Express\) ', '', chipset)
			chipset = chipset.replace('Wireless Adapter', '')
			chipset = chipset.replace('Wireless Network Adapter', '')
			chipset = chipset.replace('Network controller', '')
			chipset = chipset.replace('Wireless Network Controller', '')

			return chipset
		
		modalias = IEEE80211_Hardware.get_phy_uevent(phy=phy, field='MODALIAS')
		if modalias:
			bus = modalias[:3]
			if bus == 'pci':
				pci_bus_addr = IEEE80211_Hardware.get_phy_uevent(phy=phy, field='PCI_SLOT_NAME')
				if re.match(r'^\d+:', pci_bus_addr):
					pci_bus_addr = re.sub(r'^\d+:', '', pci_bus_addr)
					lspci = subprocess.run(['lspci'], capture_output=True, text=True)

					if lspci.returncode == 0:
						lspci = lspci.stdout.splitlines()
						for pcidev in lspci:
							if pcidev.startswith(pci_bus_addr):
								return clean_name(pci_bus_addr, pcidev)
							
			if bus == 'usb':
				vid = modalias[5:9].lower()
				pid = modalias[10:14].lower()
				lsusb = subprocess.run(['lsusb'], capture_output=True, text=True)

				if lsusb.returncode == 0:
					lsusb = lsusb.stdout.splitlines()
					for usbdev in lsusb:
						match = re.search(fr'ID {vid}:{pid} (.+)', usbdev)
						if match:
							chipset = match.group(1).replace('Wireless Adapter', '').strip()
							return chipset
		return None
	
	def get_iface_mac(iface: str) -> str:
		return Helpers.read_file_as_str(f"/sys/class/net/{iface}/address")
	
	def get_phy_mac(phy: str) -> str:
		return Helpers.read_file_as_str(f"/sys/class/ieee80211/{phy}/macaddress")
	
	@staticmethod
	def switch_iface_channel(iface: str, channel: int):
		result = subprocess.run(['iw', 'dev', iface, 'set', 'channel', str(channel)], capture_output=True, text=True)
		if result.returncode != 0:
			print(result.stderr)


	@staticmethod
	def get_phy_channels(phy: str) -> list:
		result = []
		iw = subprocess.run(['iw', 'phy', phy, 'channels'], capture_output=True, text=True)

		if iw.returncode == 0:
			iw = iw.stdout.splitlines()
			for iwline in iw:
				match = re.search(r'\* \d{4}\sMHz\s\[(\d+)\]', iwline)
				if match:
					channel = int(match.group(1))
					if 'disabled' in iwline or 'No IR' in iwline:
						continue
					result.append(channel)
		
		return result