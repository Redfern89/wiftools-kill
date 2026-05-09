import time
import threading
import queue
from core.ieee80211 import RadioTap, Dot11_Layer, Dot11PacketBuilder
from core.misc import IEEE80211_Utils
from core.ieee80211_hardware import IEEE80211_Hardware
from core.callback import Callback
from functools import wraps

class PacketController(Callback):
	def __init__(self):
		self.access_points = {}
		self.access_points_cnt = 0
		self.sta_cnt = 0
		
		self.on_ap_found = None
		self.on_ap_update = None
		self.on_sta_found = None
		self.on_sta_update = None
		self.on_counts_update = None

		self.on_ap_found_bssid = None
		self.on_sta_found_addr = None

	def process_packets(self, raw, ts):
		RadioTap_PKT = RadioTap(raw)
		Dot11 = Dot11_Layer(radiotap=RadioTap_PKT, pkt=raw)
		dBm_AntSignal = RadioTap_PKT.get('dBm_AntSignal')
		channel = RadioTap_PKT.get('Channel')
		mcs = RadioTap_PKT.get('MCS')
		rate = RadioTap_PKT.get('Rate')

		if rate is None:
			rate = 0

		client = IEEE80211_Utils.handle_client(Dot11)
		if client:
			ap_addr = client['ap_addr']
			sta_addr = client['sta_addr']
			if 'clients' in self.access_points.get(ap_addr, {}):
				sta = {
					'addrs': {
						'ap_addr': ap_addr,
						'client_addr': sta_addr
					},
					'rate': rate,
					'rssi': dBm_AntSignal,
					'mcs': mcs,
					'channel': channel,
					'frames': 1
				}
				if sta_addr not in self.access_points[ap_addr]['clients']:
					self.sta_cnt += 1
					if self.on_counts_update:
						self.on_counts_update(self.access_points_cnt, self.sta_cnt)

					self.access_points[ap_addr]['clients'][sta_addr] = sta
					if self.on_counts_update:
						self.on_counts_update(self.access_points_cnt, self.sta_cnt)
						
					if self.on_sta_found:
						self.on_sta_found(ap_addr, sta_addr, sta)
						#self.on_sta_found_addr(ap_addr, sta_addr)
					
					if self.on_sta_found_addr:
						pass
						#print(f'[CONTROLLER STA_ADDR] AP={ap_addr}, STA={sta_addr}')
						self.on_sta_found_addr(ap_addr, sta_addr)
				else:
					self.access_points[ap_addr]['clients'][sta_addr]['frames'] += 1
					self.access_points[ap_addr]['clients'][sta_addr]['rssi'] = dBm_AntSignal
					self.access_points[ap_addr]['clients'][sta_addr]['channel'] = channel
					self.access_points[ap_addr]['clients'][sta_addr]['mcs'] = mcs

					if self.on_sta_update:
						self.on_sta_update(ap_addr, sta_addr, self.access_points[ap_addr]['clients'][sta_addr])

		if Dot11.fc.type_subtype == 0x80: # Beacon
			elt = Dot11.Dot11Elt()
			fixedParams = Dot11.Dot11FixedParams12b()

			ssid = IEEE80211_Utils.get_ap_ssid(elt)
			vendors = IEEE80211_Utils.get_ap_vendor(elt)
			encryption = IEEE80211_Utils.get_encryption_info(elt, fixedParams)
			wps = IEEE80211_Utils.get_wps_info(elt)
			beacon_ch = IEEE80211_Utils.get_ap_channel(elt)
			
			if beacon_ch:
				ch = str(beacon_ch)
			else:
				ch = channel.channel

			ap = {
				'bssid': Dot11.addrs.addr3,
				'ssid': ssid,
				'rssi': dBm_AntSignal,
				'channel_data': {
					'freq': channel.freq,
					'ch': ch,
					'flags': channel.flags
				},
				'encryption': encryption,
				'wps': wps,
				'vendors': vendors,
				'beacons': 1,
				'clients': {}
			}

			if Dot11.addrs.addr3 not in self.access_points:
				self.access_points_cnt += 1

				if self.on_counts_update:
					self.on_counts_update(self.access_points_cnt, self.sta_cnt)

				self.access_points[Dot11.addrs.addr3] = ap
				if self.on_ap_found:
					self.on_ap_found(ap)

				if self.on_ap_found_bssid:
					self.on_ap_found_bssid(Dot11.addrs.addr3)
			else:
				self.access_points[Dot11.addrs.addr3]['beacons'] += 1

				temp_ap = ap.copy()
				temp_ap.pop('clients', None)
				temp_ap.pop('beacons', None)

				self.access_points[Dot11.addrs.addr3].update(temp_ap)
				if self.on_ap_update:
					self.on_ap_update(Dot11.addrs.addr3, self.access_points[Dot11.addrs.addr3])

class TargetPacketController(Callback):
	def __init__(self, bssid=None, interface=None, channel=None):
		self.beacon = None
		self.first_beacon_flag = False
		self.on_first_beacon = None
		self.on_target_ap_update = None
		self.on_sta_found = None
		self.on_sta_update = None
		self.on_sta_probe_req = None
		self.on_eapol_received = None
		self.on_eapol_done = None
		self.on_eapol_data_done = None
		self.on_eapol_error = None

		self.on_sta_found_addr = None

		self.stations = {}

		self.beacons = 0
		self.beacons_lost = 0
		self.ssid = None
		self.bssid = bssid
		self.vendors = None
		self.last_seq = 0

		self.eapol_map = {
			0x0088: ('M1', 'addr1', 'addr2'),
			0x0108: ('M2', 'addr2', 'addr1'),
			0x13c8: ('M3', 'addr1', 'addr2'),
			0x0308: ('M4', 'addr2', 'addr1')
		}

		IEEE80211_Hardware.switch_iface_channel(iface=interface, channel=channel)

	def add_sta_flag(self, sta_mac: str, flag: str):
		if sta_mac in self.stations:
			if not flag in self.stations[sta_mac]['flags']:
				self.stations[sta_mac]['flags'].append(flag)
	
	def del_sta_flag(self, sta_mac: str, flag: str):
		if sta_mac in self.stations:
			if flag in self.stations:
				self.stations[sta_mac]['flags'].remove(flag)

	def process_packets(self, raw, ts):
		RadioTap_PKT = RadioTap(raw)
		Dot11 = Dot11_Layer(radiotap=RadioTap_PKT, pkt=raw)
		dBm_AntSignal = RadioTap_PKT.get('dBm_AntSignal')
		channel = RadioTap_PKT.get('Channel')
		mcs = RadioTap_PKT.get('MCS')
		rate = RadioTap_PKT.get('Rate')

		if Dot11.fc.type_subtype == 0x40: # Probe request
			elt = Dot11.Dot11Elt()
			ssid = IEEE80211_Utils.get_ap_ssid(elt)
				
			if ssid == '':
				ssid = '<hidden>'
				
			if Dot11.addrs.addr2 in self.stations:
				if ssid not in self.stations[Dot11.addrs.addr2]['probes']:
					self.stations[Dot11.addrs.addr2]['probes'].append(ssid)

				if self.on_sta_update:
					self.on_sta_update(Dot11.addrs.addr2, self.stations[Dot11.addrs.addr2])
				
				if self.on_sta_probe_req:
					self.on_sta_probe_req(Dot11.addrs.addr2, ssid)

		if Dot11.fc.type_subtype == 0xD4: # Acknowledgement
			if Dot11.addrs.addr1 in self.stations:
				self.stations[Dot11.addrs.addr1]['counters']['acks'] += 1
					
				if self.on_sta_update:
					self.on_sta_update(Dot11.addrs.addr1, self.stations[Dot11.addrs.addr1])

		if Dot11.fc.type_subtype == 0x94: # Block ACK req
			if Dot11.addrs.addr1 in self.stations:
				self.stations[Dot11.addrs.addr1]['counters']['blocks'] += 1

				if self.on_sta_update:
					self.on_sta_update(Dot11.addrs.addr1, self.stations[Dot11.addrs.addr1])

		client = IEEE80211_Utils.handle_client(Dot11)
		if client:
			ap_addr = client['ap_addr']
			sta_addr = client['sta_addr']
			if ap_addr and sta_addr:
				if ap_addr == self.bssid:
					if sta_addr not in self.stations:
						sta = {
							'sta_mac': sta_addr,
							'rssi': dBm_AntSignal,
							'channel': channel,
							'rate': rate,
							'mcs': mcs,
							'counters': {
								'frames': 1,
								'acks': 0,
								'blocks': 0
							},
							'probes': [],
							'flags': [],
							'prev': {
								'message': None,
								'replay': None,
								'ts': None
							},
							'eapol': None
						}
						self.stations[sta_addr] = sta
						
						if self.on_sta_found:
							self.on_sta_found(sta)

						if self.on_sta_found_addr:
							self.on_sta_found_addr(ap_addr, sta_addr)

					else:
						self.stations[sta_addr]['counters']['frames'] += 1
						self.stations[sta_addr]['channel'] = channel
						self.stations[sta_addr]['rate'] = rate
						self.stations[sta_addr]['mcs'] = mcs
						self.stations[sta_addr]['rssi'] = dBm_AntSignal
						
						if self.on_sta_update:
							self.on_sta_update(sta_addr, self.stations[sta_addr])

		if Dot11.fc.type_subtype == 0x80:
			if Dot11.addrs.addr3 == self.bssid:
				self.beacons += 1
				if not self.first_beacon_flag:
					self.first_beacon_flag = True
					self.beacon = raw
					elt = Dot11.Dot11Elt()

					if self.on_first_beacon:
						self.ssid = IEEE80211_Utils.get_ap_ssid(elt)
						self.vendors = IEEE80211_Utils.get_ap_vendor(elt)
						self.on_first_beacon({
							'ssid': self.ssid,
							'vendors': self.vendors
						})

				fs = Dot11.Dot11FragSeq()
				beacons_lost = fs.seq - self.last_seq
				self.last_seq = fs.seq

				if self.on_target_ap_update:
					self.on_target_ap_update({
						'beacons': self.beacons,
						'rssi': dBm_AntSignal,
						'beacons_lost': beacons_lost
					})

		if Dot11.fc.type_subtype in [0x08, 0x88]:
			EAPOL = Dot11.Dot11EAPOL()
			if EAPOL:
				key_info = EAPOL.data.key_info
				replay_counter = EAPOL.data.replay_counter

				for mask, map in self.eapol_map.items():
					if ((mask & 0x0FFF8) == (key_info & 0xFFF8)):
						message, sta_addr_field, ap_addr_fielfd = map

				sta_addr = getattr(Dot11.addrs, sta_addr_field)
				ap_addr = getattr(Dot11.addrs, ap_addr_fielfd)

				if sta_addr in self.stations and ap_addr == self.bssid:
					#print(f"[KEY]: {key_info:04x}, replay={replay_counter}, message={message}, sta={sta_addr}, ds={ap_addr}, flags={Dot11.fc.flags}")

					if message == 'M1':
						self.stations[sta_addr]['prev']['message'] = message
						self.stations[sta_addr]['prev']['replay'] = replay_counter
						self.stations[sta_addr]['prev']['ts'] = ts
						self.stations[sta_addr]['eapol'] = [raw]
						self.del_sta_flag(sta_addr, 'M2')
						self.del_sta_flag(sta_addr, 'M3')
						self.del_sta_flag(sta_addr, 'M4')
						self.add_sta_flag(sta_addr, 'M1')
						
						if self.on_sta_update:
							self.on_sta_update(sta_addr, self.stations[sta_addr])

						if self.on_eapol_received:
							self.on_eapol_received(ap_addr, sta_addr, message)
					
					if self.stations[sta_addr]['prev']['message']:
						delta_ts = ts - self.stations[sta_addr]['prev']['ts']
						if delta_ts > 1.0:
							if self.on_eapol_error:
								self.on_eapol_error(sta_addr, 'timeout')

							self.stations[sta_addr]['prev']['message'] = None
							self.stations[sta_addr]['eapol'] = None
							if self.stations[sta_addr]['prev']['message'] != 'M1':
								return
						
						if message == 'M2' and self.stations[sta_addr]['prev']['message'] == 'M1':
							if replay_counter == self.stations[sta_addr]['prev']['replay']:
								self.stations[sta_addr]['prev']['message'] = message
								self.stations[sta_addr]['prev']['ts'] = ts
								self.stations[sta_addr]['eapol'].append(raw)
								self.add_sta_flag(sta_addr, message)
								
								if self.on_sta_update:
									self.on_sta_update(sta_addr, self.stations[sta_addr])

								if self.on_eapol_received:
									self.on_eapol_received(sta_addr, ap_addr, message)
							else:
								self.stations[sta_addr]['prev']['message'] = None
								if self.on_eapol_error:
									self.on_eapol_error(sta_addr, 'broken pipe')
						
						if message == 'M3' and self.stations[sta_addr]['prev']['message'] == 'M2':
							if replay_counter == self.stations[sta_addr]['prev']['replay'] +1:
								self.stations[sta_addr]['prev']['message'] = message
								self.stations[sta_addr]['prev']['ts'] = ts
								self.stations[sta_addr]['prev']['replay'] = replay_counter
								self.stations[sta_addr]['eapol'].append(raw)
								self.add_sta_flag(sta_addr, message)

								if self.on_sta_update:
									self.on_sta_update(sta_addr, self.stations[sta_addr])

								if self.on_eapol_received:
									self.on_eapol_received(ap_addr, sta_addr, message)

							else:
								self.stations[sta_addr]['prev']['message'] = None
								if self.on_eapol_error:
									self.on_eapol_error(sta_addr, 'broken pipe')
						
						if message == 'M4' and self.stations[sta_addr]['prev']['message'] == 'M3':
							if replay_counter == self.stations[sta_addr]['prev']['replay']:
								self.stations[sta_addr]['prev'] = {
									'message': None,
									'replay': None,
									'ts': None
								}
								self.stations[sta_addr]['eapol'].append(raw)
								self.add_sta_flag(sta_addr, message)

								if self.on_sta_update:
									self.on_sta_update(sta_addr, self.stations[sta_addr])
								
								if self.on_eapol_received:
									self.on_eapol_received(sta_addr, ap_addr, message)

								if self.on_eapol_done:
									self.on_eapol_done(sta_addr)

								if self.on_eapol_data_done:
									self.on_eapol_data_done(self.beacon, ap_addr, sta_addr, self.stations[sta_addr]['eapol'])

class DBController(Callback):
	def __init__(self, db):
		self.db = db
		self.on_saved_ap_found = None
		self.on_saved_ap_sta_found = None
		self.on_saved_data_recv = None
		self.task_queue = queue.Queue()
		
		# Запускаем воркера
		threading.Thread(target=self._worker, daemon=True).start()

	def async_task(func):
		"""Декоратор, который отправляет метод в очередь"""
		@wraps(func)
		def wrapper(self, *args, **kwargs):
			self.task_queue.put((func, (self, *args), kwargs))
		return wrapper

	def _worker(self):
		while True:
			func, args, kwargs = self.task_queue.get()
			try:
				func(*args, **kwargs)
			except Exception as e:
				print(f"DB Error in {func.__name__}: {e}")
			finally:
				self.task_queue.task_done()

	@async_task
	def insert_4way_handshake(self, beacon: bytes, bssid: str, sta: str, eapol_data: list):
		ap_id = self.db.insert_ap(bssid, beacon)
		self.db.remove_sta(ap_id, sta)
		for m, frame in enumerate(eapol_data):
			self.db.insert_handshake(ap_id, sta, frame, f'M{m+1}')

	@async_task
	def get_ap_db_exists(self, bssid: str):
		ap = self.db.get_row('access_points', {
			'bssid': bssid
		})
		if ap and self.on_saved_ap_found:
			self.on_saved_ap_found(bssid)

	@async_task
	def get_ap_sta_db_exists(self, bssid: str, sta: str) -> str:
		ap = self.db.get_row('access_points', {
			'bssid': bssid
		})
		if ap:
			sta_data = self.db.get_row('stations', {
				'ap_id': ap['id'],
				'sta': sta
			})
			if sta_data:
				if self.on_saved_ap_sta_found:
					self.on_saved_ap_sta_found(bssid, sta, sta_data['date'])

	def get_saved_handshakes(self):
		aps = self.db.get_rows('access_points')
		result = {}

		for ap in aps:
			beacon = ap['beacon']
			if beacon:
				RadioTap_PKT = RadioTap(beacon)
				Dot11 = Dot11_Layer(radiotap=RadioTap_PKT, pkt=beacon)
				dBm_AntSignal = RadioTap_PKT.get('dBm_AntSignal')
				channel = RadioTap_PKT.get('Channel')

				if Dot11.fc.type_subtype == 0x80:
					elt = Dot11.Dot11Elt()
					ssid = IEEE80211_Utils.get_ap_ssid(elt)
					bssid = Dot11.addrs.addr3
					
					result[bssid] = {
						'ssid': ssid,
						'bssid': bssid,
						'rssi': dBm_AntSignal,
						'date': ap['date'],
						'channel': channel.channel,
						'stations': {}
					}

					stations = self.db.get_rows('stations', {'ap_id': ap['id']})

					for sta in stations:
						sta_id = sta['sta']
						eapol = sta['eapol']
						eapol_rt = RadioTap(eapol)
						eapol_dot11 = Dot11_Layer(radiotap=eapol_rt, pkt=eapol)
						eapol_dBm_AntSignal = eapol_rt.get('dBm_AntSignal')

						if sta_id not in result[bssid]['stations']:
							result[bssid]['stations'][sta_id] = {
								'addr': sta_id,
								'messages': {}
							}
						
						result[bssid]['stations'][sta_id]['messages'][sta['message_type']] = {
							'message': sta['message_type'],
							'rssi': eapol_dBm_AntSignal,
							'flags': eapol_dot11.fc.flags,
							'date': sta['date']
						}

		return result


class PacketSender(Callback):
	def __init__(self):
		self.on_send_deauth = None
		self.on_send_deauth_done = None
		self.on_deauth_packet = None

	def send_deauth(self, ap_addr, sta_addr, reason, retries, attempts, timeout):
		def run():
			rt_base = b"\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00"
			dot11_header = Dot11PacketBuilder.Dot11(fc=0xC0, addr1=sta_addr, addr2=ap_addr, addr3=ap_addr, frag=0, seq=0, duration=314)
			deauth = Dot11PacketBuilder.Dot11Deauth(reason_code=reason)
			packet = rt_base + dot11_header + deauth
			
			if self.on_send_deauth:
				for ret in range(attempts):
					for i in range(retries):
						self.on_send_deauth(packet)
					
					if self.on_deauth_packet:
						self.on_deauth_packet(ap_addr, sta_addr, reason)

					time.sleep(timeout)

				if self.on_send_deauth_done:
					self.on_send_deauth_done()
		
		thread = threading.Thread(target=run, daemon=True)
		thread.start()
		

class WifiManagerController:
	def __init__(self):
		self.IEEE80211_MODES = {
			0: 'Unknown',
			1: 'Station',
			802: 'Ad-Hoc',
			803: 'Monitor',
			804: 'Mesh (802.11s)',
			805: 'P2P (Direct GO)',
			806: 'P2P Client'
		}

	def handle_phys_details(self):
		result = {}
		for phy in IEEE80211_Hardware.get_80211_phys():
			iface = IEEE80211_Hardware.iface_name(phy=phy)
			mode = IEEE80211_Hardware.phy_iface_get_mode(phy=phy, iface=iface)
			mode = self.IEEE80211_MODES.get(mode, "Unknown")

			result[phy] = {
				'phy': phy,
				'iface': iface,
				'channels': IEEE80211_Hardware.get_phy_channels(phy=phy),
				'mac': {
					'hw': IEEE80211_Hardware.get_phy_mac(phy=phy),
					'iface': IEEE80211_Hardware.get_iface_mac(iface=iface)
				},
				'mode': mode,
				'state': IEEE80211_Hardware.iface_get_state(iface=iface),
				'driver': IEEE80211_Hardware.get_phy_driver(phy=phy),
				'chipset': IEEE80211_Hardware.get_phy_chipset(phy=phy)
			}

		return result

	def switch_mode(self, phy, iface, mode):
		if mode == 'monitor':
			IEEE80211_Hardware.set_phy_iface_mode(phy=phy, iface=iface, mode='managed')
		else:
			IEEE80211_Hardware.set_phy_iface_mode(phy=phy, iface=iface, mode='monitor')

	def switch_state(self, iface, state):
		if state == 'up':
			IEEE80211_Hardware.iface_set_state(iface=iface, state=0)
		else:
			IEEE80211_Hardware.iface_set_state(iface=iface, state=1)