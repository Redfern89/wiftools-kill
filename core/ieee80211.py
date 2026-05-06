#!/usr/bin/env python3

import struct
from dataclasses import dataclass
from types import SimpleNamespace
from core.defs import _rt_fields_specs, _rt_presents, _rt_flags, _rt_channel_flags, _rt_mcs_known, _rt_mcs_common, _rt_mcs_rates_20mhz, _rt_mcs_bw_multipler, _rt_freq_channels_2GHz, _rt_freq_channels_5GHz, _rt_all_channels, _dot11_fc_flags, _dot11_capabilities, _dot11_tags, _dot11_wps_tlv_names, _dot11_wps_config_methods_flags, rsn_cipher_suites, rsn_akm_suites, _dot11_fc_management_types, _dot11_fc_control_types, _dot11_fc_data_types, _dot11_fc_qos_data_types, _dot11_addr2_candidates, _dot11_addr3_candidates, _dot11_wps_wfa, _dot11_vendor_specific_types, _dot11_eapol_types, _dot11_eap_status_codes, _dot11_eap_type_codes, _dot11_eap_tlv_struct, ID_NAME, RADIOTAP, RT_PRESENT, RT_CHANNEL, RT_MCS, RT_MCS_DECODED, DOT11_FC, DOT11_ADDRS, DOT11_FRAG_SEQ, DOT11_PROTECTED_DATA, DOT11_CIPHER_IV, DOT11, DOT11_FIXED_PARAMETERS_12B, DOT11_ELT_IE, DOT11_VENDOR_SPECIFIC, DOT11_WPS_IE, DOT11_WPS_VENDOR_EXTENSION, suite_field, RSN_IE, WPA_IE, DOT11_SUPPORTED_RATE, DOT11_LLC, DOT11_EAPOL, DOT11_EAPOL_RSN, DOT11_EAP, arp_opcodes

@dataclass
class ARPOpcode:
	opcode: int
	opcode_name: str

@dataclass
class ETH2Layer:
	dst_mac: str
	src_mac: str
	type: int

@dataclass
class ARPData:
	eth: ETH2Layer
	hardware_type: int
	proto_type: int
	hardware_size: int
	proto_size: int
	opcode: ARPOpcode
	sender_mac: str
	sender_ip: str
	target_mac: str
	target_ip: str

class ProtoHelpers:
	@staticmethod
	def mac2bin(mac):
		return bytes.fromhex(mac.replace(':', '').replace('-', ''))

	@staticmethod
	def bin2mac(mac):
		return ':'.join(f'{b:02x}' for b in mac)

	@staticmethod
	def bin2ip(ip):
		return '.'.join(f'{b}' for b in ip)

	@staticmethod
	def ip2bin(ip):
		return b''.join(int(b).to_bytes() for b in ip.split('.'))
	
	@staticmethod
	def makeFlagsField(flags_list, flags_value):
		flags = 0x00
		for flag in flags_value:
			try:
				index = flags_list.index(flag)
				flags |= (1 << index)
			except ValueError:
				pass
		return flags

class RadioTap:
	def __init__(self, pkt):
		self.rt_pkt = self.get_rt_pkt(pkt)
		if self.rt_pkt:
			self.it_version = self.rt_pkt.it_version
			self.it_pad = self.rt_pkt.it_pad
			self.it_len = self.rt_pkt.it_len
			self.presents = self.rt_pkt.presents
		else:
			self.presents = []

	def get(self, name):
		for item in self.presents:
			#print(item.name)
			if item.name == name:
				return item.value
		
		return None

	def get_rt_pkt(self, pkt):
		if pkt[0:2] == b"\x00\x00":
			it_version, it_pad, it_len = struct.unpack_from('<BBH', pkt, 0)
			offset = 4
			ext = True
			presents = []
			presents_flags = []

			while (ext):
				it_present_Set = struct.unpack_from('<I', pkt, offset)[0]
				presents_flags.append(it_present_Set)
				ext = (it_present_Set & (1 << 31))
				offset += 4

			for it_present in presents_flags:
				for bit in range(32):
					if bit == 31: continue

					if it_present & (1 << bit):
							if bit in _rt_fields_specs:
								size, align = _rt_fields_specs[bit]
								offset = (offset + align -1) & ~(align - 1)
								present_data = pkt[offset : offset + size]
								if bit in [0, 11]:
									presents.append(RT_PRESENT(
										bit=bit,
										name=_rt_presents[bit],
										value=int.from_bytes(present_data, 'little')
									))
								elif bit == 1:
									flags = []
									for flag_bit in range(8):
										if int.from_bytes(present_data, 'little') & (1 << flag_bit):
											flags.append(_rt_flags[flag_bit])
										presents.append(RT_PRESENT(
											bit=bit,
											name=_rt_presents[bit],
											value=flags
										))
								elif bit == 2:
									presents.append(RT_PRESENT(
										bit=bit,
										name=_rt_presents[bit],
										value=int.from_bytes(present_data, 'little') / 2
									))
								elif bit == 3:
									# Читаем частоту (первые 2 байта)
									freq = int.from_bytes(present_data[:2], 'little')
									
									# Парсим флаги канала (следующие 2 байта)
									channel_flags_raw = int.from_bytes(present_data[2:], 'little')
									channel_flags = []
									for channel_flags_bit in range(16):
										if (channel_flags_raw & (1 << channel_flags_bit)):
											channel_flags.append(_rt_channel_flags[channel_flags_bit])
									
									# Определяем номер канала по нашей базе, если нет — оставляем частоту
									channel_num = _rt_all_channels.get(freq, freq)

									presents.append(RT_PRESENT(
										bit=bit,
										name=_rt_presents[bit],
										value=RT_CHANNEL(
											freq=freq,
											channel=channel_num,
											flags=channel_flags
										)
									))
								elif bit == 5:
									presents.append(RT_PRESENT(
										bit=bit,
										name=_rt_presents[bit],
										value=int.from_bytes(present_data, 'little', signed=True)
									))
								elif bit == 19:
									mcs_known, mcs_flags, mcs_index = struct.unpack_from('<BBB', present_data)
									mcs_knowns = []
									for mcs_known_bit in range(8):
										if mcs_known & (1 << mcs_known_bit):
											mcs_knowns.append(_rt_mcs_known[mcs_known_bit])

									if mcs_known & 0x01:
										bw_val = mcs_flags & 0x03
										bandwidth = {0: '20', 1: '40', 2: '20L', 3: '20U'}.get(bw_val, 'unk')
									
									if mcs_known & 0x02:
										shortGI = bool(mcs_flags & 0x04)

									if mcs_known & 0x04:
										format = 'Greenfield' if (mcs_flags & 0x08) else 'Mixed'

									modulation, coding = _rt_mcs_common.get(mcs_index, ("Unknown", "Unknown"))
									base_lgi, base_sgi = _rt_mcs_rates_20mhz.get(mcs_index, (0, 0))

									rate = base_sgi if shortGI else base_lgi
									multiplier = _rt_mcs_bw_multipler.get(bandwidth, 1)
									final_speed = rate * multiplier

									presents.append(RT_PRESENT(
										bit=bit,
										name=_rt_presents[bit],
										value=RT_MCS(
											known=mcs_knowns,
											bandwidth=bandwidth,
											shortGI=shortGI,
											format=format,
											index=mcs_index,
											decoded=RT_MCS_DECODED(
												modulation=modulation,
												coding_rate=coding,
												streams=0,
												gi_ns=400 if shortGI else 800,
												rate=final_speed
											)
										)
									))
								else:
									presents.append(RT_PRESENT(
										bit=bit,
										name=_rt_presents[bit],
										value=present_data
									))
								offset += size
							else:
								break

			return RADIOTAP(
				it_version=it_version,
				it_pad=it_pad,
				it_len=it_len,
				presents=presents
			)
		return None

class IEEEUtils:

	@staticmethod
	def bin2mac(b: bytes) -> str:
		return ':'.join(f'{bin:02x}' for bin in b)

class Dot11Parsers:

	@staticmethod
	def _dot11EAPOL_RSN(data):		
		if data:
			key_desc, key_info, key_len, replay_counter, wpa_nonce, key_iv, wpa_key_rsc, wpa_key_id, wpa_key_mic, wpa_key_data_len = struct.unpack_from('>BHHQ32s16s8s8s16sH', data)

			if wpa_key_data_len:
				wpa_key_data = data[95:95+wpa_key_data_len]
			else:
				wpa_key_data = None

			return DOT11_EAPOL_RSN(
				key_desc=key_desc,
				key_info=key_info,
				key_len=key_len,
				replay_counter=replay_counter,
				wpa_nonce=wpa_nonce,
				key_iv=key_iv,
				wpa_key_rsc=wpa_key_rsc,
				wpa_key_id=wpa_key_id,
				wpa_key_mic=wpa_key_mic,
				wpa_key_data_len=wpa_key_data_len,
				wpa_key_data=wpa_key_data
			)

	@staticmethod
	def default(b: bytes) -> bytes:
		return b

	@staticmethod
	def decode_str(b: bytes) -> str:
		return b.decode(encoding='utf-8', errors='ignore')

	@staticmethod
	def decode_int_8b(b: bytes) -> int:
		return int.from_bytes(b)
	
	@staticmethod
	def decode_rsn(b: bytes) -> RSN_IE:
		offset = 0
		total_len = len(b)

		# Вспомогательная функция, чтобы не писать if на каждом шагу
		def has_bytes(n):
			return (offset + n) <= total_len

		# 1. Читаем версию (2 байта)
		version = int.from_bytes(b[offset:offset+2], 'little') if has_bytes(2) else 0
		offset += 2

		pair_suites = []
		akm_suites = []

		# 2. Групповой шифр (4 байта)
		group_cipher_suite_oui = "00:00:00"
		group_cipher_suite_type = 0
		
		if has_bytes(4):
			group_cipher_suite = b[offset:offset+4]
			group_cipher_suite_oui = IEEEUtils.bin2mac(group_cipher_suite[:3])
			group_cipher_suite_type = group_cipher_suite[3]
			offset += 4

		# 3. Парные шифры (2 байта на счетчик + N*4 байта)
		pairwise_ciphers_count = int.from_bytes(b[offset:offset+2], 'little') if has_bytes(2) else 0
		offset += 2

		for _ in range(pairwise_ciphers_count):
			if not has_bytes(4): break # Битый пакет, выходим из цикла
			
			pairwise_cipher_suite = b[offset:offset+4]
			offset += 4
			
			p_oui = IEEEUtils.bin2mac(pairwise_cipher_suite[:3])
			p_type = pairwise_cipher_suite[3]
			
			pair_suites.append(suite_field(
				type=ID_NAME(id=p_type, name=rsn_cipher_suites.get(p_type, "Unknown")),
				oui=p_oui
			))

		# 4. AKM сюиты (2 байта на счетчик + N*4 байта)
		akm_suites_count = int.from_bytes(b[offset:offset+2], 'little') if has_bytes(2) else 0
		offset += 2

		for _ in range(akm_suites_count):
			if not has_bytes(4): break # Битый пакет
			
			akm_suite = b[offset:offset+4]
			offset += 4
			
			a_oui = IEEEUtils.bin2mac(akm_suite[:3])
			a_type = akm_suite[3]
			
			akm_suites.append(suite_field(
				type=ID_NAME(id=a_type, name=rsn_akm_suites.get(a_type, "Unknown")),
				oui=a_oui
			))

		return RSN_IE(
			version=version,
			group_cipher=suite_field(
				type=ID_NAME(id=group_cipher_suite_type, name=rsn_cipher_suites.get(group_cipher_suite_type, "Unknown")),
				oui=group_cipher_suite_oui
			),
			pair_cnt=len(pair_suites), # Лучше брать реальную длину списка
			pair_suites=pair_suites,
			akm_cnt=len(akm_suites),
			akm_suites=akm_suites
		)


	@staticmethod
	def decode_vendor(b: bytes):
		if len(b) < 4:
			return
		
		oui = IEEEUtils.bin2mac(b[:3])
		type = b[3]

		if oui == '00:50:f2':
			if type == 4:
				return DOT11_VENDOR_SPECIFIC(
					oui=oui,
					type=type,
					info=Dot11Parsers.decode_wps(b[4:])
				)
			elif type == 1:
				return DOT11_VENDOR_SPECIFIC(
					oui=oui,
					type=type,
					info=Dot11Parsers.decode_wpa(b[4:])
				)
			else:
				return DOT11_VENDOR_SPECIFIC(
					oui=oui,
					type=type,
					info=b[4:]
				)
		else:
			return DOT11_VENDOR_SPECIFIC(
				oui=oui,
				type=type,
				info=b[4:]
			)
	
	@staticmethod
	def decode_wpa(b: bytes) -> WPA_IE:
		offset = 0
		total_len = len(b)

		def has_bytes(n):
			return (offset + n) <= total_len

		# 1. Версия WPA (2 байта)
		wpa_version = int.from_bytes(b[offset:offset+2], 'little') if has_bytes(2) else 1
		offset += 2

		unicast_ciphers = []
		akm_suites = []

		# 2. Multicast (Group) Cipher (4 байта)
		m_oui, m_type = "00:00:00", 0
		if has_bytes(4):
			multicast_suite = b[offset:offset+4]
			m_oui = IEEEUtils.bin2mac(multicast_suite[:3])
			m_type = multicast_suite[3]
			offset += 4

		# 3. Unicast Ciphers (2 байта счетчик + N*4 байта)
		u_count = int.from_bytes(b[offset:offset+2], 'little') if has_bytes(2) else 0
		offset += 2

		for _ in range(u_count):
			if not has_bytes(4): break
			cipher = b[offset:offset+4]
			offset += 4
			
			unicast_ciphers.append(suite_field(
				type=ID_NAME(id=cipher[3], name=rsn_cipher_suites.get(cipher[3], "Unknown")),
				oui=IEEEUtils.bin2mac(cipher[:3])
			))

		# 4. AKM Suites (2 байта счетчик + N*4 байта)
		a_count = int.from_bytes(b[offset:offset+2], 'little') if has_bytes(2) else 0
		offset += 2

		for _ in range(a_count):
			if not has_bytes(4): break
			suite = b[offset:offset+4]
			offset += 4 # Исправлено: было + вместо +=
			
			akm_suites.append(suite_field(
				type=ID_NAME(id=suite[3], name=rsn_akm_suites.get(suite[3], "Unknown")),
				oui=IEEEUtils.bin2mac(suite[:3])
			))

		return WPA_IE(
			version=wpa_version,
			multicast_suite=suite_field(
				type=ID_NAME(id=m_type, name=rsn_cipher_suites.get(m_type, "Unknown")),
				oui=m_oui
			),
			unicast_cnt=len(unicast_ciphers),
			unicast_suites=unicast_ciphers,
			akm_cnt=len(akm_suites),
			akm_suites=akm_suites
		)


	@staticmethod
	def decode_wps(b: bytes) -> list:
		offset = 0
		pkt_len = len(b)
		
		result = []

		handlers = {
			0x1057: Dot11Parsers.decode_int_8b,
			0x104a: Dot11Parsers.decode_int_8b,

			0x1021: Dot11Parsers.decode_str,
			0x1023: Dot11Parsers.decode_str,
			0x1024: Dot11Parsers.decode_str,
			0x1042: Dot11Parsers.decode_str,
			0x1011: Dot11Parsers.decode_str
		}

		while (offset +4 <= pkt_len):
			tag_id   = int.from_bytes(b[offset:offset+2], byteorder='big')
			tag_len  = int.from_bytes(b[offset+2:offset+4], byteorder='big')
			tag_data = b[offset+4:offset+4+tag_len]

			if tag_len > pkt_len:
				break
			
			handler = handlers.get(tag_id, Dot11Parsers.default)

			result.append(DOT11_WPS_IE(
				tag_len=tag_len,
				tag_type=ID_NAME(
					id=tag_id,
					name=_dot11_eap_tlv_struct.get(tag_id, "Unknown")
				),
				info=handler(tag_data)
			))			

			offset += 4 + tag_len
		
		return result

class Dot11_Layer:
	def __init__(self, radiotap, pkt):
		self.radiotap = radiotap
		self.pkt = pkt[self.radiotap.it_len:]
		self.fc = self.Dot11FC()
		self.offset = 0
		self.addrs = self.dot11Addrs()

	def Dot11FC(self):
		frame_control, fc_flags = struct.unpack_from('>BB', self.pkt)
		flags = []
		for fc_flag_bit in range(8):
			if fc_flags & (1 << fc_flag_bit):
				flags.append(_dot11_fc_flags[fc_flag_bit])
		
		fc_type = (frame_control >> 2) & 0b11
		fc_sub_type = (frame_control >> 4) & 0b1111
		fc_type_subtype = (fc_sub_type << 4) | (fc_type << 2)

		return DOT11_FC(
			type=fc_type,
			subtype=fc_sub_type,
			type_subtype=fc_type_subtype,
			flags=flags
		)
	
	def dot11Duration(self):
		return struct.unpack_from('<H', self.pkt, 2)[0] & 0x7FFF
	
	def dot11Addrs(self):
		addr1 = ProtoHelpers.bin2mac(self.pkt[4:10])
		self.offset = 10
		addr2 = None
		addr3 = None
		addr4 = None

		if self.fc.type_subtype in _dot11_addr2_candidates:
			addr2 = ProtoHelpers.bin2mac(self.pkt[10:16])
			self.offset = 16
		if self.fc.type_subtype in _dot11_addr3_candidates:
			addr3 = ProtoHelpers.bin2mac(self.pkt[16:22])
			self.offset = 22
		
		if 'to_ds' in self.fc.flags and 'from_ds' in self.fc.flags:
			addr4 = ProtoHelpers.bin2mac(self.pkt[22:28])
			self.offset = 28
		
		return DOT11_ADDRS(
			addr1=addr1,
			addr2=addr2,
			addr3=addr3,
			addr4=addr4
		)
	
	def Dot11FragSeq(self):
		if self.fc.type_subtype in _dot11_addr3_candidates:
			frag_seq = struct.unpack_from('<H', self.pkt, self.offset)[0]
			frag = frag_seq & 0x0F
			seq  = (frag_seq >> 4)
			
			return DOT11_FRAG_SEQ(
				frag=frag,
				seq=seq
			)
		return None

	def Dot11(self):
		return DOT11(
			fc=self.fc,
			duration=self.dot11Duration(),
			addrs=self.dot11Addrs(),
			fragseq=self.Dot11FragSeq()
		)
	
	def Dot11FixedParams12b(self):
		if self.fc.type_subtype in [0x50, 0x80]:
			offset = 24 # Skip Dot11 header
			ts, interval, cap = struct.unpack_from('<QHH', self.pkt, offset)
			capabilities = []

			for beacon_cap_bit in range(16):
				if cap & (1 << beacon_cap_bit):
					capabilities.append(_dot11_capabilities[beacon_cap_bit])
			
			return DOT11_FIXED_PARAMETERS_12B(
				timestamp=ts,
				intereval=interval,
				capabilities=capabilities
			)

		return None
	
	def Dot11Elt(self):
		if self.fc.type_subtype in [0x40, 0x50, 0x80]:
			offset = 36
			if self.fc.type_subtype == 0x40:
				offset = 24

			pkt = self.pkt[offset:]
			pkt_len = len(pkt)
			offset = 0

			if pkt_len < 2:
				return

			if hasattr(self.radiotap.presents, 'Flags'):
				if 'FCS' in self.radiotap.presents.Flags:
					pkt_len -= 4
			
			result = []
			handlers = {
				0:   Dot11Parsers.decode_str,    # SSID
				3:   Dot11Parsers.decode_int_8b, # DS Parameter set (Channel)
				48:  Dot11Parsers.decode_rsn,    # RSN Info
				221: Dot11Parsers.decode_vendor  # Vendor specific
			}

			while (offset +2 <= pkt_len):
				tag_id   = pkt[offset]
				tag_len  = pkt[offset +1]
				tag_data = pkt[offset +2:offset+2+tag_len]

				if tag_len > pkt_len:
					break
				
				handler = handlers.get(tag_id, Dot11Parsers.default)

				result.append(DOT11_ELT_IE(
					tag_len=tag_len,
					tag_type=ID_NAME(
						id=tag_id,
						name=_dot11_tags.get(tag_id, "Unknown")
					),
					info=handler(tag_data)
				))

				offset += 2 + tag_len
		
			return result

	def Dot11EAPOL(self):
		if self.fc.type_subtype in _dot11_fc_data_types or \
			self.fc.type_subtype in _dot11_fc_qos_data_types:

			if 'protected' in self.fc.flags:
				return None

			offset = 24 # skip FC, Duration, addrs, frag_seq
			
			if self.fc.type_subtype in _dot11_fc_qos_data_types:
				offset += 2
			
			pkt = self.pkt[offset:]
			offset = 0
			LLC     = pkt[:2]
			CONTROL = pkt[2]
			OUI     = pkt[3:6]
			TYPE    = pkt[6:8]
			
			if LLC == b'\xAA\xAA' and CONTROL == 0x03 and TYPE == b'\x88\x8e':
				offset += 8
				pkt = pkt[offset:]
				version, type, length = struct.unpack_from('>BBH', pkt)
				if length:
					data = pkt[4:]
				else:
					data = None
				
				handlers = {
					#0: self._dot11EAP,
					3: Dot11Parsers._dot11EAPOL_RSN
				}
				handler = handlers.get(type, Dot11Parsers.default) #self._dot11decode_default) 

				return DOT11_EAPOL(
					llc=DOT11_LLC(
						DSAP=LLC[0], SSAP=LLC[1],
						CTRL=CONTROL,
						OUI=ProtoHelpers.bin2mac(OUI),
						type=TYPE	
					),
					version=version,
					type=ID_NAME(
						id=type,
						name=_dot11_eapol_types[type]
					),
					length=length,
					data=handler(data)
				)

		return None


class Dot11PacketBuilder:
	
	@staticmethod
	def Dot11(fc, addr1, addr2=None, addr3=None, addr4=None, duration=0, frag=None, seq=None, fcflags=None, QoSControl=0x00, wep_iv=None, tkip_iv=None, ccmp_iv=None, ht_control=None):
		duration = (duration >> 1) & 0x7FFF
		packet = bytearray()
		flags = 0x00

		if fcflags:
			for flag in fcflags:
				try:
					index = _dot11_fc_flags.index(flag)
					flags |= (1 << index)
				except ValueError:
					pass

		packet.extend(struct.pack('<BBH6s', fc, flags, duration, ProtoHelpers.mac2bin(addr1)))
		if addr2:
			packet.extend(struct.pack('<6s', ProtoHelpers.mac2bin(addr2)))
		if addr3:
			packet.extend(struct.pack('<6s', ProtoHelpers.mac2bin(addr3)))
		if addr4:
			packet.extend(struct.pack('<6s', ProtoHelpers.mac2bin(addr4)))
			
		if not frag is None and not seq is None:
			frag_seq = (seq << 4) | frag
			packet.extend(struct.pack('<H', frag_seq))

		if fc in [0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8]:
			packet.extend(struct.pack('<H', QoSControl))

		if not ht_control is None:
			packet.extend(struct.pack('<I', ht_control))

		if not wep_iv is None:
			packet.extend(struct.pack('<I', wep_iv))

		if not tkip_iv is None:
			packet.extend(struct.pack('<Q', tkip_iv))

		if not ccmp_iv is None:
			packet.extend(struct.pack('<Q', ccmp_iv))

		return bytes(packet)

	@staticmethod
	def Dot11Beacon(timestamp=0, beacon_interval=100, capabilities=[]):
		packet = bytearray()
		_capabilities = ProtoHelpers.makeFlagsField(_dot11_capabilities, capabilities)
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', beacon_interval))
		packet.extend(struct.pack('<H', _capabilities))
			
		return bytes(packet)
		
	@staticmethod
	def Dot11Auth(algoritm=0, seq=0, status_code=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', algoritm))
		packet.extend(struct.pack('<H', seq))
		packet.extend(struct.pack('<H', status_code))

		return bytes(packet)

	@staticmethod
	def Dot11Deauth(reason_code=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', reason_code))

		return bytes(packet)

	@staticmethod
	def Dot11Disassoc(reason_code=0x0000):
		packet = bytearray()
		packet.extend(struct.pack('<H', reason_code))

		return bytes(packet)

	@staticmethod
	def Dot11AssocReq(capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', capabilities))
		packet.extend(struct.pack('<H', listen_interval))

		return bytes(packet)

	@staticmethod
	def dot11AssocResp(capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		_capabilities = ProtoHelpers.makeFlagsField(_dot11_capabilities, capabilities)

		packet.extend(struct.pack('<H', _capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
		
	@staticmethod
	def Dot11ReassocReq(current_ap, capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		_capabilities = ProtoHelpers.makeFlagsField(_dot11_capabilities, capabilities)
		packet.append(struct.pack('<H', _capabilities))
		packet.append(struct.pack('<H', listen_interval))
		packet.append(struct.pack('<H6s', ProtoHelpers.mac2bin(current_ap)))

		return bytes(packet)
		
	@staticmethod
	def Dot11ReassocResp(capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		_capabilities = ProtoHelpers.makeFlagsField(_dot11_capabilities, capabilities)
		packet.extend(struct.pack('<H', _capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
		
	@staticmethod
	def Dot11ProbeReq():
		pass
		
	@staticmethod
	def Dot11ProbeResp(timestamp=0, beacon_interval=0x0000,  capabilities=None):
		packet = bytearray()
		_capabilities = ProtoHelpers.makeFlagsField(_dot11_capabilities, capabilities)
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', beacon_interval))
		packet.extend(struct.pack('<H', _capabilities))
			
		return bytes(packet)

	@staticmethod
	def Dot11TLV16(id, info):
		packet = bytearray()
		packet.extend(struct.pack('>H', id))
		packet.extend(struct.pack('>H', len(info)))
		packet.extend(info)

		return bytes(packet)

	@staticmethod
	def Dot11TLV(id, info):
		packet = bytearray()
		packet.extend(struct.pack('<B', id))
		packet.extend(struct.pack('<B', len(info)))
		packet.extend(info)
		
		return bytes(packet)
		
	@staticmethod
	def LLC_SNAP(oui, control, code):
		packet = bytearray()
		packet.extend(b'\xAA\xAA') # LLC / DSAP, SSAP = SNAP
		packet.extend(struct.pack('>B', control)) # Fucking control, fucking understand 
		packet.extend(struct.pack('<3s', ProtoHelpers.mac2bin(oui)))
		packet.extend(struct.pack('>H', code))

		return bytes(packet)
		
	@staticmethod
	def EAPOL(version, type, length):
		packet = bytearray()
		packet.extend(struct.pack('>B', version))
		packet.extend(struct.pack('>B', type))
		packet.extend(struct.pack('>H', length))

		return bytes(packet)
		
	@staticmethod
	def EAPOL_HandShake(key_desc, key_info, key_len, replay_counter, nonce, iv, rsc, id, mic, wpa_data=None):
		packet = bytearray()
		packet.extend(struct.pack('>B', key_desc))
		packet.extend(struct.pack('>H', key_info))
		packet.extend(struct.pack('>H', key_len))
		packet.extend(struct.pack('>Q', replay_counter))
		packet.extend(struct.pack('>32s', nonce))
		packet.extend(struct.pack('>16s', iv))
		packet.extend(struct.pack('>Q', rsc))
		packet.extend(struct.pack('>Q', id))
		packet.extend(struct.pack('>16s', mic))

		if wpa_data:
			wpa_len = len(wpa_data)
		else:
			wpa_len = 0
		packet.extend(struct.pack('>H', wpa_len))
			
		if wpa_data:
			packet.extend(wpa_data)

		return bytes(packet)
		
	@staticmethod
	def EAP(code, id, type, data):
		packet = bytearray()
		length = 5 + len(data)

		packet.extend(struct.pack('>B', code))
		packet.extend(struct.pack('>B', id))
		packet.extend(struct.pack('>H', length))
		packet.extend(struct.pack('>B', type))
		packet.extend(data)

		return bytes(packet)
		
	@staticmethod
	def EAP_EXPANDED(vendor_id, vendor_type, opcode, flags=0x00):
		packet = bytearray()
		packet.extend(struct.pack('>3s', ProtoHelpers.mac2bin(vendor_id)))
		packet.extend(struct.pack('>I', vendor_type))
		packet.extend(struct.pack('>B', opcode))
		packet.extend(struct.pack('>B', flags))

		return bytes(packet)