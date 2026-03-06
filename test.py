#!/usr/bin/env python3

import struct
from dataclasses import dataclass
from types import SimpleNamespace
import pprint

raw = \
	b"\x00\x00\x15\x00\x2a\x48\x08\x00\x00\x00\x85\x09\x80\x04\xdb\x01" \
	b"\x00\x00\x07\x00\x07\x88\x42\x6c\x00\x7c\x3e\x82\xcf\x41\x77\x04" \
	b"\x5e\xa4\x6a\x28\x47\x40\x3f\x8c\x93\x04\x90\x40\x98\x00\x00\x8c" \
	b"\x69\x00\x20\x00\x00\x00\x00\x3c\xce\xaa\xee\x82\x85\x7f\x58\xa6" \
	b"\x46\x69\xba\x3c\xfb\xd2\x0c\x28\x0c\x11\x7e\x5d\x4d\x54\x6e\x56" \
	b"\x23\x3e\xbc\x39\x90\xd0\x6d\x07\x31\xd4\xf6\x20\xc4\x6c\x34\xda" \
	b"\xbf\x2c\x1c\xa6\xef\x09\xa9\xe0\xbb\xc1\xdf\x67\xab\xe1\xa4\xe8" \
	b"\x67\x3d\x1f\x64\x08\x54\x22\x69\x92\xfd\xcb\x9d\xbf\x4d\x8f\x3e" \
	b"\x04\x1e\x58"

raw_ath = \
	b"\x00\x00\x27\x00\x2b\x40\x08\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
	b"\xd6\xd1\x2f\x04\x00\x00\x00\x00\x10\x00\x85\x09\x80\x04\xed\x00" \
	b"\x00\x00\x07\x00\x07\xed\x00\x88\x42\x6c\x00\x7c\x3e\x82\xcf\x41" \
	b"\x77\x04\x5e\xa4\x6a\x28\x47\x40\x3f\x8c\x93\x04\x90\x30\xab\x00" \
	b"\x00\xb3\x1a\x00\x20\x00\x00\x00\x00\x6c\x54\x2a\x7c\x66\x2f\xcf" \
	b"\x7e\x63\x5f\x3c\x17\x96\x29\x4d\x8e\x0e\xb8\xdc\x16\x6a\xe4\x20" \
	b"\x52\x5e\x19\xf6\x0f\xb2\x18\x06\x2b\x88\x50\x4b\x5f\x8a\x5b\x0f" \
	b"\xdb\x1d\x54\xb0\xe9\xb7\xf0\xed\xd3\xbb\xf0\x47\x91\x11\x59\x47" \
	b"\x82\xf9\x99\x1f\xa4\x16\x9e\x72\xdf\xd7\x39\x25\x06\x00\x34\x6c" \
	b"\x9b\x01\x97\x48\x21\x5d\xdd\x79\x4a"


raw2 = \
	b"\x00\x00\x24\x00\x2f\x40\x00\xa0\x20\x08\x00\x00\x00\x00\x00\x00" \
	b"\x59\xcc\x2f\x04\x00\x00\x00\x00\x10\x6c\x85\x09\xc0\x00\xe7\x00" \
	b"\x00\x00\xe7\x00\x88\x49\x3c\x00\x04\x5e\xa4\x6a\x28\x47\x7c\x3e" \
	b"\x82\xcf\x41\x77\x40\x3f\x8c\x93\x04\x90\x40\x49\x00\x00\x8f\x14" \
	b"\x00\x20\x00\x00\x00\x00\x70\xa9\x4e\x27\x64\x53\x3f\x9e\x3d\x63" \
	b"\xd6\xc0\x73\xd6\xec\x67\xd2\x35\xd8\x10\x96\x30\x49\x4a\x15\x22" \
	b"\x02\xc1\x8f\x14\xd0\x6a\xf4\x56\xa5\xdd\x47\xb7\xc8\xdc\xb8\x07" \
	b"\x77\x35\x2e\x1a\xc0\x63\xc3\x2b\x37\xa7\x5f\x87\x2b\x4c\xe1\xe1" \
	b"\x68\xfb\xcb\x28\x05\xd2\x65\xfc\x5b\xa6\xe2\x8f\xb6\x1f\xf2\x3f" \
	b"\xc8\x57\x86\xe3\x7f\x03"



rt_presents = ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',
			   'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation',
			   'dB_TX_Attenuation', 'dBm_TX_Power', 'Antenna',
			   'dB_AntSignal', 'dB_AntNoise', 'RXFlags', 'TXFlags',
			   'b17', 'b18', 'ChannelPlus', 'MCS', 'A_MPDU',
			   'VHT', 'timestamp', 'HE', 'HE_MU', 'HE_MU_other_user',
			   'zero_length_psdu', 'L_SIG', 'TLV',
			   'RadiotapNS', 'VendorNS', 'Ext']

rt_flags = [
	'CFP', 'Preamble', 'WEP', 'Fragmentation',
	'FCS', 'PAD', 'BadFCS', 'ShortGI' 
]

rt_channel_flags = [
	'700MHz', '800MHz', '900MHz', '', 'Turbo',
	'CCK', 'OFDM', '2GHz', '5GHz',
	'Passive', 'CCK-OFDM (Dynamic)', 'GFSK',
	'GSM', 'Static_Turbo', 'Half-Rate', 'Quarter-Rate'
]

@dataclass
class RT_CHANNEL:
	freq: int
	flags: list

# Формат: бит: (размер_в_байтах, выравнивание)
RT_FIELDS_SPEC = {
	0: (8, 8), # TSFT
	1: (1, 1), # FLAGS
	2: (1, 1), # RATE
	3: (4, 2), # CHANNEL
	4: (2, 2), # FHSS
	5: (1, 1), # DBM_ANTSIGNAL
	6: (1, 1), # DBM_ANTNOISE
	7: (2, 2), # LOCK_QUALITY
	8: (2, 2), # TX_ATTENUATION
	9: (2, 2), # DB_TX_ATTENUATION
	10: (1, 1), # DBM_TX_POWER
	11: (1, 1), # ANTENNA
	12: (1, 1), # DB_ANTSIGNAL
	13: (1, 1), # DB_ANTNOISE
	14: (2, 2), # RX_FLAGS
	15: (2, 2), # TX_FLAGS
	16: (1, 1), # RTS_RETRIES
	17: (1, 1), # DATA_RETRIES
	19: (3, 1), # MCS
	20: (8, 4), # AMPDU_STATUS
	21: (12, 2), # VHT
	22: (12, 8), # TIMESTAMP
}

presents = {}
if raw_ath[0:2] == b"\x00\x00":
	it_version, it_pad, it_len = struct.unpack_from('<BBH', raw_ath, 0)
	offset = 4
	ext = True
	presents_flags = []

	while (ext):
		it_present_Set = struct.unpack_from('<I', raw_ath, offset)[0]
		presents_flags.append(it_present_Set)
		ext = (it_present_Set & (1 << 31))
		offset += 4

	for it_present in presents_flags:
		for bit in range(32):
			if bit == 31: continue

			if it_present & (1 << bit):
					if bit in RT_FIELDS_SPEC:
						size, align = RT_FIELDS_SPEC[bit]
						offset = (offset + align -1) & ~(align - 1)
						present_data = raw_ath[offset : offset + size]
						if bit in [0, 11]:
							presents[rt_presents[bit]] = int.from_bytes(present_data, 'little')
						elif bit == 1:
							flags = []
							for flag_bit in range(8):
								if int.from_bytes(present_data, 'little') & (1 << flag_bit):
									flags.append(rt_flags[flag_bit])
								presents[rt_presents[bit]] = flags
						elif bit == 2:
							presents[rt_presents[bit]] = int.from_bytes(present_data, 'little') / 2
						elif bit == 3:
							freq = int.from_bytes(present_data[:2], 'little')
							channel_flags = []
							for channel_flags_bit in range(16):
								if (int.from_bytes(present_data[2:], 'little') & (1 << channel_flags_bit)):
									channel_flags.append(rt_channel_flags[channel_flags_bit])
							presents[rt_presents[bit]] = RT_CHANNEL(
								freq=freq,
								flags=channel_flags
							)
						elif bit == 5:
							presents[rt_presents[bit]] = int.from_bytes(present_data, 'little', signed=True)
						else:
							presents[rt_presents[bit]] = present_data
						offset += size
					else:
						break

presents = SimpleNamespace(**presents)
pprint.pprint(presents)
#if hasattr(presents, 'dBm_AntSignal'):
#	print(presents.dBm_AntSignal)
