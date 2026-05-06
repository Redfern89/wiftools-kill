from dataclasses import dataclass

# Формат: бит: (размер_в_байтах, выравнивание)
_rt_fields_specs = {
	0: (8, 8),   # TSFT
	1: (1, 1),   # FLAGS
	2: (1, 1),   # RATE
	3: (4, 2),   # CHANNEL
	4: (2, 2),   # FHSS
	5: (1, 1),   # DBM_ANTSIGNAL
	6: (1, 1),   # DBM_ANTNOISE
	7: (2, 2),   # LOCK_QUALITY
	8: (2, 2),   # TX_ATTENUATION
	9: (2, 2),   # DB_TX_ATTENUATION
	10: (1, 1),  # DBM_TX_POWER
	11: (1, 1),  # ANTENNA
	12: (1, 1),  # DB_ANTSIGNAL
	13: (1, 1),  # DB_ANTNOISE
	14: (2, 2),  # RX_FLAGS
	15: (2, 2),  # TX_FLAGS
	16: (1, 1),  # RTS_RETRIES
	17: (1, 1),  # DATA_RETRIES
	19: (3, 1),  # MCS
	20: (8, 4),  # AMPDU_STATUS
	21: (12, 2), # VHT
	22: (12, 8), # TIMESTAMP
}

_rt_presents = ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',
			   'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation',
			   'dB_TX_Attenuation', 'dBm_TX_Power', 'Antenna',
			   'dB_AntSignal', 'dB_AntNoise', 'RXFlags', 'TXFlags',
			   'b17', 'b18', 'ChannelPlus', 'MCS', 'A_MPDU',
			   'VHT', 'timestamp', 'HE', 'HE_MU', 'HE_MU_other_user',
			   'zero_length_psdu', 'L_SIG', 'TLV',
			   'RadiotapNS', 'VendorNS', 'Ext']

_rt_flags = [
	'CFP', 'Preamble', 'WEP', 'Fragmentation',
	'FCS', 'PAD', 'BadFCS', 'ShortGI' 
]

_rt_channel_flags = [
	'700MHz', '800MHz', '900MHz', '', 'Turbo',
	'CCK', 'OFDM', '2GHz', '5GHz',
	'Passive', 'CCK-OFDM (Dynamic)', 'GFSK',
	'GSM', 'Static_Turbo', 'Half-Rate', 'Quarter-Rate'
]

_rt_mcs_known = [
	'Bandwidth', 'Index', 'GI', 'Format',
	'FECType', 'STBCStreams', 'SpatialStreams'
]

_rt_mcs_common = {
	0: ("BPSK", "1/2"),
	1: ("QPSK", "1/2"),
	2: ("QPSK", "3/4"),
	3: ("16-QAM", "1/2"),
	4: ("16-QAM", "3/4"),
	5: ("64-QAM", "2/3"),
	6: ("64-QAM", "3/4"),
	7: ("64-QAM", "5/6"),
	8: ("256-QAM", "3/4"), # Начиная с VHT (ac)
	9: ("256-QAM", "5/6"), # Начиная с VHT (ac)
	10: ("1024-QAM", "3/4"), # Начиная с HE (ax)
	11: ("1024-QAM", "5/6"), # Начиная с HE (ax)
}

_rt_mcs_rates_20mhz = {
	# MCS: (Long_GI_Mbps, Short_GI_Mbps)
	0: (6.5, 7.2),
	1: (13.0, 14.4),
	2: (19.5, 21.7),
	3: (26.0, 28.9),
	4: (39.0, 43.3),
	5: (52.0, 57.8),
	6: (58.5, 65.0),
	7: (65.0, 72.2),
	8: (78.0, 86.7),
	9: (91.0, 101.1),
	10: (104.0, 115.6),
	11: (117.0, 130.0)
}

_rt_mcs_bw_multipler = {
	"20": 1,
	"40": 2.08,
	"80": 4.5,
	"160": 9.0
}

_dot11_fc_flags = [
	'to_ds', 'from_ds', 'MoreFrag', 'Retry',
	'PWRMgmt', 'MoreData', 'protected', 'Order'
]

_dot11_capabilities = [
	'ESS', 'IBSS', 'b2', 'b3', 
	'privacy', 'ShortPreamble', 'b6', 'b7',
	'Spectrum', 'QoS', 'ShortSlotTime', 'AutoPowerSave',
	'RadioMeasurment', 'EPD', 'b14', 'b15'
]

'''
	https://www.radiotap.org/fields/Channel.html
'''
_rt_freq_channels_2GHz = {
	2412: 1,
	2417: 2,
	2422: 3,
	2427: 4,
	2432: 5,
	2437: 6,
	2442: 7,
	2447: 8,
	2452: 9,
	2457: 10,
	2462: 11,
	2467: 12,
	2472: 13,
	2484: 14
}

_rt_freq_channels_5GHz = {
    # UNII-1 (Нижний диапазон)
    5180: 36,
    5200: 40,
    5220: 44,
    5240: 48,
    
    # UNII-2 (Middle + Extended)
    5260: 52,
    5280: 56,
    5300: 60,
    5320: 64,
    5500: 100,
    5520: 104,
    5540: 108,
    5560: 112,
    5580: 116,
    5600: 120,
    5620: 124,
    5640: 128,
    5660: 132,
    5680: 136,
    5700: 140,
    5720: 144,
    
    # UNII-3 (Верхний диапазон)
    5745: 149,
    5765: 153,
    5785: 157,
    5805: 161,
    5825: 165
}

_rt_all_channels = {**_rt_freq_channels_2GHz, **_rt_freq_channels_5GHz}

_dot11_tags = {
	0: 'SSID',
	1: 'SUPP_RATES',
	2: 'FH_PARAMETER',
	3: 'DS_PARAMETER',
	4: 'CF_PARAMETER',
	5: 'TIM',
	6: 'IBSS_PARAMETER',
	7: 'COUNTRY_INFO',
	8: 'FH_HOPPING_PARAMETER',
	9: 'FH_HOPPING_TABLE',
	10: 'REQUEST',
	11: 'QBSS_LOAD',
	12: 'EDCA_PARAM_SET',
	13: 'TSPEC',
	14: 'TCLAS',
	15: 'SCHEDULE',
	16: 'CHALLENGE_TEXT',
	32: 'POWER_CONSTRAINT',
	33: 'POWER_CAPABILITY',
	34: 'TPC_REQUEST',
	35: 'TPC_REPORT',
	36: 'SUPPORTED_CHANNELS',
	37: 'CHANNEL_SWITCH_ANN',
	38: 'MEASURE_REQ',
	39: 'MEASURE_REP',
	40: 'QUIET',
	41: 'IBSS_DFS',
	42: 'ERP_INFO',
	43: 'TS_DELAY',
	44: 'TCLAS_PROCESS',
	45: 'HT_CAPABILITY',
	46: 'QOS_CAPABILITY',
	47: 'ERP_INFO_OLD',
	48: 'RSN_IE',
	50: 'EXT_SUPP_RATES',
	51: 'AP_CHANNEL_REPORT',
	52: 'NEIGHBOR_REPORT',
	53: 'RCPI',
	54: 'MOBILITY_DOMAIN',
	55: 'FAST_BSS_TRANSITION',
	56: 'TIMEOUT_INTERVAL',
	57: 'RIC_DATA',
	58: 'DSE_REG_LOCATION',
	59: 'SUPPORTED_OPERATING_CLASSES',
	60: 'EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT',
	61: 'HT_OPERATION',
	62: 'SECONDARY_CHANNEL_OFFSET',
	63: 'BSS_AVG_ACCESS_DELAY',
	64: 'ANTENNA',
	65: 'RSNI',
	66: 'MEASURE_PILOT_TRANS',
	67: 'BSS_AVB_ADM_CAPACITY',
	68: 'IE_68_CONFLICT',
	68: 'WAPI_PARAM_SET',
	68: 'BSS_AC_ACCESS_DELAY',
	69: 'TIME_ADV',
	70: 'RM_ENABLED_CAPABILITY',
	71: 'MULTIPLE_BSSID',
	72: '20_40_BSS_CO_EX',
	73: '20_40_BSS_INTOL_CH_REP',
	74: 'OVERLAP_BSS_SCAN_PAR',
	75: 'RIC_DESCRIPTOR',
	76: 'MMIE',
	78: 'EVENT_REQUEST',
	79: 'EVENT_REPORT',
	80: 'DIAGNOSTIC_REQUEST',
	81: 'DIAGNOSTIC_REPORT',
	82: 'LOCATION_PARAMETERS',
	83: 'NO_BSSID_CAPABILITY',
	84: 'SSID_LIST',
	85: 'MULTIPLE_BSSID_INDEX',
	86: 'FMS_DESCRIPTOR',
	87: 'FMS_REQUEST',
	88: 'FMS_RESPONSE',
	89: 'QOS_TRAFFIC_CAPABILITY',
	90: 'BSS_MAX_IDLE_PERIOD',
	91: 'TFS_REQUEST',
	92: 'TFS_RESPONSE',
	93: 'WNM_SLEEP_MODE',
	94: 'TIM_BROADCAST_REQUEST',
	95: 'TIM_BROADCAST_RESPONSE',
	96: 'COLLOCATED_INTER_REPORT',
	97: 'CHANNEL_USAGE',
	98: 'TIME_ZONE',
	99: 'DMS_REQUEST',
	100: 'DMS_RESPONSE',
	101: 'LINK_IDENTIFIER',
	102: 'WAKEUP_SCHEDULE',
	104: 'CHANNEL_SWITCH_TIMING',
	105: 'PTI_CONTROL',
	106: 'PU_BUFFER_STATUS',
	107: 'INTERWORKING',
	108: 'ADVERTISEMENT_PROTOCOL',
	109: 'EXPIDITED_BANDWIDTH_REQ',
	110: 'QOS_MAP_SET',
	111: 'ROAMING_CONSORTIUM',
	112: 'EMERGENCY_ALERT_ID',
	113: 'MESH_CONFIGURATION',
	114: 'MESH_ID',
	115: 'MESH_LINK_METRIC_REPORT',
	116: 'CONGESTION_NOTIFICATION',
	117: 'MESH_PEERING_MGMT',
	118: 'MESH_CHANNEL_SWITCH',
	119: 'MESH_AWAKE_WINDOW',
	120: 'BEACON_TIMING',
	121: 'MCCAOP_SETUP_REQUEST',
	122: 'MCCAOP_SETUP_REPLY',
	123: 'MCCAOP_ADVERTISEMENT',
	124: 'MCCAOP_TEARDOWN',
	125: 'GANN',
	126: 'RANN',
	127: 'EXTENDED_CAPABILITIES',
	128: 'AGERE_PROPRIETARY',
	130: 'MESH_PREQ',
	131: 'MESH_PREP',
	132: 'MESH_PERR',
	133: 'CISCO_CCX1_CKIP',
	136: 'CISCO_CCX2',
	137: 'PXU',
	138: 'PXUC',
	139: 'AUTH_MESH_PEERING_EXCH',
	140: 'MIC',
	141: 'DESTINATION_URI',
	142: 'U_APSD_COEX',
	143: 'WAKEUP_SCHEDULE_AD',
	144: 'EXTENDED_SCHEDULE',
	145: 'STA_AVAILABILITY',
	146: 'DMG_TSPEC',
	147: 'NEXT_DMG_ATI',
	148: 'DMG_CAPABILITIES',
	149: 'CISCO_CCX3',
	150: 'CISCO_VENDOR_SPECIFIC',
	151: 'DMG_OPERATION',
	152: 'DMG_BSS_PARAMETER_CHANGE',
	153: 'DMG_BEAM_REFINEMENT',
	154: 'CHANNEL_MEASURMENT_FB',
	157: 'AWAKE_WINDOW',
	158: 'MULTI_BAND',
	159: 'ADDBA_EXT',
	160: 'NEXTPCP_LIST',
	161: 'PCP_HANDOVER',
	162: 'DMG_LINK_MARGIN',
	163: 'SWITCHING_STREAM',
	164: 'SESSION_TRANSMISSION',
	165: 'DYN_TONE_PAIR_REP',
	166: 'CLUSTER_REP',
	167: 'RELAY_CAPABILITIES',
	168: 'RELAY_TRANSFER_PARAM',
	169: 'BEAMLINK_MAINTENANCE',
	170: 'MULTIPLE_MAC_SUBLAYERS',
	171: 'U_PID',
	172: 'DMG_LINK_ADAPTION_ACK',
	173: 'SYMBOL_PROPRIETARY',
	174: 'MCCAOP_ADVERTISEMENT_OV',
	175: 'QUIET_PERIOD_REQ',
	177: 'QUIET_PERIOD_RES',
	182: 'ECAPC_POLICY',
	183: 'CLUSTER_TIME_OFFSET',
	184: 'INTRA_ACCESS_CAT_PRIO',
	185: 'SCS_DESCRIPTOR',
	190: 'ANTENNA_SECTOR_ID',
	191: 'VHT_CAPABILITY',
	192: 'VHT_OPERATION',
	193: 'EXT_BSS_LOAD',
	194: 'WIDE_BW_CHANNEL_SWITCH',
	195: 'TX_PWR_ENVELOPE',
	196: 'CHANNEL_SWITCH_WRAPPER',
	199: 'OPERATING_MODE_NOTIFICATION',
	201: 'REDUCED_NEIGHBOR_REPORT',
	206: 'FINE_TIME_MEASUREMENT_PARAM',
	207: 'S1G_OPEN_LOOP_LINK_MARGIN_INDEX',
	208: 'RPS',
	209: 'PAGE_SLICE',
	210: 'AID_REQUEST',
	211: 'AID_RESPONSE',
	212: 'S1G_SECTOR_OPERATION',
	213: 'S1G_BEACON_COMPATIBILITY',
	214: 'SHORT_BEACON_INTERVAL',
	215: 'CHANGE_SEQUENCE',
	216: 'TWT',
	217: 'S1G_CAPABILITIES',
	220: 'SUBCHANNEL_SELECTIVE_TRANSMISSION',
	221: 'VENDOR_SPECIFIC_IE',
	222: 'AUTHENTICATION_CONTROL',
	223: 'TSF_TIMER_ACCURACY',
	224: 'S1G_RELAY',
	225: 'REACHABLE_ADDRESS',
	226: 'S1G_RELAY_DISCOVERY',
	228: 'AID_ANNOUNCEMENT',
	229: 'PV1_PROBE_RESPONSE_OPTION',
	230: 'EL_OPERATION',
	231: 'SECTORIZED_GROUP_ID_LIST',
	232: 'S1G_OPERATION',
	233: 'HEADER_COMPRESSION',
	234: 'SST_OPERATION',
	235: 'MAD',
	236: 'S1G_RELAY_ACTIVATION',
	237: 'CAG_NUMBER',
	239: 'AP_CSN',
	240: 'FILS_INDICATION',
	241: 'DIFF_INITIAL_LINK_SETUP',
	242: 'FRAGMENT',
	244: 'RSNX',
	255: 'ELEMENT_ID_EXTENSION'
}

_dot11_wps_tlv_names = {
	0x1001: 'AP_CHANNEL',
	0x1002: 'ASSOCIATION_STATE',
	0x1003: 'AUTHENTICATION_TYPE',
	0x1004: 'AUTHENTICATION_TYPE_FLAGS',
	0x1005: 'AUTHENTICATOR',
	0x1008: 'CONFIG_METHODS',
	0x1009: 'CONFIGURATION_ERROR',
	0x100a: 'CONFIRMATION_URL4',
	0x100b: 'CONFIRMATION_URL6',
	0x100c: 'CONNECTION_TYPE',
	0x100d: 'CONNECTION_TYPE_FLAGS',
	0x100e: 'CREDENTIAL',
	0x1011: 'DEVICE_NAME',
	0x1012: 'DEVICE_PASSWORD_ID',
	0x1015: 'E_HASH2',
	0x1016: 'E_SNONCE1',
	0x1017: 'E_SNONCE2',
	0x1018: 'ENCRYPTED_SETTINGS',
	0x100f: 'ENCRYPTION_TYPE',
	0x1010: 'ENCRYPTION_TYPE_FLAGS',
	0x101a: 'ENROLLEE_NONCE',
	0x101b: 'FEATURE_ID',
	0x101c: 'IDENTITY',
	0x101d: 'IDENTITY_PROOF',
	0x101e: 'KEY_WRAP_AUTHENTICATOR',
	0x101f: 'KEY_IDENTIFIER',
	0x1020: 'MAC_ADDRESS',
	0x1021: 'MANUFACTURER',
	0x1022: 'MESSAGE_TYPE',
	0x1023: 'MODEL_NAME',
	0x1024: 'MODEL_NUMBER',
	0x1026: 'NETWORK_INDEX',
	0x1027: 'NETWORK_KEY',
	0x1028: 'NETWORK_KEY_INDEX',
	0x1029: 'NEW_DEVICE_NAME',
	0x102a: 'NEW_PASSWORD',
	0x102c: 'OOB_DEVICE_PASSWORD',
	0x102d: 'OS_VERSION',
	0x102f: 'POWER_LEVEL',
	0x1030: 'PSK_CURRENT',
	0x1031: 'PSK_MAX',
	0x1032: 'PUBLIC_KEY',
	0x1033: 'RADIO_ENABLED',
	0x1034: 'REBOOT',
	0x1035: 'REGISTRAR_CURRENT',
	0x1036: 'REGISTRAR_ESTABLISHED',
	0x1037: 'REGISTRAR_LIST',
	0x1038: 'REGISTRAR_MAX',
	0x1039: 'REGISTRAR_NONCE',
	0x103a: 'REQUEST_TYPE',
	0x103b: 'RESPONSE_TYPE',
	0x103c: 'RF_BANDS',
	0x103d: 'R_HASH1',
	0x103e: 'R_HASH2',
	0x103f: 'R_SNONCE1',
	0x1040: 'R_SNONCE2',
	0x1041: 'SELECTED_REGISTRAR',
	0x1042: 'SERIAL_NUMBER',
	0x1044: 'WIFI_PROTECTED_SETUP_STATE',
	0x1045: 'SSID',
	0x1046: 'TOTAL_NETWORKS',
	0x1047: 'UUID_E',
	0x1048: 'UUID_R',
	0x1049: 'VENDOR_EXTENSION',
	0x104a: 'VERSION',
	0x104b: 'X509_CERTIFICATE_REQUEST',
	0x104c: 'X509_CERTIFICATE',
	0x104d: 'EAP_IDENTITY',
	0x104e: 'MESSAGE_COUNTER',
	0x104f: 'PUBLIC_KEY_HASH',
	0x1050: 'REKEY_KEY',
	0x1051: 'KEY_LIFETIME',
	0x1052: 'PERMITTED_CONFIG_METHODS',
	0x1053: 'SELECTED_REGISTRAR_CONFIG_METHODS',
	0x1054: 'PRIMARY_DEVICE_TYPE',
	0x1055: 'SECONDARY_DEVICE_TYPE_LIST',
	0x1056: 'PORTABLE_DEVICE',
	0x1057: 'AP_SETUP_LOCKED',
	0x1058: 'APPLICATION_EXTENSION',
	0x1059: 'EAP_TYPE',
	0x1060: 'INITIALIZATION_VECTOR',
	0x1061: 'KEY_PROVIDED_AUTOMATICALLY',
	0x1062: '8021X_ENABLED',
	0x1063: 'APPSESSIONKEY',
	0x1064: 'WEPTRANSMITKEY',
	0x106a: 'REQUESTED_DEV_TYPE'
}

_dot11_wps_config_methods_flags = [
	'USB', 'Ethernet', 'Label', 'Display',
	'ExtNFC', 'IntNFC', 'NFCInterface', 'PushButton',
	'Keypad', 'VirtualPushButton', 'PhyPushButton', 'b11',
	'b12', 'VirtualDisplay', 'PhyDisplay', 'b16'
]


rsn_cipher_suites = {
	0x00: "Group",
	0x01: "WEP-40",
	0x02: "TKIP",
	0x03: "WRAP",
	0x04: "CCMP",
	0x05: "WEP-104",
	0x06: "BIP",
	0x07: "CMAC-128",
	0x08: "GCMP-128",
	0x09: "GCMP-256",
	0x0A: "BIP-GMAC-128",
	0x0B: "BIP-GMAC-256",
	0x0C: "BIP-CMAC-128",
	0x0D: "BIP-CMAC-256"
}

rsn_akm_suites = {
	0x01: "802.1X (RSNA)",
	0x02: "PSK",
	0x03: "802.1X-FT (Fast Transition)",
	0x04: "PSK-FT",
	0x05: "802.1X-PMKSA (PMSK)",
	0x06: "802.1X-PSK",
	0x07: "802.1X-TDLS",
	0x08: "SAE",
	0x09: "SAE-FT",
	0x0A: "PSK-SHA256",
	0x0B: "802.1X-SHA256",
	0x0C: "SAE-SHA384 (WPA3-Enterprise 192-bit)",
	0x0D: "802.1X-FT-SHA384"
}


_dot11_fc_management_types = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0]
_dot11_fc_control_types    = [0x44, 0x54, 0x64, 0x74, 0x84, 0x94, 0xA4, 0xB4, 0xC4, 0xD4, 0xE4, 0xF4]
_dot11_fc_data_types       = [0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78]
_dot11_fc_qos_data_types   = [0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8]

_dot11_addr2_candidates = [
	# Management
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 
	# Control
	0x44, 0x74, 0xA4, 0xB4, 0x84, 0x94,
	# Data
	0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8
]
_dot11_addr3_candidates = [
	# Management
	0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
	# Data
	0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xE8, 0xF8
]

_dot11_wps_wfa = [
	'VERSION2', 'AUTHORIZEDMACS', 'NETWORK_KEY_SHAREABLE', 'REQUEST_TO_ENROLL', 
	'SETTINGS_DELAY_TIME', 'REG_CFG_METHODS', 'MULTI_AP', 'MULTI_AP_PROFILE', 'MULTI_AP_8021Q', 	
]

_dot11_vendor_specific_types = {
	0: 'Unknown',
	1: 'WPA', 
	2: 'WMM_WME', 
	4: 'WPS', 
	17: 'Net_Cost', 
	18: 'Tethering'
}

_dot11_eapol_types = [
	'EAP', 'START', 'LOGOFF', 'KEY', 'ENCAP_ASF_ALERT', 'MKA', 'ANNOUNCEMENT_GENERIC', 'ANNOUNCEMENT_SPECIFIC', 'ANNOUNCEMENT_REQUEST'
]

'''
	RFC 3748
	  ╰─> 4. EAP Packet Format
'''
_dot11_eap_status_codes = {
	1: 'Request',
	2: 'Response',
	3: 'Success',
	4: 'Failure'
}
'''
	RFC 3748
	  ╰─> 5. Initial EAP Request/Response Types
'''
_dot11_eap_type_codes = {
	1:   'Identity',
	2:   'Notification',
	3:   'Nak',
	4:   'MD5-Challenge',
	5:   'OTP',
	6:   'GTC',
	13:  'EAP-TLS',
	18:  'EAP-SIM',
	21:  'EAP-TTLS',
	23:  'EAP-AKA',
	25:  'PEAP',
	43:  'EAP-FAST',
	254: 'Expanded',
	255: 'Experimental'
}

_dot11_eap_tlv_struct = {
	0x1001: 'AP_CHANNEL',                         # AP Channel
	0x1002: 'ASSOCIATION_STATE',                  # Association State
	0x1003: 'AUTHENTICATION_TYPE',                # Authentication Type
	0x1004: 'AUTHENTICATION_TYPE_FLAGS',          # Authentication Type Flags
	0x1005: 'AUTHENTICATOR',                      # Authenticator
	0x1008: 'CONFIG_METHODS',                     # Config Methods
	0x1009: 'CONFIGURATION_ERROR',                # Configuration Error
	0x100a: 'CONFIRMATION_URL4',                  # Confirmation URL4
	0x100b: 'CONFIRMATION_URL6',                  # Confirmation URL6
	0x100c: 'CONNECTION_TYPE',                    # Connection Type
	0x100d: 'CONNECTION_TYPE_FLAGS',              # Connection Type Flags
	0x100e: 'CREDENTIAL',                         # Credential
	0x1011: 'DEVICE_NAME',                        # Device Name
	0x1012: 'DEVICE_PASSWORD_ID',                 # Device Password ID
	0x1014: 'E_HASH1',                            # E Hash1
	0x1015: 'E_HASH2',                            # E Hash2
	0x1016: 'E_SNONCE1',                          # E SNonce1
	0x1017: 'E_SNONCE2',                          # E SNonce2
	0x1018: 'ENCRYPTED_SETTINGS',                 # Encrypted Settings
	0x100f: 'ENCRYPTION_TYPE',                    # Encryption Type
	0x1010: 'ENCRYPTION_TYPE_FLAGS',              # Encryption Type Flags
	0x101a: 'ENROLLEE_NONCE',                     # Enrollee Nonce
	0x101b: 'FEATURE_ID',                         # Feature Id
	0x101c: 'IDENTITY',                           # Identity
	0x101d: 'IDENTITY_PROOF',                     # Identity Proof
	0x101e: 'KEY_WRAP_AUTHENTICATOR',             # Key Wrap Authenticator
	0x101f: 'KEY_IDENTIFIER',                     # Key Identifier
	0x1020: 'MAC_ADDRESS',                        # MAC Address
	0x1021: 'MANUFACTURER',                       # Manufacturer
	0x1022: 'MESSAGE_TYPE',                       # Message Type
	0x1023: 'MODEL_NAME',                         # Model Name
	0x1024: 'MODEL_NUMBER',                       # Model Number
	0x1026: 'NETWORK_INDEX',                      # Network Index
	0x1027: 'NETWORK_KEY',                        # Network Key
	0x1028: 'NETWORK_KEY_INDEX',                  # Network Key Index
	0x1029: 'NEW_DEVICE_NAME',                    # New Device Name
	0x102a: 'NEW_PASSWORD',                       # New Password
	0x102c: 'OOB_DEVICE_PASSWORD',                # OOB Device Password
	0x102d: 'OS_VERSION',                         # OS Version
	0x102f: 'POWER_LEVEL',                        # Power Level
	0x1030: 'PSK_CURRENT',                        # PSK Current
	0x1031: 'PSK_MAX',                            # PSK Max
	0x1032: 'PUBLIC_KEY',                         # Public Key
	0x1033: 'RADIO_ENABLED',                      # Radio Enabled
	0x1034: 'REBOOT',                             # Reboot
	0x1035: 'REGISTRAR_CURRENT',                  # Registrar Current
	0x1036: 'REGISTRAR_ESTABLISHED',              # Registrar Established
	0x1037: 'REGISTRAR_LIST',                     # Registrar List
	0x1038: 'REGISTRAR_MAX',                      # Registrar Max
	0x1039: 'REGISTRAR_NONCE',                    # Registrar Nonce
	0x103a: 'REQUEST_TYPE',                       # Request Type
	0x103b: 'RESPONSE_TYPE',                      # Response Type
	0x103c: 'RF_BANDS',                           # RF Bands
	0x103d: 'R_HASH1',                            # R Hash1
	0x103e: 'R_HASH2',                            # R Hash2
	0x103f: 'R_SNONCE1',                          # R Snonce1
	0x1040: 'R_SNONCE2',                          # R Snonce2
	0x1041: 'SELECTED_REGISTRAR',                 # Selected Registrar
	0x1042: 'SERIAL_NUMBER',                      # Serial Number
	0x1044: 'WIFI_PROTECTED_SETUP_STATE',         # Wifi Protected Setup State
	0x1045: 'SSID',                               # SSID
	0x1046: 'TOTAL_NETWORKS',                     # Total Networks
	0x1047: 'UUID_E',                             # UUID E
	0x1048: 'UUID_R',                             # UUID R
	0x1049: 'VENDOR_EXTENSION',                   # Vendor Extension
	0x104a: 'VERSION',                            # Version
	0x104b: 'X509_CERTIFICATE_REQUEST',           # X509 Certificate Request
	0x104c: 'X509_CERTIFICATE',                   # X509 Certificate
	0x104d: 'EAP_IDENTITY',                       # EAP Identity
	0x104e: 'MESSAGE_COUNTER',                    # Message Counter
	0x104f: 'PUBLIC_KEY_HASH',                    # Public Key Hash
	0x1050: 'REKEY_KEY',                          # Rekey Key
	0x1051: 'KEY_LIFETIME',                       # Key Lifetime
	0x1052: 'PERMITTED_CONFIG_METHODS',           # Permitted Config Methods
	0x1053: 'SELECTED_REGISTRAR_CONFIG_METHODS',  # Selected Registrar Config Methods
	0x1054: 'PRIMARY_DEVICE_TYPE',                # Primary Device Type
	0x1055: 'SECONDARY_DEVICE_TYPE_LIST',         # Secondary Device Type List
	0x1056: 'PORTABLE_DEVICE',                    # Portable Device
	0x1057: 'AP_SETUP_LOCKED',                    # Ap Setup Locked
	0x1058: 'APPLICATION_EXTENSION',              # Application Extension
	0x1059: 'EAP_TYPE',                           # EAP Type
	0x1060: 'INITIALIZATION_VECTOR',              # Initialization Vector
	0x1061: 'KEY_PROVIDED_AUTOMATICALLY',         # Key Provided Automatically
	0x1062: '8021X_ENABLED',                      # 8021x Enabled
	0x1063: 'APPSESSIONKEY',                      # AppSessionKey
	0x1064: 'WEPTRANSMITKEY',                     # WEPTransmitKey
	0x106a: 'REQUESTED_DEV_TYPE'                  # Requested Device Type
}

arp_opcodes = {
	1: "Request",
	2: "Reply",
	3: "PARP_Request",
	4: "PARP_Reply",
	8: "InARP_Request",
	9: "InARP_Reply"
}

iface_types = {
	0: 'Unknown',
	1: 'Station',
	802: 'Ad-Hoc',
	803: 'Monitor',
	804: 'Mesh (802.11s)',
	805: 'P2P (Direct GO)',
	806: 'P2P Client'
}

@dataclass
class ID_NAME:
	id: int
	name: str

@dataclass
class RADIOTAP:
	it_version: int
	it_pad: int
	it_len: int
	presents: any

@dataclass
class RT_PRESENT:
	bit: int
	name: str
	value: any

@dataclass
class RT_CHANNEL:
	freq: int
	channel: int
	flags: list

@dataclass
class RT_MCS_DECODED:
    modulation: str    # "64-QAM"
    coding_rate: str   # "5/6"
    streams: int       # 2 (для MIMO 2x2)
    gi_ns: int         # 400 (наносекунды)
    rate: float        # 144.4 (Мбит/с)

@dataclass
class RT_MCS:
	known: list
	bandwidth: str
	shortGI: bool
	format: str
	index: int
	decoded: RT_MCS_DECODED

@dataclass
class DOT11_FC:
	type: int
	subtype: int
	type_subtype: int
	flags: list

@dataclass
class DOT11_ADDRS:
	addr1: any
	addr2: any
	addr3: any
	addr4: any

@dataclass
class DOT11_FRAG_SEQ:
	frag: int
	seq: int

@dataclass
class DOT11_PROTECTED_DATA:
	QoS_Control: any
	CIPHER_IV: any
	Data: any
	size: int

@dataclass
class DOT11_CIPHER_IV:
	type: str
	iv: any

@dataclass
class DOT11:
	fc: DOT11_FC
	duration: int
	addrs: DOT11_ADDRS
	fragseq: DOT11_FRAG_SEQ

@dataclass
class DOT11_FIXED_PARAMETERS_12B:
	timestamp: int
	intereval: float
	capabilities: list

@dataclass
class DOT11_ELT_IE:
	tag_len: int
	tag_type: ID_NAME
	info: any

@dataclass
class DOT11_VENDOR_SPECIFIC:
	oui: str
	type: int
	info: any

@dataclass
class DOT11_WPS_IE:
	tag_len: int
	tag_type: ID_NAME
	info: any

@dataclass
class DOT11_WPS_VENDOR_EXTENSION:
	vendor_extension: any
	vendor_id: int
	tags: list

@dataclass
class suite_field:
	type: ID_NAME
	oui: str

@dataclass
class RSN_IE:
	version: int
	group_cipher: suite_field
	pair_cnt: int
	pair_suites: list
	akm_cnt: int
	akm_suites: list
	#rsn_capabilities: int
	#pmk_id_count: int
	#pmk_id_list: any
	#group_management_cipher: any

@dataclass
class WPA_IE:
	version: int
	multicast_suite: suite_field
	unicast_cnt: int
	unicast_suites: list
	akm_cnt: 1
	akm_suites: list

@dataclass
class DOT11_SUPPORTED_RATE:
	rate: float
	basic: bool

@dataclass
class DOT11_LLC:
	DSAP: int
	SSAP: int
	CTRL: int
	OUI: str
	type: int

@dataclass
class DOT11_EAPOL:
	llc: DOT11_LLC
	version: int
	type: ID_NAME
	length: int
	data: any

@dataclass
class DOT11_EAPOL_RSN:
	key_desc: int
	key_info: any
	key_len: int
	replay_counter: int
	wpa_nonce: any
	key_iv: any
	wpa_key_rsc: any
	wpa_key_id: any
	wpa_key_mic: any
	wpa_key_data_len: int
	wpa_key_data: any

@dataclass
class DOT11_EAP:
	code: ID_NAME
	id: int
	length: int
	type: ID_NAME
	packet: any

@dataclass
class PHYMode:
	type: int
	mode: str