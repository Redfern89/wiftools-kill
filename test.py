#!/usr/bin/env python3

import struct
from dataclasses import dataclass
from types import SimpleNamespace

__rt_presents = ['TSFT', 'Flags', 'Rate', 'Channel', 'FHSS', 'dBm_AntSignal',
			   'dBm_AntNoise', 'Lock_Quality', 'TX_Attenuation',
			   'dB_TX_Attenuation', 'dBm_TX_Power', 'Antenna',
			   'dB_AntSignal', 'dB_AntNoise', 'RXFlags', 'TXFlags',
			   'b17', 'b18', 'ChannelPlus', 'MCS', 'A_MPDU',
			   'VHT', 'timestamp', 'HE', 'HE_MU', 'HE_MU_other_user',
			   'zero_length_psdu', 'L_SIG', 'TLV',
			   'RadiotapNS', 'VendorNS', 'Ext']

__rt_flags = [
	'CFP', 'Preamble', 'WEP', 'Fragmentation',
	'FCS', 'PAD', 'BadFCS', 'ShortGI' 
]

__rt_channel_flags = [
	'700MHz', '800MHz', '900MHz', '', 'Turbo',
	'CCK', 'OFDM', '2GHz', '5GHz',
	'Passive', 'CCK-OFDM (Dynamic)', 'GFSK',
	'GSM', 'Static_Turbo', 'Half-Rate', 'Quarter-Rate'
]

__rt_mcs_known = [
	'Bandwidth', 'Index', 'GI', 'Format',
	'FECType', 'STBCStreams', 'SpatialStreams'
]


_dot11_fc_flags = [
	'to_ds', 'from_ds', 'MoreFrag', 'Retry',
	'PWRMgmt', 'MoreData', 'protected', 'Order'
]

_dot11_beacon_capabilities = [
	'ESS', 'IBSS', 'b2', 'b3', 
	'privacy', 'ShortPreamble', 'b6', 'b7',
	'Spectrum', 'QoS', 'ShortSlotTime', 'AutoPowerSave',
	'RadioMeasurment', 'EPD', 'b14', 'b15'
]

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


MS_OUI = b'\x00\x50\xf2'

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
class RT_CHANNEL:
	freq: int
	flags: list

@dataclass
class RT_MCS:
	known: list
	bandwidth: str
	shortGI: bool
	format: str
	index: int

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
	rsn_capabilities: int
	pmk_id_count: int
	pmk_id_list: any
	group_management_cipher: any

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

# Формат: бит: (размер_в_байтах, выравнивание)
RT_FIELDS_SPEC = {
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

def RadioTap(pkt):
	if pkt[0:2] == b"\x00\x00":
		it_version, it_pad, it_len = struct.unpack_from('<BBH', pkt, 0)
		offset = 4
		ext = True
		presents = {}
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
						if bit in RT_FIELDS_SPEC:
							size, align = RT_FIELDS_SPEC[bit]
							offset = (offset + align -1) & ~(align - 1)
							present_data = pkt[offset : offset + size]
							if bit in [0, 11]:
								presents[__rt_presents[bit]] = int.from_bytes(present_data, 'little')
							elif bit == 1:
								flags = []
								for flag_bit in range(8):
									if int.from_bytes(present_data, 'little') & (1 << flag_bit):
										flags.append(__rt_flags[flag_bit])
									presents[__rt_presents[bit]] = flags
							elif bit == 2:
								presents[__rt_presents[bit]] = int.from_bytes(present_data, 'little') / 2
							elif bit == 3:
								freq = int.from_bytes(present_data[:2], 'little')
								channel_flags = []
								for channel_flags_bit in range(16):
									if (int.from_bytes(present_data[2:], 'little') & (1 << channel_flags_bit)):
										channel_flags.append(__rt_channel_flags[channel_flags_bit])
								presents[__rt_presents[bit]] = RT_CHANNEL(
									freq=freq,
									flags=channel_flags
								)
							elif bit == 5:
								presents[__rt_presents[bit]] = int.from_bytes(present_data, 'little', signed=True)
							elif bit == 19:
								mcs_known, mcs_flags, mcs_index = struct.unpack_from('<BBB', present_data)
								mcs_knowns = []
								for mcs_known_bit in range(8):
									if mcs_known & (1 << mcs_known_bit):
										mcs_knowns.append(__rt_mcs_known[mcs_known_bit])

								if mcs_known & 0x01:
									bw_val = mcs_flags & 0x03
									bandwidth = {0: '20', 1: '40', 2: '20L', 3: '20U'}.get(bw_val, 'unk')
								
								if mcs_known & 0x02:
									shortGI = bool(mcs_flags & 0x04)

								if mcs_known & 0x04:
									format = 'Greenfield' if (mcs_flags & 0x08) else 'Mixed'
								
								presents[__rt_presents[bit]] = RT_MCS(
									known=mcs_knowns,
									bandwidth=bandwidth,
									shortGI=shortGI,
									format=format,
									index=mcs_index
								)
							else:
								presents[__rt_presents[bit]] = present_data
							offset += size
						else:
							break

		presents = SimpleNamespace(**presents)
		return RADIOTAP(
			it_version=it_version,
			it_pad=it_pad,
			it_len=it_len,
			presents=presents
		)
	return None

class Dot11_L2:
	def __init__(self, radiotap, pkt):
		self.radiotap = radiotap
		self.pkt = pkt[self.radiotap.it_len:]
		self.fc = self.Dot11FC()
		self.offset = 0
		self.addrs = self.dot11Addrs()

	def mac2str(self, mac):
		return ':'.join(f'{b:02X}' for b in mac)

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
		addr1 = self.mac2str(self.pkt[4:10])
		self.offset = 10
		addr2 = None
		addr3 = None
		addr4 = None

		if self.fc.type_subtype in _dot11_addr2_candidates:
			addr2 = self.mac2str(self.pkt[10:16])
			self.offset = 16
		if self.fc.type_subtype in _dot11_addr3_candidates:
			addr3 = self.mac2str(self.pkt[16:22])
			self.offset = 22
		
		if 'to_ds' in self.fc.flags and 'from_ds' in self.fc.flags:
			addr4 = self.mac2str(self.pkt[22:28])
			self.offset = 28
		
		return DOT11_ADDRS(
			addr1=addr1,
			addr2=addr2,
			addr3=addr3,
			addr4=addr4
		)
	
	def dot11FragSeq(self):
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
			fragseq=self.dot11FragSeq()
		)
	

	def dot11ProtectedData(self):
		if self.fc.type_subtype in _dot11_fc_data_types or \
			self.fc.type_subtype in _dot11_fc_qos_data_types:

			if 'protected' not in self.fc.flags:
				return None

			offset = 24 # skip FC, Duration, addrs, frag_seq
			cipher_iv = None
			cipher_type = None
			
			if self.fc.type_subtype in _dot11_fc_qos_data_types:
				qos_control_iv = struct.unpack_from('<H', self.pkt, offset)[0]
				offset += 2

			if 'protected' in self.fc.flags:
				iv = self.pkt[offset:offset+8]
				if iv[3] & 0x20:
					if iv[1] == ((iv[0] | 0x20) & 0x7f):
						cipher_iv = iv
						cipher_type = 'TKIP'
					elif iv[2] == 0x00:
						cipher_iv = iv
						cipher_type = 'CCMP'
					else:
						cipher_iv = iv[:4]
						cipher_type = 'WEP'
				offset += 8

			return DOT11_PROTECTED_DATA(
				QoS_Control=qos_control_iv,
				CIPHER_IV=DOT11_CIPHER_IV(
					type=cipher_type,
					iv=cipher_iv
				),
				Data=self.pkt[offset:],
				size=len(self.pkt[offset:])
			)

	def Dot11FixedParams12b(self):
		if self.fc.type_subtype in [0x50, 0x80]:
			offset = 24 # Skip Dot11 header
			ts, interval, cap = struct.unpack_from('<QHH', self.pkt, offset)
			capabilities = []

			for beacon_cap_bit in range(16):
				if cap & (1 << beacon_cap_bit):
					capabilities.append(_dot11_beacon_capabilities[beacon_cap_bit])
			
			return DOT11_FIXED_PARAMETERS_12B(
				timestamp=ts,
				intereval=interval,
				capabilities=capabilities
			)

		return None
	
	def _dot11decode_default(self, data):
		return data

	def _dot11ssid(self, data):
		return data.decode('utf-8', errors='ignore')
	
	def _dot11_decode_str(self, data):
		return data.decode('utf-8', errors='ignore')
	
	def _dot11_wps_config_methods(self, data):
		data = int.from_bytes(data, 'big')
		result = []

		for bit in range(16):
			if data & (1 << bit):
				result.append(_dot11_wps_config_methods_flags[bit])

		return result
	
	def _dot11_wps_vendor_extension(self, data):
		wps_vendor_extension_tlv_data = data[3:]
		wps_vendor_extension_tlv_data_len = len(wps_vendor_extension_tlv_data)
		offset = 0
		tags = []

		while (offset +2 <= wps_vendor_extension_tlv_data_len):
			TAG_ID   = wps_vendor_extension_tlv_data[offset]
			TAG_LEN  = wps_vendor_extension_tlv_data[offset +1]
			TAG_INFO = wps_vendor_extension_tlv_data[offset +2:offset+2+TAG_LEN]
			
			if TAG_LEN >= wps_vendor_extension_tlv_data_len:
				break
			
			tags.append(DOT11_WPS_IE(
				tag_len=TAG_LEN,
				tag_type=ID_NAME(
					id=TAG_ID,
					name=_dot11_wps_wfa[TAG_ID]
				),
				info=TAG_INFO
			))

			offset += 2 + TAG_LEN

		return DOT11_WPS_VENDOR_EXTENSION(
			vendor_extension=data,
			vendor_id=int.from_bytes(data[:3], 'big'),
			tags=tags
		)
	
	def _dot11WPS(self, data):
		offset = 0
		size   = len(data)
		result = []

		handlers = {
			0x1021: self._dot11_decode_str, 
			0x1023: self._dot11_decode_str,
			0x1024: self._dot11_decode_str,
			0x1042: self._dot11_decode_str,
			0x1011: self._dot11_decode_str,
			0x1008: self._dot11_wps_config_methods,
			0x1049: self._dot11_wps_vendor_extension
		}

		while (offset + 4 <= size):
			TAG_ID   = struct.unpack_from('>H', data[offset:offset+2])[0]
			TAG_LEN  = struct.unpack_from('>H', data[offset+2:offset+4])[0]
			TAG_INFO = data[offset+4:offset+4+TAG_LEN]
			handler  = handlers.get(TAG_ID, self._dot11decode_default)

			if TAG_LEN >= size:
				break

			result.append(DOT11_WPS_IE(
				tag_len=TAG_LEN,
				tag_type=ID_NAME(
					id=TAG_ID,
					name=_dot11_wps_tlv_names.get(TAG_ID, None)
				),
				info=handler(TAG_INFO)
			))

			offset += 4 + TAG_LEN
		return result

	def _dot11venorspecific(self, data):
		oui  = data[:3]
		type = data[3]
		info = data[4:]
		
		if oui == MS_OUI:
			if type == 4:
				return DOT11_VENDOR_SPECIFIC(
					oui=oui,
					type=type,
					info=self._dot11WPS(info)
				)
			if type == 1:
				return DOT11_VENDOR_SPECIFIC(
					oui=oui,
					type=type,
					info=self._dot11WPA(info)
				)
			
		return DOT11_VENDOR_SPECIFIC(
			oui=oui,
			type=type,
			info=info
		)

	def _dot11RSN(self, rsn):
		version = struct.unpack('<H', rsn[0:2])[0]
		group_cipher_oui = rsn[2:5]
		group_cipher_ver = rsn[5]
		group_cipher = suite_field(
			type=ID_NAME(
				id=group_cipher_ver,
				name=rsn_cipher_suites.get(group_cipher_ver, "Unknown")
			),
			oui=self.mac2str(group_cipher_oui)
		)

		pairwise_cnt = struct.unpack('<H', rsn[6:8])[0]
		offset = 8
		pairwise_suites = []
		for _ in range(pairwise_cnt):
			suite = rsn[offset:offset+4]
			pairwise_suites.append(suite_field(
				type=ID_NAME(
					id=suite[3],
					name=rsn_cipher_suites.get(suite[3], "Unknown")
				),
				oui=self.mac2str(suite[0:3])
			))
			offset += 4

		akm_cnt = struct.unpack('<H', rsn[offset:offset+2])[0]
		offset += 2
		akm_suites = []
		for _ in range(akm_cnt):
			suite = rsn[offset:offset+4]
			akm_suites.append(suite_field(
				type=ID_NAME(
					id=suite[3],
					name=rsn_akm_suites.get(suite[3], "Unknown")
				),
				oui=self.mac2str(suite[0:3])
			))
			offset += 4

		rsn_capabilities = pmkid_count = 0
		pmkid_list = None
		group_management_cipher = None

		if offset + 2 <= len(rsn):
			rsn_capabilities = struct.unpack('<H', rsn[offset:offset+2])[0]
			offset += 2

		if offset + 2 <= len(rsn):
			pmkid_count = struct.unpack('<H', rsn[offset:offset+2])[0]
			offset += 2
			if pmkid_count > 0:
				pmkid_list = []
				for _ in range(pmkid_count):
					pmkid = rsn[offset:offset+16]
					pmkid_list.append(pmkid)
					offset += 16

		if offset + 4 <= len(rsn):
			oui = rsn[offset:offset+3]
			cipher_type = rsn[offset+3]
			group_management_cipher = suite_field(
				type=cipher_type,
				name=self.rsn_cipher_suites.get(cipher_type, "Unknown"),
				oui=self.mac2str(oui)
			)

		return RSN_IE(
			version=version,
			group_cipher=group_cipher,
			pair_cnt=pairwise_cnt,
			pair_suites=pairwise_suites,
			akm_cnt=akm_cnt,
			akm_suites=akm_suites,
			rsn_capabilities=rsn_capabilities,
			pmk_id_count=pmkid_count,
			pmk_id_list=pmkid_list,
			group_management_cipher=group_management_cipher
		)

	def _dot11WPA(self, rsn):
		version = struct.unpack('<H', rsn[0:2])[0]
		group_cipher = rsn[2:6]
		group_cipher_oui = group_cipher[0:3]
		group_cipher_ver = group_cipher[3]
		pairwise_cnt = rsn[6]

		pairwise_suites = []
		akm_suites = []

		offset = 8
		for i in range(pairwise_cnt):
			pairwise = rsn[offset:offset+4]
			pairwise_suites.append(suite_field(
					type=ID_NAME(
						id=pairwise[3], 
						name=rsn_cipher_suites.get(pairwise[3], 0)
					), 
					oui=self.mac2str(pairwise[0:3])
				)
			)
			offset += 4

		akm_suites_cnt = rsn[offset]
		offset += 2
		for i in range(akm_suites_cnt):
			akm = rsn[offset:offset+4]
			akm_suites.append(suite_field(
					type=ID_NAME(
						id=akm[3], 
						name=rsn_akm_suites.get(akm[3], 0)
					), 
					oui=self.mac2str(akm[0:3])
				)
			)
			offset += 4

		return WPA_IE(
			version=version,
			multicast_suite=suite_field(
				type=ID_NAME(
					id=group_cipher_ver,
					name=rsn_cipher_suites.get(group_cipher_ver, 0)
				),
				oui=self.mac2str(group_cipher_oui)
			),
			unicast_cnt=pairwise_cnt,
			unicast_suites=pairwise_suites,
			akm_cnt=akm_suites_cnt,
			akm_suites=akm_suites
		)
	
	def _dot11rates(self, data):
		rates = []
		for i in range(len(data)):
			raw = data[i]
			is_basic = bool(raw & 0x80)  # проверяем 7-й бит
			rate_value = raw - 128 if is_basic else raw
			speed_mbps = rate_value / 2

			rates.append(DOT11_SUPPORTED_RATE(
				rate=speed_mbps,
				basic=is_basic
			))
		
		return rates

	def Dot11Elt(self):
		if self.fc.type_subtype in [0x50, 0x80]:
			offset = 36 # Skip Dot11 Header + Fixed params 
			packet_len = len(self.pkt[offset:])
			packet = self.pkt[offset:]
			
			if hasattr(self.radiotap.presents, 'Flags'):
				if 'FCS' in self.radiotap.presents.Flags:
					packet_len -= 4
				offset = 0

			result = []
			handlers = {
				0: self._dot11ssid,
				1: self._dot11rates,
				48: self._dot11RSN,
				50: self._dot11rates,
				221: self._dot11venorspecific
			}

			while (offset + 2 <= packet_len):
				tag_id   = packet[offset]
				tag_len  = packet[offset +1]
				tag_data = packet[offset +2:offset+2+tag_len]
				handler  = handlers.get(tag_id, self._dot11decode_default)

				result.append(DOT11_ELT_IE(
					tag_len=tag_len,
					tag_type=ID_NAME(
						id=tag_id,
						name=_dot11_tags[tag_id]
					),
					info=handler(tag_data)
				))

				offset += 2 + tag_len
			return result
		
		return None
	
	def _dot11EAPOL_RSN(self, data):		
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

	def _dot11eap_Identity(self, data):
		return data.decode('utf-8', errors="Ignore")
	
	def _dot11eap_Expanded(self, data):
		size = len(data)
		result = []
		offset = 9

		handlers = {
			0x1021: self._dot11_decode_str, 
			0x1023: self._dot11_decode_str,
			0x1024: self._dot11_decode_str,
			0x1042: self._dot11_decode_str,
			0x1011: self._dot11_decode_str,
			0x1008: self._dot11_wps_config_methods,
			0x1049: self._dot11_wps_vendor_extension
		}

		while (offset + 4 <= size):
			TAG_ID   = struct.unpack_from('>H', data[offset:offset+2])[0]
			TAG_LEN  = struct.unpack_from('>H', data[offset+2:offset+4])[0]
			TAG_INFO = data[offset+4:offset+4+TAG_LEN]
			handler = handlers.get(TAG_ID, self._dot11decode_default)

			if TAG_INFO:
				result.append(DOT11_WPS_IE(
					tag_len=TAG_LEN,
					tag_type=ID_NAME(
						id=TAG_ID,
						name=_dot11_wps_tlv_names.get(TAG_ID, None)
					),
					info=handler(TAG_INFO)
				))

			offset += 4 + TAG_LEN
		return result

	def _dot11EAP(self, data):
		code, id, length, type = struct.unpack_from('>BBHB', data)
		eap_data = data[5:length+5]
		handlers = {
			1: self._dot11eap_Identity,
			254: self._dot11eap_Expanded
		}
		handler = handlers.get(type, self._dot11decode_default)

		if code not in [3, 4]:
			return DOT11_EAP(
				code=ID_NAME(
					id=code,
					name=_dot11_eap_status_codes.get(code)
				),
				id=id,
				length=length,
				type=ID_NAME(
					id=type,
					name=_dot11_eap_type_codes.get(type)
				),
				packet=handler(eap_data)
			)
		
		return None
		

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
					0: self._dot11EAP,
					3: self._dot11EAPOL_RSN
				}
				handler = handlers.get(type, self._dot11decode_default) 

				return DOT11_EAPOL(
					llc=DOT11_LLC(
						DSAP=LLC[0], SSAP=LLC[1],
						CTRL=CONTROL,
						OUI=self.mac2str(OUI),
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

class Dot11:
	def __init__(self, pkt):
		self.RadioTap = RadioTap(pkt)
		self.Dot11 = Dot11_L2(self.RadioTap, pkt)

######################
#   PacketBuilder    #
######################
class PacketBuilder(IEEE80211_DEFS, IEEE80211_Utils):
	def __init__(self):
		pass
	
	def RadioTap_Channel(self, channel, flags=None):
		if flags:
			flags = self.makeFlagsField(self.ieee80211_radiotap_channel_flags_names, flags)
		else:
			flags = 0x0000;
		
		return int.from_bytes(struct.pack('<HH', channel, flags), 'little')

	def RadioTap(self, it_pad=0x00, it_presents=None):
		packet = bytearray()
		presents = bytearray()
		
		# RadioTap header - Version (0x00), Padding, Length, Presents (to many)
		packet.extend(struct.pack('<BB', 0x00, it_pad))
		_it_presents = 0x00000000
		
		if it_presents:
			offset = 8

			for present, _ in it_presents.items():
				present_index = self.getKeyByVal(self.ieee80211_radiotap_presents_names, present)
				if present_index:
					_it_presents |= (1 << present_index)

			for bit in range(16):
				if (_it_presents & (1 << bit)):
					present_chunk = bytearray()
					name = self.ieee80211_radiotap_presents_names.get(bit, None)
					value = it_presents.get(name)
					
					sa = self.ieee80211_radiotap_presents_sizes_aligns[bit]
					align = sa.get('align', 1)
					size = sa.get('size', 1)

					# Fucked stupid agliements blyatt
					if offset % align != 0:
						padding = align - (offset % align)
						present_chunk.extend(b'\x00' * padding)
						offset += padding
					# 1: 'b' if signed else 'B', 2: 'h' if signed else 'H', 4: 'i' if signed else 'I', 8: 'q' if signed else 'Q'
					fmt = self.get_struct_format(size, signed=value < 0)
					present_chunk.extend(struct.pack(f'<{fmt}', value))
					offset += size
					presents.extend(bytes(present_chunk))

		it_len = len(presents) + 8
		packet.extend(struct.pack('<H', it_len))
		packet.extend(struct.pack('<I', _it_presents))
		packet.extend(bytes(presents))

		return bytes(packet)


	def Dot11(self, fc, addr1, addr2=None, addr3=None, addr4=None, duration=0, frag=None, seq=None, fcflags=None, QoSControl=0x00, wep_iv=None, tkip_iv=None, ccmp_iv=None, ht_control=None):
		duration = (duration >> 1) & 0x7FFF
		packet = bytearray()
		flags = 0x00

		if fcflags:
			flags = self.makeFlagsField(self.ieee80211_fc_flags, fcflags)

		packet.extend(struct.pack('<BBH6s', fc, flags, duration, self.mac2bin(addr1)))
		if addr2:
			packet.extend(struct.pack('<6s', self.mac2bin(addr2)))
		if addr3:
			packet.extend(struct.pack('<6s', self.mac2bin(addr3)))
		if addr4:
			packet.extend(struct.pack('<6s', self.mac2bin(addr4)))
		
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

	def Dot11Beacon(self, timestamp=0, beacon_interval=0.00001, capabilities=0x0000):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', int(beacon_interval * 1000000 / 1024)))
		packet.extend(struct.pack('<H', _capabilities))
		
		return bytes(packet)
	
	def Dot11Auth(self, algoritm=0, seq=0, status_code=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', algoritm))
		packet.extend(struct.pack('<H', seq))
		packet.extend(struct.pack('<H', status_code))

		return bytes(packet)

	def Dot11Deauth(self, reason_code=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', reason_code))

		return bytes(packet)

	def Dot11Disassoc(self, reason_code=0x0000):
		packet = bytearray()
		packet.extend(struct.pack('<H', reason_code))

		return bytes(packet)

	def Dot11AssocReq(self, capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		packet.extend(struct.pack('<H', capabilities))
		packet.extend(struct.pack('<H', listen_interval))

		return bytes(packet)

	def dot11AssocResp(self, capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<H', _capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
	
	def Dot11ReassocReq(self, current_ap, capabilities=0x0000, listen_interval=0):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.append(struct.pack('<H', _capabilities))
		packet.append(struct.pack('<H', listen_interval))
		packet.append(struct.pack('<H6s', self.mac2bin(current_ap)))

		return bytes(packet)
	
	def Dot11ReassocResp(self, capabilities=0x0000, status_code=0x0000, assoc_id=0x0000):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<H', _capabilities))
		packet.extend(struct.pack('<H', status_code))
		packet.extend(struct.pack('<H', (assoc_id & 0x3FFF)))

		return bytes(packet)
		
	def Dot11ProbeReq(self):
		pass
	
	def Dot11ProbeResp(self, timestamp=0, beacon_interval=0x0000,  capabilities=None):
		packet = bytearray()
		_capabilities = self.makeFlagsField(self.ieee80211_capabilities, capabilities)
		packet.extend(struct.pack('<Q', timestamp))
		packet.extend(struct.pack('<H', beacon_interval))
		packet.extend(struct.pack('<H', _capabilities))
		
		return bytes(packet)

	def Dot11TLV16(self, id, info):
		packet = bytearray()
		packet.extend(struct.pack('>H', id))
		packet.extend(struct.pack('>H', len(info)))
		packet.extend(info)

		return bytes(packet)

	def Dot11TLV(self, id, info):
		packet = bytearray()
		packet.extend(struct.pack('<B', id))
		packet.extend(struct.pack('<B', len(info)))
		packet.extend(info)
	
		return bytes(packet)
		
	def LLC_SNAP(self, oui, control, code):
		packet = bytearray()
		packet.extend(b'\xAA\xAA') # LLC / DSAP, SSAP = SNAP
		packet.extend(struct.pack('>B', control)) # Fucking control, fucking understand 
		packet.extend(struct.pack('<3s', self.mac2bin(oui)))
		packet.extend(struct.pack('>H', code))

		return bytes(packet)
		
	def EAPOL(self, version, type, length):
		packet = bytearray()
		packet.extend(struct.pack('>B', version))
		packet.extend(struct.pack('>B', type))
		packet.extend(struct.pack('>H', length))

		return bytes(packet)
	
	def EAPOL_HandShake(self, key_desc, key_info, key_len, replay_counter, nonce, iv, rsc, id, mic, wpa_data=None):
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
	
	def EAP(self, code, id, type, data):
		packet = bytearray()
		length = 5 + len(data)

		packet.extend(struct.pack('>B', code))
		packet.extend(struct.pack('>B', id))
		packet.extend(struct.pack('>H', length))
		packet.extend(struct.pack('>B', type))
		packet.extend(data)

		return bytes(packet)
	
	def EAP_EXPANDED(self, vendor_id, vendor_type, opcode, flags=0x00):
		packet = bytearray()
		packet.extend(struct.pack('>3s', self.mac2bin(vendor_id)))
		packet.extend(struct.pack('>I', vendor_type))
		packet.extend(struct.pack('>B', opcode))
		packet.extend(struct.pack('>B', flags))

		return bytes(packet)