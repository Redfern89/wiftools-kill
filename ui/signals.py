from PyQt5.QtCore import QObject, pyqtSignal

class UISignals(QObject):
	ap_found_signal              = pyqtSignal(dict) # AP Data
	ap_update_signal             = pyqtSignal(str, dict) # AP Addr, AP Data
	start_signal                 = pyqtSignal()
	stop_signal                  = pyqtSignal()
	close_signal                 = pyqtSignal()
	sta_found_signal             = pyqtSignal(str, str, dict) # ap addr, sta addr, sta data
	sta_update_signal            = pyqtSignal(str, str, dict) # ap addr, sta addr, sta data
	counts_update_signal         = pyqtSignal(int, int) # ap count, sta count
	set_ap_saved_signal          = pyqtSignal(str) # AP Addr
	set_sta_ap_saved_signal      = pyqtSignal(str, str, str) # AP Addr, STA Addr, Date

	show_wifi_manager_signal     = pyqtSignal()
	wifi_manager_created         = pyqtSignal()
	request_phys_signal          = pyqtSignal()
	response_phys_signal         = pyqtSignal(dict) # not used
	select_interface_signal      = pyqtSignal(dict) # Interface data
	channel_change_signal        = pyqtSignal(str) # channel (Str)
	change_iface_mode_signal     = pyqtSignal(str, str, str) # PHY, Iface, Mode
	iface_updown_signal          = pyqtSignal(str, str) # Iface, state

	show_target_signal           = pyqtSignal(str, str, int) # Iface, target bssid, channel
	close_target_signal          = pyqtSignal()
	start_target_signal          = pyqtSignal()
	stop_target_signal           = pyqtSignal()
	set_trget_first_data_signal  = pyqtSignal(dict) # AP First data
	update_target_ap_signal      = pyqtSignal(dict) # AP Data
	target_sta_found_signal      = pyqtSignal(dict) # STA Data
	target_sta_update_signal     = pyqtSignal(str, dict) # STA Addr, STA Data
	target_sta_probe_signal      = pyqtSignal(str, str) # STA Addr, SSID
	target_eapol_recv_signal     = pyqtSignal(str, str, str) # src mac, dst mac, Message
	target_eapol_error_signal    = pyqtSignal(str, str) # STA Addr, error message
	target_eapol_done_signal     = pyqtSignal(str) # STA Addr
	target_send_deauth_signal    = pyqtSignal(str, str, int, int, int, int) # AP Addr, STA Addr, reason, retries, attempts, timeout
	target_on_deauth_signal      = pyqtSignal(str, str, int) # AP Addr, STA Addr, Reason code
	target_on_deauth_done_signal = pyqtSignal()

	handshakes_db_show_signal    = pyqtSignal()

	def __init__(self):
		super().__init__()
