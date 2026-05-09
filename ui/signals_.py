from PyQt5.QtCore import QObject, pyqtSignal

class TargetSignals(QObject):
	show_signal                  = pyqtSignal(str, str, int) # Iface, target bssid, channel
	close_signal                 = pyqtSignal()
	start_signal                 = pyqtSignal()
	stop_signal                  = pyqtSignal()
	set_first_data_signal        = pyqtSignal(dict) # AP First data
	update_ap_signal             = pyqtSignal(dict) # AP Data
	sta_found_signal             = pyqtSignal(dict) # STA Data
	sta_update_signal            = pyqtSignal(str, dict) # STA Addr, STA Data
	sta_probe_signal             = pyqtSignal(str, str) # STA Addr, SSID
	eapol_recv_signal            = pyqtSignal(str, str, str) # src mac, dst mac, Message
	eapol_error_signal           = pyqtSignal(str, str) # STA Addr, error message
	eapol_done_signal            = pyqtSignal(str) # STA Addr
	send_deauth_signal           = pyqtSignal(str, str, int, int, int, int) # AP Addr, STA Addr, reason, retries, attempts, timeout
	on_deauth_signal             = pyqtSignal(str, str, int) # AP Addr, STA Addr, Reason code
	on_deauth_done_signal        = pyqtSignal()
	request_saved_sta            = pyqtSignal(str, str) # AP Addr, STA Addr
	set_sta_saved_signal         = pyqtSignal(str, str, str) # AP Addr, STA Addr, Date
	
class WiFiManagerSignals(QObject):
	show_signal                  = pyqtSignal()
	on_created                   = pyqtSignal()
	request_phys_signal          = pyqtSignal()
	response_phys_signal         = pyqtSignal(dict) # not used
	select_interface_signal      = pyqtSignal(dict) # Interface data
	channel_change_signal        = pyqtSignal(str) # channel (Str)
	change_iface_mode_signal     = pyqtSignal(str, str, str) # PHY, Iface, Mode
	iface_updown_signal          = pyqtSignal(str, str) # Iface, state	

class ScannerSignals(QObject):
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
	request_saved_ap_sta         = pyqtSignal(str, str) # AP Addr, STA Addr
	
class HandshakesDBSignals(QObject):
	show_signal                  = pyqtSignal()
	req_signal                   = pyqtSignal()
	resp_signal                  = pyqtSignal(dict) # Saved data	

class UISignals(QObject):
	def __init__(self):
		super().__init__()

		self.scanner             = ScannerSignals()
		self.target              = TargetSignals()
		self.wifi                = WiFiManagerSignals()
		self.handshakes          = HandshakesDBSignals()
