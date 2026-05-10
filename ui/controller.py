from ui.scaner_window import ScannerWindow
from ui.wifi_manager_window import WiFiManager
from ui.target_window import DeauthDialog
from ui.handshakes_db_window import HandshakesDBDialog

class UIController():
	def __init__(self, core=None):
		self.core = core

		self.scanner_window = None
		self.wifi_manager = None
		self.target_window = None
		self.handshakes_db_window = None

	def show_scaner_window(self):
		if self.scanner_window is None:
			self.scanner_window = ScannerWindow(self.core)
		
		self.scanner_window.show()

	def show_wifi_manager(self):
		if self.wifi_manager is None:
			self.wifi_manager = WiFiManager(self.core)
			self.core.UISignals.wifi.on_created.emit()

		self.wifi_manager.show()

	def show_target_window(self, iface, bssid, channel):
		# Тут создаем заново, потому что нужно передавать новые параметры
		self.target_window = DeauthDialog(self.core, iface, bssid, channel)
		self.target_window.show()

	def show_handshakes_db_window(self):
		if self.handshakes_db_window is None:
			self.handshakes_db_window = HandshakesDBDialog(core=self.core)
		
		self.handshakes_db_window.show()