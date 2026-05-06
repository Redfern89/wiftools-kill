import threading
import random
import time

from core.ieee80211_hardware import IEEE80211_Hardware
from core.callback import Callback

import traceback

class ChannelHopper(Callback):
	def __init__(self):
		self.interface = None
		self.channels = None
		self._stop_event = threading.Event()
		self.on_channel_change = None
		self.thread = None

	def setData(self, iface, channels):
		self.interface = iface
		self.channels = channels

	def start_hopping(self):
		self.thread = threading.Thread(target=self.run, daemon=True)
		self.thread.start()

	def run(self):
		if self._stop_event.is_set():
			self._stop_event.clear()
		
		try:
			while True:
				if self._stop_event.is_set():
					break
				
				ch = random.choice(self.channels)
				IEEE80211_Hardware.switch_iface_channel(self.interface, ch)
				#self.WiFiPhyManager.switch_iface_channel(self.interface, ch)

				if self.on_channel_change:
					self.on_channel_change(str(ch))
				
				time.sleep(0.4)

		except Exception as e:
			traceback.print_exc()
			print(f"Error: {e}")
			
	
	def stop(self):
		self._stop_event.set()
		
		if self.thread and self.thread.is_alive():
			self.thread.join(timeout=1.0)
			self.thread = None