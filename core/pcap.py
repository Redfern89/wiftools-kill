import threading
import pcap
import traceback
from core.callback import Callback

class PacketSniffer(Callback):
    def __init__(self):
        self.interface = None
        self._stop_event = threading.Event()
        self.on_packet_received = None
        self.on_packet_send = None
        self.on_packet_send_retries = None
        self.thread = None
        self.pHandle = None

    def setIface(self, iface):
        self.interface = iface

    def start_capture(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        if self._stop_event.is_set():
            self._stop_event.clear()
        
        try:
            self.pHandle = pcap.pcap(name=self.interface, promisc=True, immediate=True, timeout_ms=100)
            
            for ts, pkt in self.pHandle:
                if self._stop_event.is_set():
                    break
                
                if self.on_packet_received:
                    self.on_packet_received(pkt, ts)

        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

    def send(self, data):
        if self.pHandle:
            self.pHandle.sendpacket(data)

            if self.on_packet_send:
                self.on_packet_send()

    def send2(self, data):
        pHandle = pcap.pcap(name=self.interface, promisc=True, immediate=True, timeout_ms=100)
        pHandle.sendpacket(data)

    def send_data(self, retries, data):
        def run():
            for _ in range(retries):
                self.send2(data)
        
        self.send_thread = threading.Thread(target=run, daemon=True)
        self.send_thread.start()
        self.send_thread.join()

        if self.on_packet_send_retries:
            self.on_packet_send_retries()

    
    def stop(self):
        self._stop_event.set()
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            self.thread = None