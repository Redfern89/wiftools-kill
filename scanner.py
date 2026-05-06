#!/usr/bin/env python3

import sys
from PyQt5.QtWidgets import QApplication
from ui.controller import UIController
from core.app import AppCore
from core.pcap import PacketSniffer
from core.controllers import (
    PacketController,
    WifiManagerController,
    TargetPacketController,
    PacketSender,
    DBController
)
from core.hopper import ChannelHopper

class Orchestrator:
	def __init__(self, app_core, ui_controller):
		self.core = app_core
		self.ui = ui_controller
		self.signals = app_core.UISignals

		self.hopper = ChannelHopper()
		self.sniffer = PacketSniffer()
		self.pkt_sender = PacketSender()
		self.pkt_controller = PacketController()
		self.db_controller = DBController(db=app_core.Database)
		
		self.target_controller = None
		self.wifi_controller = None 
		self._setup_initial_callbacks()
		self._setup_logic_signals() # Только логика, без UI

	def _setup_logic_signals(self):
		"""Коннектим только то, что не касается окон напрямую"""
		self.signals.start_signal.connect(self.start_scanner)
		self.signals.stop_signal.connect(self.stop_all)
		self.signals.close_signal.connect(self.stop_all)
		self.signals.target_send_deauth_signal.connect(self.pkt_sender.send_deauth)
		
		# Переключатели режимов
		self.signals.show_target_signal.connect(self.switch_to_target)
		self.signals.close_target_signal.connect(self.switch_to_scanner)
		self.signals.show_wifi_manager_signal.connect(self.show_wifi_manager)

		# Сеттеры данных
		self.signals.select_interface_signal.connect(self._handle_iface_select)

	def run_scanner_ui(self):
		"""Метод для правильного запуска главного окна"""
		self.ui.show_scaner_window() # Теперь окно создано!
		
		# Вот теперь коннектим UI к сигналам
		win = self.ui.scanner_window
		self.signals.ap_found_signal.connect(win.add_ap)
		self.signals.ap_update_signal.connect(win.update_ap)
		self.signals.sta_found_signal.connect(win.add_sta)
		self.signals.sta_update_signal.connect(win.update_sta)
		self.signals.counts_update_signal.connect(win.update_counts)
		self.signals.channel_change_signal.connect(win.on_channel_change)

	def _setup_initial_callbacks(self):
		"""Настройка базовых связей логика -> сигналы"""
		self.hopper.setCallback('on_channel_change', self.signals.channel_change_signal.emit)
		
		self.pkt_controller.setCallback('on_ap_found', self.signals.ap_found_signal.emit)
		self.pkt_controller.setCallback('on_ap_update', self.signals.ap_update_signal.emit)
		self.pkt_controller.setCallback('on_sta_found', self.signals.sta_found_signal.emit)
		self.pkt_controller.setCallback('on_sta_update', self.signals.sta_update_signal.emit)
		self.pkt_controller.setCallback('on_counts_update', self.signals.counts_update_signal.emit)
		
		# По дефолту сниффер работает с общим контроллером пакетов
		self.sniffer.setCallback('on_packet_received', self.pkt_controller.process_packets)

	def _setup_main_signals(self):
		"""Привязка сигналов к действиям компонентов и UI"""
		# Управление сканером
		self.signals.start_signal.connect(self.start_scanner)
		self.signals.stop_signal.connect(self.stop_all)
		self.signals.close_signal.connect(self.stop_all)
		
		# Вызов окон
		self.signals.show_target_signal.connect(self.switch_to_target)
		self.signals.show_wifi_manager_signal.connect(self.show_wifi_manager)
		self.signals.close_target_signal.connect(self.switch_to_scanner)

		# Интерфейс и каналы
		self.signals.select_interface_signal.connect(self._handle_iface_select)
		self.signals.channel_change_signal.connect(self.ui.scanner_window.on_channel_change)

		# UI Update (Сканер)
		self.signals.ap_found_signal.connect(self.ui.scanner_window.add_ap)
		self.signals.ap_update_signal.connect(self.ui.scanner_window.update_ap)
		self.signals.sta_found_signal.connect(self.ui.scanner_window.add_sta)
		self.signals.sta_update_signal.connect(self.ui.scanner_window.update_sta)
		self.signals.counts_update_signal.connect(self.ui.scanner_window.update_counts)

	def _handle_iface_select(self, adapter):
		self.sniffer.setIface(adapter['iface'])
		self.hopper.setData(adapter['iface'], adapter['channels'])
		self.ui.scanner_window.on_select_iface(adapter['iface'])

	def start_scanner(self):
		self.sniffer.start_capture()
		self.hopper.start_hopping()

	def stop_all(self):
		self.sniffer.stop()
		self.hopper.stop()
		#self.core.Database.close()

	def switch_to_target(self, iface, bssid, channel):
		self.stop_all()
		
		# 1. Сначала СОЗДАЕМ окно
		self.ui.show_target_window(iface=iface, bssid=bssid, channel=channel)
		
		# 2. Теперь, когда self.ui.target_window уже не None, создаем контроллер
		self.target_controller = TargetPacketController(bssid=bssid, interface=iface, channel=channel)
		
		# 3. Переобуваем сниффер
		self.sniffer.detachCallback('on_packet_received', self.pkt_controller.process_packets)
		self.sniffer.setCallback('on_packet_received', self.target_controller.process_packets)
		
		# 4. Вяжем контроллер с сигналами
		self.target_controller.setCallback('on_target_ap_update', self.signals.update_target_ap_signal.emit)
		self.target_controller.setCallback('on_first_beacon', self.signals.set_trget_first_data_signal.emit)
		self.target_controller.setCallback('on_sta_found', self.signals.target_sta_found_signal.emit)
		self.target_controller.setCallback('on_sta_update', self.signals.target_sta_update_signal.emit)
		self.target_controller.setCallback('on_sta_probe_req', self.signals.target_sta_probe_signal.emit)
		self.target_controller.setCallback('on_eapol_received', self.signals.target_eapol_recv_signal.emit)
		self.target_controller.setCallback('on_eapol_error', self.signals.target_eapol_error_signal.emit)
		self.target_controller.setCallback('on_eapol_done',  self.signals.target_eapol_done_signal.emit)

		self.target_controller.setCallback('on_eapol_data_done', self.db_controller.insert_4way_handshake)

		self.pkt_sender.setCallback('on_send_deauth', self.sniffer.send)
		self.pkt_sender.setCallback('on_send_deauth_done', self.signals.target_on_deauth_done_signal.emit)
		self.pkt_sender.setCallback('on_deauth_packet', self.signals.target_on_deauth_signal.emit)

		# 5. Вяжем сигналы с методами НОВОГО окна
		# Сначала отрубаем старые связи, если они были (защита от дублей)
		try: self.signals.update_target_ap_signal.disconnect()
		except: pass
		try: self.signals.set_trget_first_data_signal.disconnect()
		except: pass
		try: self.signals.target_sta_found_signal.disconnect()
		except: pass
		try: self.signals.target_sta_update_signal.disconnect()
		except: pass
		try: self.signals.target_sta_probe_signal.disconnect()
		except: pass
		try: self.signals.target_eapol_recv_signal.disconnect()
		except: pass
		try: self.signals.target_eapol_error_signal.disconnect()
		except: pass
		try: self.signals.target_eapol_done_signal.disconnect()
		except: pass
		try: self.signals.target_on_deauth_signal.disconnect()
		except: pass
		try: self.signals.target_on_deauth_done_signal.disconnect()
		except: pass

		self.signals.update_target_ap_signal.connect(self.ui.target_window.update_target_ap)
		self.signals.set_trget_first_data_signal.connect(self.ui.target_window.set_first_data)
		self.signals.target_sta_found_signal.connect(self.ui.target_window.add_sta)
		self.signals.target_sta_update_signal.connect(self.ui.target_window.update_sta)
		self.signals.target_sta_probe_signal.connect(self.ui.target_window.probe_request)
		self.signals.target_eapol_recv_signal.connect(self.ui.target_window.eapol_message)
		self.signals.target_eapol_error_signal.connect(self.ui.target_window.eapol_error)
		self.signals.target_eapol_done_signal.connect(self.ui.target_window.eapol_done)
		self.signals.target_on_deauth_signal.connect(self.ui.target_window.on_deauth)
		self.signals.target_on_deauth_done_signal.connect(self.ui.target_window.deauth_done)

		self.signals.start_target_signal.connect(self.sniffer.start_capture)
		self.signals.stop_target_signal.connect(self.sniffer.stop)

	def switch_to_scanner(self):
		self.stop_all()
		# Возвращаем колбэк общего сканера
		self.sniffer.setCallback('on_packet_received', self.pkt_controller.process_packets)
		self.target_controller = None # Чистим за собой

	def show_wifi_manager(self):
		if not self.wifi_controller:
			self.wifi_controller = WifiManagerController()
			self.signals.change_iface_mode_signal.connect(self.wifi_controller.switch_mode)
			self.signals.iface_updown_signal.connect(self.wifi_controller.switch_state)
			self.signals.request_phys_signal.connect(self._update_phys)
		
		self.ui.show_wifi_manager()
		self.signals.request_phys_signal.emit()

	def _update_phys(self):
		data = self.wifi_controller.handle_phys_details()
		self.ui.wifi_manager.update_phys_list(data)

def main():
	app = QApplication(sys.argv)
	app_core = AppCore()
	ui_controller = UIController(core=app_core)
	
	# Запускаем оркестратор, который свяжет всё воедино
	orchestrator = Orchestrator(app_core, ui_controller)
	orchestrator.run_scanner_ui()

	sys.exit(app.exec_())

if __name__ == "__main__":
	main()
