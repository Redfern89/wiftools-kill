#!/usr/bin/env python3

import random
from re import sub
import time
import sys
import subprocess
import json
import threading
import pcap

from dot11 import Dot11Parser
from misc import WiFiPhyManager
import target
import wifiman 

from PyQt5.QtWidgets import (
	QLabel, QMainWindow, QTableView, QVBoxLayout, QHBoxLayout, QPushButton, 
	QMessageBox, QApplication, QWidget, QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QStatusBar, QDialog
)
from PyQt5.QtGui import QFont, QPixmap, QStandardItemModel, QStandardItem, QIcon, QPainter
from PyQt5.QtCore import Q_ARG, QMetaObject, QRect, Qt, QSize, QItemSelection, QTimer, pyqtSlot

from misc import VendorOUI, WiFiHelper

DEBUG = True

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
	return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class StationsTable(QWidget):
	def __init__(self, parent=None):
		super().__init__(parent)
		layout = QVBoxLayout(self)
		layout.setContentsMargins(35, 5, 5, 5)
		
		top_layout = QHBoxLayout()
		top_layout.setContentsMargins(0, 0, 0, 0)
		
		self.assocIconLabel = QLabel()
		self.assocIconLabel.setPixmap(QPixmap('icons/satellite-dish.png').scaled(24, 24, Qt.KeepAspectRatio))
		self.assocIconLabel.setFixedWidth(24)
		
		assocLabelFont = QFont()
		assocLabelFont.setBold(True)
		assocLabelFont.setPointSize(12)
		self.assocLabel = QLabel('Associated stations:')
		self.assocLabel.setFont(assocLabelFont)
		
		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 5, self)
		self.model.setHorizontalHeaderLabels(['MAC', 'RSSI', 'Frames', 'Rate', 'Modulation'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		
		self.progress_delegate = ProgressBarDelegate(self.table)
		self.table.setItemDelegateForColumn(1, self.progress_delegate)

		self.table.setColumnWidth(0, 170)
		self.table.setColumnWidth(1, 300)
		self.table.setColumnWidth(4, 55)
		self.table.setColumnWidth(5, 80)
		
		top_layout.addWidget(self.assocIconLabel)
		top_layout.addWidget(self.assocLabel)
		layout.addLayout(top_layout)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def update_data(self, ssid, stations):
		self.model.setRowCount(0)
		
		self.assocLabel.setText(f'Associated stations for "{ssid}":')
		
		for station in stations:
			first_item = QStandardItem(QIcon('icons/signal.png'), str(station.get('station_MAC', "")))
			row = [first_item]
			for col in ['station_dBm_AntSignal', 'station_Frames', 'station_Rate', 'station_ChannelFlags']:
				row.append(QStandardItem(str(station.get(col, ""))))
			self.model.appendRow(row)
			
			row_number = self.model.rowCount() -1
			self.table.setRowHeight(row_number, 40)

class ProgressBarDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		if 1:
			try:
				rssi_value = int(index.data())
			except ValueError:
				return
		
			signal_strength = int(scale_rssi(rssi_value, -85, -40, 0, 100))
			padding = 6
			bar_rect = option.rect.adjusted(padding, padding, -padding, -padding)

			if option.state & QStyle.State_Selected:
				painter.fillRect(option.rect, option.palette.highlight())
			
			
			progress_option = QStyleOptionProgressBar()
			#progress_option.setStyleSheet("QProgressBar {border: 2px solid grey; border-radius: 5px; text-align: center;}")
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = signal_strength
			progress_option.text = f"{rssi_value} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter

			painter.save()
			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar , progress_option, painter)
			#option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
			painter.restore()
		else:
			super().paint(painter, option, index)

	def createEditor(self, parent, option, index):
		return None

class BSSIDDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		bssid = index.data(Qt.UserRole +3)
		ssid = index.data(Qt.UserRole +1)
		item_type = index.data(Qt.UserRole)

		if item_type == 'STA_ITEM':
			painter.save()
			#data = json.loads(index.data(Qt.UserRole +1))
			data = index.data(Qt.UserRole +1)
			icon = QIcon('icons/signal.png')
			icon.paint(painter, option.rect.adjusted(20, 4, -4, -4), Qt.AlignLeft | Qt.AlignVCenter)

			if option.state & QStyle.State_Selected:
				painter.setPen(Qt.white)
			else:
				painter.setPen(Qt.black)

			padding = 3
			bar_rect = option.rect.adjusted(200, padding, -padding-300, -padding)
			progress_option = QStyleOptionProgressBar()
			#progress_option.setStyleSheet("QProgressBar {border: 2px solid grey; border-radius: 5px; text-align: center;}")
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = int(scale_rssi(data.get('station_dBm_AntSignal', -90), -85, -40, 0, 100))
			progress_option.text = f"{data.get('station_dBm_AntSignal', -90)} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter


			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar , progress_option, painter)

			mac = index.data(Qt.UserRole +3)
			painter.drawText(option.rect.adjusted(45, -3, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, mac)
			painter.restore()

		if bssid and item_type == 'AP_ITEM': # Только для основных строк с BSSID
			painter.save()
			icon = index.data(Qt.DecorationRole)
			icon_size = option.decorationSize.width() if icon else 0

			icon = QIcon('icons/wifi-router.png')
			icon.paint(painter, option.rect.adjusted(4, 4, -4, -4), Qt.AlignLeft | Qt.AlignVCenter)
			
			if option.state & QStyle.State_Selected:
				painter.setPen(Qt.white)
			else:
				painter.setPen(Qt.black)

			ssid_rect = option.rect.adjusted(40, -22, 0, 0)
			ssid_font = QFont(option.font)
			ssid_font.setBold(True)
			if ssid == '<Hidden>':
				painter.setPen(Qt.red)
			painter.setFont(ssid_font)
			painter.drawText(ssid_rect, Qt.AlignLeft | Qt.AlignVCenter, ssid)

			bssid_font = QFont(option.font)
			bssid_font.setPointSize(bssid_font.pointSize() - 2)
			painter.setFont(bssid_font)
			if option.state & QStyle.State_Selected:
				painter.setPen(Qt.white)
			else:
				painter.setPen(Qt.darkGray)
			painter.drawText(option.rect.adjusted(40, 0, 0, 20), Qt.AlignLeft | Qt.AlignVCenter, bssid.upper())

			painter.restore()
		else:
			super().paint(painter, option, index)

class WiFiManager(QMainWindow):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.access_points = {}
		self.running = False

		self.setWindowTitle("WiFi Cracker")
		self.setGeometry(*self._center_window(1120, 520))
		self.central_widget = QWidget()
		self.setCentralWidget(self.central_widget)

		self.work_sec = 0
		self.work_min = 0
		self.work_hours = 0
		self.work_days = 0

		self.found_ap_cnt = 0
		self.found_sta_cnt = 0

		self.interface = ''
		self.supported_channels = []
		self.vendor_oui = VendorOUI()

		self.btn_wifi = QPushButton('Выбор адаптера')
		self.btn_wifi.setIcon(QIcon('icons/ethernet.png'))
		self.btn_wifi.setIconSize(QSize(24, 24))
		self.btn_scan = QPushButton('Сканировать')
		self.btn_scan.setIcon(QIcon('icons/refresh.png'))
		self.btn_scan.setIconSize(QSize(24, 24))
		self.btn_scan.setEnabled(False)
		self.btn_stop = QPushButton('Остановить')
		self.btn_stop.setIcon(QIcon('icons/cancelled.png'))
		self.btn_stop.setIconSize(QSize(24, 24))
		self.btn_stop.setVisible(False)
		self.btn_targ = QPushButton('Выбор цели')
		self.btn_targ.setIcon(QIcon('icons/target.png'))
		self.btn_targ.setIconSize(QSize(24, 24))
		self.btn_sett = QPushButton('Настройки')
		self.btn_sett.setIcon(QIcon('icons/settings.png'))
		self.btn_sett.setIconSize(QSize(24, 24))

		self.btn_scan.clicked.connect(self.scan)
		self.btn_stop.clicked.connect(self.stop)
		self.btn_wifi.clicked.connect(self.show_wifiman_dialog)
		self.btn_targ.clicked.connect(self.select_target)

		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_wifi)
		top_layout.addWidget(self.btn_scan)
		top_layout.addWidget(self.btn_stop)
		top_layout.addWidget(self.btn_targ)
		top_layout.addWidget(self.btn_sett)
		top_layout.setContentsMargins(5, 5, 5, 0)
		top_layout.addStretch()

		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 6, self)
		self.model.setHorizontalHeaderLabels(['BSSID', 'ch', 'Vendor', 'RSSI', 'Encryption', 'Cipher', 'AKM'])
		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		self.table.doubleClicked.connect(self.select_target)
		self.progress_delegate = ProgressBarDelegate(self.table)
		self.table.setItemDelegateForColumn(3, self.progress_delegate)
		self.bssid_delegate = BSSIDDelegate(self.table)
		self.table.setItemDelegateForColumn(0, self.bssid_delegate)

		self.table.setColumnWidth(0, 250) # BSSID
		self.table.setColumnWidth(1, 50)  # Channel
		self.table.setColumnWidth(2, 100) # Vendor
		self.table.setColumnWidth(3, 350) # RSSI
		self.table.setColumnWidth(4, 100) # Encryption
		self.table.setColumnWidth(5, 100) # Cipher
		self.table.setColumnWidth(6, 100) # AKM

		# Основной layout
		main_layout = QVBoxLayout(self.central_widget)
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		self.setLayout(main_layout)

		self.interfaceIconLabel = QLabel()
		self.interfaceIconLabel.setPixmap(QPixmap('icons/cancelled.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.statusLabel = QLabel('Interface not selected')
		self.statusLabel.setFixedWidth(350)

		self.workIconLabel = QLabel()
		self.workIconLabel.setPixmap(QPixmap('icons/clock-time.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.workLabel = QLabel('0d 00:00:00')
		self.workLabel.setFixedWidth(150)

		self.networksIconLabel = QLabel()
		self.networksIconLabel.setPixmap(QPixmap('icons/menu.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.networksLabel = QLabel('Networks: 0')

		self.statusbar = QStatusBar()
		self.statusbar.addWidget(self.interfaceIconLabel)
		self.statusbar.addWidget(self.statusLabel)
		self.statusbar.addWidget(self.workIconLabel)
		self.statusbar.addWidget(self.workLabel)
		self.statusbar.addWidget(self.networksIconLabel)
		self.statusbar.addWidget(self.networksLabel)
		self.setStatusBar(self.statusbar) 

		self.workTimer = QTimer()
		self.workTimer.setInterval(1000)
		self.workTimer.timeout.connect(self.on_work_timer)

	def init_work_timer(self):
		self.work_sec = 0
		self.work_min = 0
		self.work_hours = 0
		self.work_days = 0

		self.workLabel.setText('0d 00:00:00')
		self.workTimer.start()

	def _get_selected_row(self):
		indexes = self.table.selectionModel().selectedIndexes()
		return indexes[0].row() if indexes else None

	def _get_value(self, row, column, role=Qt.DisplayRole):
		return self.model.data(self.model.index(row, column), role)

	def on_selection_changed(self):
		if self.running:
			return

		row = self._get_selected_row()
		if row is None:
			return
		
		target_role  = self._get_value(row, 0, Qt.UserRole)
		if target_role == 'AP_ITEM':
			self.btn_targ.setEnabled(True)
		else:
			self.btn_targ.setEnabled(False)

	def select_target(self):
		if self.running:
			return

		row = self._get_selected_row()
		if row is None:
			return

		target_bssid = self._get_value(row, 0)
		target_role  = self._get_value(row, 0, Qt.UserRole)
		
		if target_role == 'AP_ITEM':
			target_channel = self._get_value(row, 1)
			target_dialog = target.DeauthDialog(self.interface, target_bssid, target_channel)
			target_dialog.exec_()

	def show_wifiman_dialog(self):
		wifiman_dialog = wifiman.WiFiManager(self)
		wifiman_dialog.exec_()
		
		if wifiman_dialog.result() == QDialog.Accepted:
			result = wifiman_dialog.select_iface()
			if not result.get('interface') is None:
				self.interface = result.get('interface', None)
				self.supported_channels = result.get('supported_channels', None)
				self.interfaceIconLabel.setPixmap(QPixmap('icons/ethernet.png').scaled(26, 26, Qt.KeepAspectRatio))
				self.statusLabel.setText(f"Interface: {self.interface}, CH: ?")
				self.btn_scan.setEnabled(True)

	def scan(self):
		if self.interface:
			self.running = True
			self.init_work_timer()
			self.start_monitoring(self.interface)
			self.channel_hopper(self.interface)

	def stop(self):
		if self.running:
			self.running = False
			self.monitor_thread.join()
			self.hopper_thread.join()

			self.btn_scan.setVisible(True)
			self.btn_stop.setVisible(False)
			self.btn_wifi.setEnabled(True)
			self.btn_targ.setEnabled(True)

			self.workTimer.stop()

	def on_work_timer(self):
		self.work_sec += 1

		if self.work_sec >= 59:
			self.work_sec = 0
			self.work_min += 1
		elif self.work_min >= 59:
			self.work_min = 0
			self.work_hours += 1
		elif self.work_hours >= 24:
			self.work_sec = 0
			self.work_min = 0
			self.work_hours = 0
			self.work_days += 1
		
		self.workLabel.setText(f"{self.work_days}d {self.work_hours:02d}:{self.work_min:02d}:{self.work_sec:02d}")

	def find_row_by_userrole(self, value, role):
		for row in range(self.model.rowCount()):
			item = self.model.item(row, 0)
			if item and item.data(Qt.UserRole + role) == value:
				return row
		return -1

	@pyqtSlot(object, str)
	def __update_label(self, label, text):
		label.setText(text)

	@pyqtSlot(str)
	def __add_network(self, network):
		data = json.loads(network)
		items = []

		for key in ['BSSID', 'SSID', 'channel', 'vendor', 'rssi', 'encryption', 'cipher', 'akm']:
			if key == 'BSSID':
				item = QStandardItem(str(data.get(key, '')))
				item.setData('AP_ITEM', Qt.UserRole)
				item.setData(data.get('SSID', ''), Qt.UserRole +1)
				item.setData(data.get('BSSID', ''), Qt.UserRole +2)
				item.setData(self.vendor_oui.get_mac_vendor_mixed(data.get('BSSID', '')), Qt.UserRole +3)
				items.append(item)
			else:
				if key not in ['SSID', 'BSSID']:
					items.append(QStandardItem(str(data.get(key, ''))))
		
		self.model.appendRow(items)
		self.table.setRowHeight(self.model.rowCount() - 1, 40)
	
	@pyqtSlot(str, int, str)
	def __update_ap_role_by_bssid(self, bssid, role, value):
		row = self.find_row_by_userrole(bssid.upper(), 2) # Ищем по UserRole +2, где хранится BSSID
		if row != -1:
			item = self.model.item(row, 0)
			if item:
				item.setData(value, Qt.UserRole + role)

	@pyqtSlot(str, int, str)
	def __update_ap_by_bssid(self, bssid, item, data):
		row = self.find_row_by_userrole(bssid.upper(), 2) # Ищем по UserRole +2, где хранится BSSID
		if row != -1:
			self.model.item(row, item).setText(str(data))

	@pyqtSlot(str, str)
	def __add_sta_by_bssid(self, bssid, data):
		sta_data = json.loads(data)
		row = self.find_row_by_userrole(bssid.upper(), 2) # Ищем по UserRole +2, где хранится BSSID
		if row != -1:
			item = QStandardItem()
			item.setData('STA_ITEM', Qt.UserRole)
			item.setData(sta_data, Qt.UserRole +1)
			item.setData(self.vendor_oui.get_mac_vendor_mixed(sta_data.get('station_MAC', '')), Qt.UserRole +3)
			item.setData(sta_data.get('station_MAC', ''), Qt.UserRole + 4)
			self.model.insertRow(row + 1, [item])
			self.table.setSpan(row + 1, 0, 1, 4)
			'''subitem = QStandardItem("")
			sub_row = [QStandardItem("") for _ in range(self.model.columnCount())]
			sub_row[0] = subitem
			self.model.insertRow(row + 1, sub_row)
			self.table.setSpan(row + 1, 0, 1, 8)
			subitem_index = self.model.index(row + 1, 0)
			stations_table = StationsTable(self)
			#stations_table.update_data(ssid, stations)
			
			self.table.setIndexWidget(subitem_index, stations_table)
			self.table.setRowHeight(row +1, 103)
			
			self.table.viewport().update()'''

	@pyqtSlot(str, str)
	def __update_sta_data(self, sta_mac, data):
		station = json.loads(data)
		row = self.find_row_by_userrole(sta_mac, 4)
		if row != -1:
			self.model.item(row, 0).setData(station, Qt.UserRole +1)

	@pyqtSlot(object, bool)
	def __toggle_elem(self, elem, visible):
		elem.setVisible(visible)

	@pyqtSlot(object, bool)
	def __enbled_elem_toggle(self, elem, enabled):
		elem.setEnabled(enabled)
	
	@pyqtSlot(str, str, int, int)
	def __show_message(self, title, message, icon_type, buttons):
		msg = QMessageBox(self)
		msg.setWindowTitle(title)
		msg.setText(message)
		msg.setIcon(QMessageBox.Icon(icon_type))
		msg.setStandardButtons(QMessageBox.StandardButtons(buttons))
		msg.show()

	def safe_show_message(self, title, message, icon_type, buttons):
		QMetaObject.invokeMethod(self, "__show_message", Qt.QueuedConnection,
			Q_ARG(str, title),
			Q_ARG(str, message),
			Q_ARG(int, icon_type),
			Q_ARG(int, buttons)
		)

	def safe_toggle_elem(self, elem, visible):
		QMetaObject.invokeMethod(self, "__toggle_elem", Qt.QueuedConnection,
			Q_ARG(object, elem),
			Q_ARG(bool, visible)
		)

	def safe_enbled_elem_toggle(self, elem, enabled):
		QMetaObject.invokeMethod(self, "__enbled_elem_toggle", Qt.QueuedConnection,
			Q_ARG(object, elem),
			Q_ARG(bool, enabled)
		)

	def safe_update_sta_data(self, sta_mac, data):
		QMetaObject.invokeMethod(self, "__update_sta_data", Qt.QueuedConnection, 
				Q_ARG("QString", sta_mac),
				Q_ARG("QString", data)
			)

	def safe_update_ap_role_by_bssid(self, bssid, role, value):
		QMetaObject.invokeMethod(self, "__update_ap_role_by_bssid", Qt.QueuedConnection, 
			   Q_ARG("QString", bssid),
			   Q_ARG("int", role),
			   Q_ARG("QString", value)
			)

	def safe_add_subitem_by_bssid(self, bssid, data):
		QMetaObject.invokeMethod(self, "__add_sta_by_bssid", Qt.QueuedConnection, 
			   Q_ARG("QString", bssid),
			   Q_ARG("QString", data)
			)

	def safe_add_network(self, network):
		QMetaObject.invokeMethod(self, "__add_network", Qt.QueuedConnection, Q_ARG(str, network))

	def safe_update_ap_item_by_bssid(self, bssid, item, data):
		QMetaObject.invokeMethod(self, "__update_ap_by_bssid", Qt.QueuedConnection, #TODO
			   Q_ARG("QString", bssid), 
			   Q_ARG("int", item), 
			   Q_ARG("QString", data)
			)

	def safe_update_label(self, label, text):
		QMetaObject.invokeMethod(self, "__update_label", Qt.QueuedConnection, 
				Q_ARG(object, label),
				Q_ARG(str, text)
		)


	def _center_window(self, w, h):
		# Это прям ацкий костыль, но я не нашел другого способа получить разрешение экрана без использования дополнительных библиотек. Если кто-то знает, как это сделать в PyQt5 без сторонних зависимостей, буду рад узнать.
		# Возвращает координаты для центрирования окна.
		xrandr_wxh = subprocess.check_output("xrandr | grep '*' | awk '{print $1}' | head -n1", shell=True).decode().strip()
		screen_w, screen_h = map(int, xrandr_wxh.split('x'))
		return round((screen_w - w) / 2), round((screen_h - h) / 2), w, h
	
	def channel_hopper(self, interface):
		def run():
			wifiman = WiFiPhyManager()
			while True:
				if not self.running:
					if DEBUG:
						print("[+] Hopper stopped")
					break

				ch = random.choice(self.supported_channels)
				self.safe_update_label(self.statusLabel, f"Interface: {self.interface}, CH: {ch}")
				wifiman.switch_iface_channel(interface, ch)
				#subprocess.run(f"iwconfig {interface} channel {ch}", shell=True)
				time.sleep(0.5)

		if DEBUG:
			print("[+] Hopper started")

		self.hopper_thread = threading.Thread(target=run, daemon=True)
		self.hopper_thread.start()
		
	def start_monitoring(self, iface):
		def run():
			#try:
			pHandle = pcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=100)
			if DEBUG:
				print(f"[*] Sniffing on {iface}...")
			self.safe_toggle_elem(self.btn_scan, False)
			self.safe_toggle_elem(self.btn_stop, True)
			self.safe_enbled_elem_toggle(self.btn_wifi, False)
			self.safe_enbled_elem_toggle(self.btn_targ, False)
			self.process_packets(pHandle)

			#except Exception as e:
			#	if DEBUG:
			#		print(f"[!] Failed to open interface {iface}: {e}")
			#	self.running = False
			#	self.safe_show_message("Error", str(e), QMessageBox.critical, QMessageBox.Ok)

		self.monitor_thread = threading.Thread(target=run, daemon=True)
		self.monitor_thread.start()

	def process_packets(self, pHandle):
		for ts, pkt in pHandle:
			if not self.running:
				if DEBUG:
					print("[+] pcap stopped")
				break

			wifi_pkt = Dot11Parser(pkt)
			channel_present = wifi_pkt.return_RadioTap_PresentFlag('Channel')
			channel = channel_present.get('channel', 0) if channel_present else 0
			channel_flags = channel_present.get('flags', 0) if channel_present else 'None'
			rssi = wifi_pkt.return_RadioTap_PresentFlag('dbm_Antenna_Signal') or -100

			type_subtype = wifi_pkt.return_Dot11_frame_control()
			dot11frame = wifi_pkt.return_Dot11()

			if type_subtype in [0x08, 0x88]: # Data, QoS Data
				fc_flags = wifi_pkt.return_dot11_framecontrol_flags()
				flag_names = {f.name for f in fc_flags} # Делаем set для скорости
				
				# Проверка на мультикаст (нечетный первый байт ADDR1)
				is_multicast = int(dot11frame.addr1.split(':')[0], 16) & 1
				
				if not is_multicast and 'more_data' not in flag_names:
					to_ds       = 'to_ds' in flag_names
					from_ds     = 'from_ds' in flag_names
					is_direct   = False
					direct_type = ""
					ap_addr     = None
					client_addr = None
					
					if from_ds:
						#is_direct = (dot11frame.addr2 == dot11frame.addr3) - без этого можно видеть связи router > ap > client
						# мб позже сделаю
						is_direct = dot11frame.addr1 != 'ff:ff:ff:ff:ff:ff' # Исключаем широковещательные
						is_direct = dot11frame.addr1[:8] != '01:00:5e' and is_direct # Исключаем IPv4 multicast
						is_direct = dot11frame.addr1[:8] != '33:33:00' and is_direct # Исключаем IPv6 multicast
						ap_addr = dot11frame.addr2 or dot11frame.addr3
						client_addr = dot11frame.addr1
						direct_type = "AP -> Client"
					elif to_ds:
						#is_direct = (dot11frame.addr1 == dot11frame.addr3)
						is_direct = dot11frame.addr3 != 'ff:ff:ff:ff:ff:ff'# and is_direct # Исключаем широковещательные
						direct_type = "Client -> AP"
						ap_addr = dot11frame.addr1 or dot11frame.addr3
						client_addr = dot11frame.addr2

					if is_direct:
						if ap_addr not in self.access_points:
							continue

						if client_addr not in self.access_points[ap_addr]['clients']:
							if DEBUG:
								print(f"[+] Detected client on {ap_addr} -> {client_addr}")
							client = {
								'station_MAC': client_addr,
								'station_dBm_AntSignal': rssi,
								'station_Rate': 'Unknown',
								'station_ChannelFlags': channel_flags
							}
							self.found_sta_cnt += 1
							self.safe_update_label(self.networksLabel, f"Networks: {self.found_ap_cnt} [{self.found_sta_cnt}]")
							self.access_points[ap_addr]['clients'].append(client_addr)
							self.safe_add_subitem_by_bssid(ap_addr, json.dumps(client))
						else:
							client = {
								'station_MAC': client_addr,
								'station_dBm_AntSignal': rssi,
								'station_Rate': 'Unknown',
								'station_ChannelFlags': channel_flags
							}
							self.safe_update_sta_data(client_addr, json.dumps(client))
						
			beacon = wifi_pkt.return_Dot11_Beacon_ProbeResponse()
			if beacon:
				elt = wifi_pkt.return_Dot11Elt()
				wifi_dot11 = wifi_pkt.return_Dot11()
				bssid = wifi_dot11.addr3
				wifi = WiFiHelper()
				ssid = wifi.get_ap_ssid(wifi_pkt)
				vendor = wifi.get_ap_vendor(wifi_pkt)
				channel = wifi.get_ap_channel(wifi_pkt)
				enc_type, unicast_pair_suites, akm_suites = wifi.return_ap_encryptions(beacon, elt)
				akm_suites = ', '.join(akm_suites) if akm_suites else '-'
				unicast_pair_suites = ', '.join(unicast_pair_suites) if unicast_pair_suites else '-'
				enc_type = '/'.join(enc_type)
				
				if bssid in self.access_points:
					self.safe_update_ap_role_by_bssid(bssid, 1, ssid)             # Обновляем SSID в UserRole +1
					self.safe_update_ap_item_by_bssid(bssid, 1, str(channel))     # Обновляем канал
					self.safe_update_ap_item_by_bssid(bssid, 2, str(vendor))      # Обновляем вендора
					self.safe_update_ap_item_by_bssid(bssid, 3, str(rssi))        # Обновляем RSSI
					self.safe_update_ap_item_by_bssid(bssid, 4, str(enc_type))    # Обновляем тип шифрования
					self.safe_update_ap_item_by_bssid(bssid, 5, str(unicast_pair_suites)) # Обновляем парные шифры
					self.safe_update_ap_item_by_bssid(bssid, 6, str(akm_suites))  # Обновляем шифры аутентификации
				else:
					ap_info = {
						"BSSID": bssid.upper(),
						"SSID": ssid,
						"channel": channel,
						"vendor": vendor,
						"rssi": rssi,
						"encryption": enc_type,
						"cipher": unicast_pair_suites,
						"akm": akm_suites,
						"clients": []
					}
					self.found_ap_cnt += 1
					self.access_points[bssid] = ap_info
					self.safe_add_network(json.dumps(ap_info))			


if __name__ == "__main__":
	app = QApplication(sys.argv)
	window = WiFiManager()
	window.show()
	sys.exit(app.exec_())