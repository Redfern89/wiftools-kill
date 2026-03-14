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

import pprint

from PyQt5.QtWidgets import (
	QAbstractItemView, QLabel, QMainWindow, QTableView, QVBoxLayout, QHBoxLayout, QPushButton, 
	QMessageBox, QApplication, QWidget, QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QStatusBar, QDialog
)
from PyQt5.QtGui import QFont, QPixmap, QStandardItemModel, QStandardItem, QIcon, QPainter
from PyQt5.QtCore import Q_ARG, QMetaObject, QRect, Qt, QSize, QItemSelection, QTimer, pyqtSlot

from misc import VendorOUI, WiFiHelper

DEBUG = True

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
	return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

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
		self.model.setHorizontalHeaderLabels(['MAC', 'RSSI', 'Frames', 'Rate', 'Modulation', 'Probes'])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.table.setIconSize(QSize(32, 32))

		self.table.setSelectionMode(QAbstractItemView.NoSelection)
		self.table.setFocusPolicy(Qt.NoFocus)
		
		self.progress_delegate = ProgressBarDelegate(self.table)
		self.table.setItemDelegateForColumn(1, self.progress_delegate)

		self.table.setColumnWidth(0, 200)  # MAC
		self.table.setColumnWidth(1, 300)  # RSSI
		self.table.setColumnWidth(2, 55)   # Frames
		self.table.setColumnWidth(3, 80)   # Rate
		self.table.setColumnWidth(4, 200)  # Modulation
		self.table.setColumnWidth(5, 100)  # Probes

		top_layout.addWidget(self.assocIconLabel)
		top_layout.addWidget(self.assocLabel)
		layout.addLayout(top_layout)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def find_row_by_bssid(self, bssid):
		for row in range(self.model.rowCount()):
			item = self.model.item(row, 0)
			if item and item.data(Qt.DisplayRole) == bssid:
				return row
		return -1

	def set_ssid(self, ssid):
		self.assocLabel.setText(f'Associated stations for "{ssid}":')

	def add_sta(self, sta_data):
		sta_mac = sta_data['list_items'].get('station_MAC', None)
		if sta_mac:
			row = self.find_row_by_bssid(sta_mac)

			if row == -1:
				for k, v in sta_data['list_items'].items():
					if k == 'station_MAC':
						first_item = QStandardItem(QIcon('icons/signal.png'), str(v))
						row = [first_item]
					elif k == 'station_ChannelFlags':
						channel_flags = '+'.join(v)
						row.append(QStandardItem(channel_flags))
					elif k == 'station_Rate':
						row.append(QStandardItem(f'{v} MB/s'))
					else:
						row.append(QStandardItem(str(v)))

				self.model.appendRow(row)
				row_number = self.model.rowCount() -1
				self.table.setRowHeight(row_number, 40)
			else:
				for index, (k, v) in enumerate(sta_data.get('list_items').items()):
					item = self.model.item(row, index)
					if k == 'station_MAC':
						continue
					elif k == 'station_ChannelFlags':
						channel_flags = '+'.join(v)
						item.setText(channel_flags)
					elif k == 'station_Rate':
						item.setText(f'{v} MB/s')
					else:
						item.setText(str(v))

				probes = sta_data.get('probes', None)
				probes_list = []
				if probes:
					for pk, pv in probes.items():
						for probe_key, probe_value in pv.items():
							if probe_key == 'ssid':
								if probe_value not in probes_list:
									probes_list.append(probe_value)
				
				item = self.model.item(row, 5)
				if item:
					item.setText(', '.join(probes_list))
				else:
					self.model.setItem(row, 5, QStandardItem(', '.join(probes_list)))

class BSSIDDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		bssid = index.data(Qt.UserRole +3)
		ssid = index.data(Qt.UserRole +1)
		item_type = index.data(Qt.UserRole)

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
				ssid_font.setUnderline(True)
				painter.setFont(ssid_font)
				pending_icon = QIcon('icons/pending.png')
				icon_size = 16
				ssid_rect = option.rect.adjusted(60, -22, 0, 0)
				icon_rect = QRect(option.rect.left() + 40, option.rect.top()+2, icon_size, icon_size)
				pending_icon.paint(painter, icon_rect, Qt.AlignLeft | Qt.AlignVCenter)
				painter.drawText(ssid_rect, Qt.AlignLeft | Qt.AlignVCenter, ssid)
			else:
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

class WPSDeligate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		state = index.data(Qt.UserRole +4)
		version = index.data(Qt.UserRole +5)
		
		if state in ['WPS_LOCKED', 'WPS_UNLOCKED']:
			font = QFont(option.font)
			painter.save()
			
			painter.setFont(font)
			if state == 'WPS_LOCKED':
				painter.setPen(Qt.red)
				font.setUnderline(True)
				icon = QIcon('icons/padlock.png')
			else:
				icon = QIcon('icons/unlocked.png')

			painter.setFont(font)

			icon_size = 16
			wps_rect = option.rect.adjusted(20, 0, 0, 0)
			icon_rect = QRect(option.rect.left(), option.rect.top()+12, icon_size, icon_size)
			icon.paint(painter, icon_rect, Qt.AlignLeft | Qt.AlignVCenter)
			painter.drawText(wps_rect, Qt.AlignLeft | Qt.AlignVCenter, version)
			painter.restore()
		else:
			super().paint(painter, option, index)

class WiFiManager(QMainWindow):
	def __init__(self, parent=None):
		super().__init__(parent)

		self.access_points = {}
		self.probes = {}
		self.running = False

		self.setWindowTitle("WiFi Cracker")
		self.setWindowIcon(QIcon('icons/satellite-dish.png'))
		self.setGeometry(*self._center_window(1180, 720))
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
		self.model.setHorizontalHeaderLabels(['BSSID', 'ch', 'Vendor', 'RSSI', 'Encryption', 'Cipher', 'AKM', 'WPS', 'Beacons'])
		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		self.table.doubleClicked.connect(self.select_target)
		self.bssid_delegate = BSSIDDelegate(self.table)
		self.progress_delegate = ProgressBarDelegate(self.table)
		self.wps_deligate = WPSDeligate(self.table)
		self.table.setItemDelegateForColumn(0, self.bssid_delegate)
		self.table.setItemDelegateForColumn(3, self.progress_delegate)
		self.table.setItemDelegateForColumn(7, self.wps_deligate)

		self.table.setColumnWidth(0, 200) # BSSID
		self.table.setColumnWidth(1, 50)  # Channel
		self.table.setColumnWidth(2, 90) # Vendor
		self.table.setColumnWidth(3, 250) # RSSI
		self.table.setColumnWidth(4, 100) # Encryption
		self.table.setColumnWidth(5, 100) # Cipher
		self.table.setColumnWidth(6, 100) # AKM
		self.table.setColumnWidth(7, 150) # WPS
		#self.table.setColumnWidth(8, 100) # Beacons

		self.probes_table = QTableView(self)
		self.probes_table_model = QStandardItemModel(0, 3, self)
		self.probes_table_model.setHorizontalHeaderLabels(['MAC', 'SSID', 'Vendor'])

		self.probes_table.setModel(self.probes_table_model)
		self.probes_table.horizontalHeader().setStretchLastSection(True)
		self.probes_table.setEditTriggers(QTableView.NoEditTriggers)
		self.probes_table.setShowGrid(False)
		self.probes_table.verticalHeader().setVisible(False)
		self.probes_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.probes_table.setIconSize(QSize(32, 32))
		self.probes_table.setFixedHeight(150)

		self.probes_table.setColumnWidth(0, 250) # MAC
		self.probes_table.setColumnWidth(1, 350) # SSID

		# Основной layout
		main_layout = QVBoxLayout(self.central_widget)
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		main_layout.addWidget(self.probes_table)
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

	def closeEvent(self, event):
		try:
			if self.running:
				self.running = False
				if self.monitor_thread.is_alive():
					self.monitor_thread.join()
				if self.hopper_thread.is_alive():
					self.hopper_thread.join()
		finally:
			if DEBUG:
				print("[+] Done!")
			event.accept()

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
	
	def has_nested_exists(self, row):
		for col in range(self.model.columnCount()):
			index = self.model.index(row, col)
			widget = self.table.indexWidget(index)
			if isinstance(widget, QWidget):
				return True
		
		return False

	@pyqtSlot(object, str)
	def __update_label(self, label, text):
		label.setText(text)

	@pyqtSlot(str)
	def __add_network(self, network):
		data = json.loads(network)
		items = []

		for key in ['BSSID', 'SSID', 'channel', 'vendor', 'rssi', 'encryption', 'cipher', 'akm', 'wps', 'beacons']:
			if key == 'BSSID':
				item = QStandardItem(str(data.get(key, '')))
				item.setData('AP_ITEM', Qt.UserRole)
				item.setData(data.get('SSID', ''), Qt.UserRole +1)
				item.setData(data.get('BSSID', ''), Qt.UserRole +2)
				item.setData(self.vendor_oui.get_mac_vendor_mixed(data.get('BSSID', '')), Qt.UserRole +3)
				items.append(item)
			if key == 'wps':
				item = QStandardItem(data['wps']['version'])
				item.setData(data['wps']['role'], Qt.UserRole + 4)
				item.setData(data['wps']['version'], Qt.UserRole + 5)
				items.append(item)
			else:
				if key not in ['SSID', 'BSSID']:
					items.append(QStandardItem(str(data.get(key, ''))))
		
		self.model.appendRow(items)
		self.table.setRowHeight(self.model.rowCount() - 1, 40)

	@pyqtSlot(str)
	def __add_probe(self, probe):
		probe = json.loads(probe)
		items = []
		for key in ['MAC', 'SSID', 'Vendor']:
			if key == 'MAC':
				mac = self.vendor_oui.get_mac_vendor_mixed(probe.get('MAC', ''))
				item = QStandardItem(QIcon('icons/investigation.png'), mac)
				items.append(item)
			else:
				items.append(QStandardItem(probe.get(key, '')))
		
		self.probes_table_model.appendRow(items)
		self.probes_table.setRowHeight(self.probes_table_model.rowCount() - 1, 40)
	
	@pyqtSlot(str, int, int, str)
	def __update_ap_role_by_bssid(self, bssid, role, col, value):
		row = self.find_row_by_userrole(bssid.upper(), 2) # Ищем по UserRole +2, где хранится BSSID
		if row != -1:
			item = self.model.item(row, col)
			if item:
				item.setData(value, Qt.UserRole + role)

	@pyqtSlot(str, int, str)
	def __update_ap_by_bssid(self, bssid, item, data):
		row = self.find_row_by_userrole(bssid.upper(), 2) # Ищем по UserRole +2, где хранится BSSID
		if row != -1:
			self.model.item(row, item).setText(str(data))

	@pyqtSlot(str, str)
	def __update_sta_data(self, bssid, data):
		sta_data = json.loads(data)
		row = self.find_row_by_userrole(bssid.upper(), 2) # Ищем по UserRole +2, где хранится BSSID
		if row != -1:
			if not self.has_nested_exists(row +1):
				first_item = self.model.item(row, 0)
				ssid = first_item.data(Qt.UserRole +1)
				subitem = QStandardItem("")
				sub_row = [QStandardItem("") for _ in range(self.model.columnCount())]
				sub_row[0] = subitem
				self.model.insertRow(row + 1, sub_row)
				self.table.setSpan(row + 1, 0, 1, 9)
				subitem_index = self.model.index(row + 1, 0)
				stations_table = StationsTable(self)
				stations_table.set_ssid(ssid)
				stations_table.add_sta(sta_data)
				
				self.table.setIndexWidget(subitem_index, stations_table)
				self.table.setRowHeight(row +1, 103)
				
				self.table.viewport().update()
			else:
				subitem_index = self.model.index(row + 1, 0)
				stations_table = self.table.indexWidget(subitem_index)
				stations_table.add_sta(sta_data)
				
				num_rows = stations_table.model.rowCount()
				new_height = max(75, ((num_rows * 40) + 64))
				self.table.setRowHeight(row +1, new_height)

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

	def safe_update_ap_role_by_bssid(self, bssid, role, col, value):
		QMetaObject.invokeMethod(self, "__update_ap_role_by_bssid", Qt.QueuedConnection, 
			   Q_ARG("QString", bssid),
			   Q_ARG("int", role),
			   Q_ARG("int", col),
			   Q_ARG("QString", value)
			)

	def safe_update_sta_data(self, bssid, data):
		QMetaObject.invokeMethod(self, "__update_sta_data", Qt.QueuedConnection, 
			   Q_ARG("QString", bssid),
			   Q_ARG("QString", data)
			)

	def safe_add_network(self, network):
		QMetaObject.invokeMethod(self, "__add_network", Qt.QueuedConnection, Q_ARG(str, network))

	def safe_add_probe(self, probe):
		QMetaObject.invokeMethod(self, "__add_probe", Qt.QueuedConnection, Q_ARG(str, probe))

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
			if len(pkt) < 12:
				continue

			if not self.running:
				if DEBUG:
					print("[+] pcap stopped")
				break

			wifi_pkt = Dot11Parser(pkt)
			channel_present = wifi_pkt.return_RadioTap_PresentFlag('Channel')
			channel = channel_present.get('channel', 0) if channel_present else 0
			channel_flags = channel_present.get('flags', 0) if channel_present else 'None'
			rssi = wifi_pkt.return_RadioTap_PresentFlag('dbm_Antenna_Signal') or -100
			rate = wifi_pkt.return_RadioTap_PresentFlag('Rate') or 0

			type_subtype = wifi_pkt.return_Dot11_frame_control()
			dot11frame = wifi_pkt.return_Dot11()

			if type_subtype == 0x40:
				wifi = WiFiHelper()
				elt = wifi_pkt.return_Dot11Elt()
				ssid = wifi.get_ap_ssid(wifi_pkt)
				vendor = wifi.get_ap_vendor(wifi_pkt)
				probe_addr = dot11frame.addr2

				if probe_addr not in self.probes:
					probe = {
						'MAC': probe_addr,
						'SSID': ssid,
						'Vendor': vendor 
					}
					self.probes[probe_addr] = probe
					self.safe_add_probe(json.dumps(probe))
				
				for ap_k, ap_v in self.access_points.items():
					if probe_addr in ap_v['clients']:
						#print(f'[+] Probe req: ssid="{ssid}", vendor="{vendor}" from {probe_addr}')
						if not probe_addr in self.access_points[ap_k]['clients'][probe_addr]['probes']:
							self.access_points[ap_k]['clients'][probe_addr]['probes'][probe_addr] = {
								'ssid': ssid,
								'vendor': vendor
							}
							self.safe_update_sta_data(ap_k, json.dumps(self.access_points[ap_k]['clients'][probe_addr]))

			if type_subtype == 0x94: # Block ACK req
				if dot11frame.addr2 in self.access_points:
					if dot11frame.addr1 in self.access_points[dot11frame.addr2]['clients']:
						self.access_points[dot11frame.addr2]['clients'][dot11frame.addr1]['list_items']['station_ChannelFlags'] = channel_flags
						self.access_points[dot11frame.addr2]['clients'][dot11frame.addr1]['list_items']['station_Rate'] = rate
						client = self.access_points[dot11frame.addr2]['clients'][dot11frame.addr1]
						self.safe_update_sta_data(dot11frame.addr2, json.dumps(client))

			if type_subtype in [0x08, 0x88]: # Data, QoS Data
				fc_flags = wifi_pkt.return_dot11_framecontrol_flags()
				flag_names = {f.name for f in fc_flags} # Делаем set для скорости
				
				# Проверка на мультикаст (нечетный первый байт ADDR1)
				is_multicast = int(dot11frame.addr1.split(':')[0], 16) & 1
				
				if not is_multicast and 'more_data' not in flag_names:
					to_ds       = 'to_ds' in flag_names
					from_ds     = 'from_ds' in flag_names
					is_direct   = False
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
					elif to_ds:
						#is_direct = (dot11frame.addr1 == dot11frame.addr3)
						is_direct = dot11frame.addr3 != 'ff:ff:ff:ff:ff:ff'# and is_direct # Исключаем широковещательные
						ap_addr = dot11frame.addr1 or dot11frame.addr3
						client_addr = dot11frame.addr2

					if is_direct:
						if ap_addr not in self.access_points:
							continue

						if client_addr not in self.access_points[ap_addr]['clients']:
							if DEBUG:
								print(f"[+] Detected client on {ap_addr} -> {client_addr}")
							client = {
								'list_items': {
									'station_MAC': self.vendor_oui.get_mac_vendor_mixed(client_addr),
									'station_dBm_AntSignal': rssi,
									'frames': 1,
									'station_Rate': rate,
									'station_ChannelFlags': channel_flags
								},
								'probes': {}
							}
							self.found_sta_cnt += 1
							self.safe_update_label(self.networksLabel, f"Networks: {self.found_ap_cnt} [{self.found_sta_cnt}]")
							self.access_points[ap_addr]['clients'][client_addr] = client
							self.safe_update_sta_data(ap_addr, json.dumps(client))
						else:
							self.access_points[ap_addr]['clients'][client_addr]['list_items']['frames'] += 1
							client = self.access_points[ap_addr]['clients'][client_addr]
							self.safe_update_sta_data(ap_addr, json.dumps(client))
						
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
			
				wps_version = '-'
				wps_locked = None
				wps_role = 'WPS_NONE'

				for ie in elt:
					if ie.ID == 221 and ie.INFO.type == 4 and ie.INFO.oui == '00:50:f2':
						wps_info = ie.INFO.data
						for wps_ie in wps_info:
							if wps_ie.ID == 0x104a and wps_ie.INFO == b'\x10':
								wps_version = '1.0'
							if wps_ie.ID == 0x1049:
								if hasattr(wps_ie.INFO, 'ID') and wps_ie.INFO.ID == '00:37:2a':
									wps_version = '2.0'
							if wps_ie.ID == 0x1057 and wps_ie.INFO == b'\x01':
								wps_locked = True
						
						wps_role = 'WPS_LOCKED' if wps_locked else 'WPS_UNLOCKED'
					
					
				if bssid in self.access_points:
					beacons = self.access_points[bssid]['beacons']
					beacons += 1
					self.access_points[bssid]['beacons'] = beacons

					self.safe_update_ap_role_by_bssid(bssid, 1, 0, ssid)          # Обновляем SSID в UserRole +1
					self.safe_update_ap_item_by_bssid(bssid, 1, str(channel))     # Обновляем канал
					self.safe_update_ap_item_by_bssid(bssid, 2, str(vendor))      # Обновляем вендора
					self.safe_update_ap_item_by_bssid(bssid, 3, str(rssi))        # Обновляем RSSI
					self.safe_update_ap_item_by_bssid(bssid, 4, str(enc_type))    # Обновляем тип шифрования
					self.safe_update_ap_item_by_bssid(bssid, 5, str(unicast_pair_suites)) # Обновляем парные шифры
					self.safe_update_ap_item_by_bssid(bssid, 6, str(akm_suites))  # Обновляем шифры аутентификации
					self.safe_update_ap_item_by_bssid(bssid, 7, str(wps_version)) # Обновляем WPS
					self.safe_update_ap_item_by_bssid(bssid, 8, str(beacons))     # Обновляем маяки
					self.safe_update_ap_role_by_bssid(bssid, 4, 7, wps_role)
					self.safe_update_ap_role_by_bssid(bssid, 5, 7, wps_version)
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
						"wps": {
							"version": wps_version,
							"locked": wps_locked,
							"role": wps_role
						},
						"beacons": 1,
						"clients": {}
					}
					self.found_ap_cnt += 1
					self.access_points[bssid] = ap_info
					self.safe_add_network(json.dumps(ap_info))			


if __name__ == "__main__":
	app = QApplication(sys.argv)
	window = WiFiManager()
	window.show()
	sys.exit(app.exec_())