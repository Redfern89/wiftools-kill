
from PyQt5 import QtWidgets

from PyQt5.QtWidgets import (
	QApplication, QTreeView, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView, QPushButton, QLabel, QProgressBar, 
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle, QComboBox, QSizePolicy, QMessageBox, QDialog, QTextEdit, QFileDialog,
	QMainWindow, QTableView, QGroupBox, QFrame, QSpinBox, QDoubleSpinBox, QCheckBox, QLayout, QMenu, QAction, QProxyStyle
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QPainter, QColor, QPen, QPainterPath, QFont, QKeyEvent, QPixmap, QPalette
from PyQt5.QtCore import Qt, QEvent, QSize, QTimer, QObject, QMetaObject, Q_ARG, pyqtSlot, QRect, QTimer, QPropertyAnimation, QEasingCurve, QCoreApplication, QItemSelection

from ui.controls import Controls
from ui.deligates import ProgressBarDelegate, TargetSTADelegate
import shutil

from core.misc import Helpers

from datetime import datetime

class DeauthDialog(QDialog, Controls):
	
	def __init__(self, core=None, interface=None, bssid=None, channel=None):
		super().__init__()

		self.core = core
		self.first_beacon_flag = False
		self.interface = interface
		self.target = self.core.VendorOUI.get_oui_name_mixed(bssid)
		self.bssid = bssid
		self.channel = str(channel)
		self.old_ap_rssi = None
		self.lost_becons = 0

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

	def init_ui(self):
		self.setWindowTitle(self.core.Translations.gettext(
			'target_window_title',
			bssid=self.target
		))
		self.setWindowIcon(QIcon('resources/icons/target.png'))
		# --- ЦЕНТРУЕМ ОКНО ---
		self.setFixedSize(1200, 600)

		# --- ВЕРХНИЙ БЛОК: Две колонки ---
		top_layout = QHBoxLayout()

		# Левая колонка (Статус)
		status_layout = QVBoxLayout()
		self.interface_label = self.create_status_label(
			self.core.Translations.gettext('interface_label'), 
			self.interface
		)
		self.ssid_label = self.create_status_label(
			self.core.Translations.gettext('ssid_label'), 
			self.core.Translations.gettext('empty_label')
		)
		self.bssid_label = self.create_status_label(
			self.core.Translations.gettext('bssid_label'), 
			self.target
		)
		self.saved_lbl_pixmap = QLabel()
		self.saved_lbl_pixmap.setPixmap(QPixmap('resources/icons/check-mark.png').scaled(16, 16, Qt.KeepAspectRatio))
		
		self.channel_label = self.create_status_label(
			self.core.Translations.gettext('channel_label'), 
			self.channel
		)
		self.beacons_label = self.create_status_label(
			self.core.Translations.gettext('beacons_label'), 
			0
		)
		self.lost_beacons_label = self.create_status_label(
			self.core.Translations.gettext('lost_beacons_label_key'), 
			0
		)

		rssi_progress_layout, self.rssi_progress = self.create_progress_bar(
			self.core.Translations.gettext('rssi_label'), 
			-90, -20, -90, "- dBm"
		)

		status_layout.addWidget(self.interface_label)
		status_layout.addWidget(self.ssid_label)
		bssid_layout = QHBoxLayout()

		bssid_layout.setSpacing(5)
		bssid_layout.addWidget(self.bssid_label)
		#if self.bssid.lower() in self.sta_done:
		#	bssid_layout.addWidget(self.saved_lbl_pixmap)
		bssid_layout.addStretch(1)
		
		status_layout.addLayout(bssid_layout)
		status_layout.addWidget(self.channel_label)
		status_layout.addWidget(self.beacons_label)
		status_layout.addWidget(self.lost_beacons_label)
		status_layout.addLayout(rssi_progress_layout)

		settings_layout = QVBoxLayout()

		deauth_packets_layout, self.deauth_retries_edit = self.create_spinbox(
			self.core.Translations.gettext('deauth_packets_label'), 
			1, 500, 'deauth_packets', 127
		)

		deauth_attempts_layout, self.deauth_attempts_edit = self.create_spinbox(
			self.core.Translations.gettext('deauth_attempts_label'),
			1, 100, 'deauth_attempts', 3
		)

		deauth_timeout_layout, self.deauth_timeout_edit = self.create_spinbox(
			self.core.Translations.gettext('deauth_timeout_label'),
			1, 10, 'deauth_timeout', 1, "сек"
		)

		deauth_reason_layout, self.deauth_reason_select = self.create_combobox(
			self.core.Translations.gettext('deauth_reason_label'), 
			self.deauth_reasons, 'deauth_reason', 3
		)

		hc22000_layout, self.hc22000_checkbox = self.create_checkbox(
			self.core.Translations.gettext('hc22000_checkbox'), 
			'create_hc2200', True,
			bool(shutil.which('hcxpcapngtool'))
		)
		deauth_dst_layout, self.deauth_dst_checkbox = self.create_checkbox(
			self.core.Translations.gettext('deauth_dst_checkbox'),
			'deauth_from_sta', True, True
		)

		settings_layout.addLayout(deauth_packets_layout)
		settings_layout.addLayout(deauth_attempts_layout)
		settings_layout.addLayout(deauth_timeout_layout)
		settings_layout.addLayout(deauth_reason_layout)
		settings_layout.addLayout(hc22000_layout)
		settings_layout.addLayout(deauth_dst_layout)

		# Добавляем две колонки в верхний блок
		top_layout.addLayout(status_layout, 2)  # Даем статусу больше места
		top_layout.addLayout(settings_layout, 1)  # Настройки чуть уже

		# Фиксируем размер верхнего блока, чтобы он не тянулся вниз
		top_layout.setSizeConstraint(QLayout.SetFixedSize)

		# --- СРЕДНИЙ БЛОК: Кнопки ---
		buttons_layout = QHBoxLayout()
		self.start_button = self.create_button(
			text='start_button', 
			icon='refresh',
			callback=self.start
		)
		self.stop_button = self.create_button(
			text='stop_button',
			icon='cancelled',
			callback=self.stop,
			enabled=False
		)
		self.deauth_button = self.create_button(
			text='deauth_button',
			icon='unlocked',
			callback=lambda: self.send_deauth(target="broadcast"),
			enabled=False
		)
		self.deauth_direct_button = self.create_button(
			text='deauth_direct_button',
			icon='unlock',
			callback=lambda: self.send_deauth(target="direct"),
			visible=False
		)

		buttons_layout.addWidget(self.start_button)
		buttons_layout.addWidget(self.stop_button)
		buttons_layout.addWidget(self.deauth_button)
		buttons_layout.addWidget(self.deauth_direct_button)
		buttons_layout.addStretch()

		# --- НИЖНИЙ БЛОК: Таблица ---
		self.stations_table = QTableView(self)
		self.stations_table_model = QStandardItemModel(0, 5, self)
		self.stations_table_model.setHorizontalHeaderLabels(self.core.Translations.getlist('target_sta_table_labels'))

		self.stations_table.setModel(self.stations_table_model)
		self.stations_table.horizontalHeader().setStretchLastSection(True)
		self.stations_table.setEditTriggers(QTableView.NoEditTriggers)
		self.stations_table.setShowGrid(False)
		self.stations_table.verticalHeader().setVisible(False)
		self.stations_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.stations_table.setIconSize(QSize(32, 32))
		self.stations_table.setItemDelegateForColumn(1, ProgressBarDelegate(self.stations_table))
		self.stations_table.setItemDelegateForColumn(0, TargetSTADelegate(self.stations_table, self))
		self.stations_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
		self.stations_table.setSelectionBehavior(QTableView.SelectRows)
		self.stations_table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		#self.stations_table.customContextMenuRequested.connect(self.stations_table_menu)

		# --- Рзамеры колонок в таблице ---
		self.stations_table.setColumnWidth(0, 200)  # MAC
		self.stations_table.setColumnWidth(1, 300)  # RSSI
		self.stations_table.setColumnWidth(2, 60)   # Frames
		self.stations_table.setColumnWidth(3, 100)  # ACKs
		self.stations_table.setColumnWidth(4, 100)  # Rate
		self.stations_table.setColumnWidth(5, 200)  # Modulation
		self.stations_table.setColumnWidth(6, 100)  # Flags
		self.stations_table.setColumnWidth(7, 100)  # Probes

		# Указываем, что таблица должна занимать оставшееся место
		self.stations_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

		self.log_table = QTableView()
		self.log_table_model = QStandardItemModel(0, 2, self)
		self.log_table_model.setHorizontalHeaderLabels(self.core.Translations.getlist('log_table_labels'))
		self.log_table.setModel(self.log_table_model)

		self.log_table.horizontalHeader().setStretchLastSection(True)
		self.log_table.setEditTriggers(QTableView.NoEditTriggers)
		self.log_table.setShowGrid(False)
		self.log_table.verticalHeader().setVisible(False)
		self.log_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.log_table.setIconSize(QSize(20, 20))
		self.log_table.setColumnWidth(0, 900)
		self.log_table.setFont(QFont("Courier New", 11))

		# --- ЛОГ ---
		self.log_textarea = QTextEdit()
		self.log_textarea.setFont(QFont("Courier New", 10))
		self.log_textarea.setReadOnly(True)

		# --- ОБЪЕДИНЯЕМ ВСЁ В ГЛАВНЫЙ ЛЭЙАУТ ---
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addLayout(buttons_layout)
		main_layout.addWidget(self.stations_table)  # Добавляем таблицу
		main_layout.addWidget(self.log_table)       # Добавляем лог

		self.setLayout(main_layout)

		self.lost_beacons_timer = QTimer()
		self.lost_beacons_timer.setInterval(1000)
		self.lost_beacons_timer.timeout.connect(self.update_lost_beacons)
		self.lost_beacons_timer.start()

		self.log('target', self.core.Translations.gettext(
			'target_msg',
			bssid=self.target
			)
		)

	def on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
		row = self.get_table_selected_row(self.stations_table)
		if row is None:
			self.deauth_direct_button.setVisible(False)
		else:
			sta_addr = self.stations_table_model.data(self.stations_table_model.index(row, 0), Qt.UserRole)
			sta_addr = self.core.VendorOUI.get_oui_name_mixed(sta_addr)
			self.deauth_direct_button.setVisible(True)
			self.deauth_direct_button.setText(self.core.Translations.gettext(
				'deauth_button_direct',
				sta_addr=sta_addr
			))

	def update_ap_rssi(self, value):
		self.rssi_progress.setValue(value)
		palette = self.rssi_progress.palette()
		
		if value > -55:
			color = QColor("#27ae60") # Зеленый (отличный сигнал)
		elif value > -70:
			color = QColor("#f1c40f") # Желтый (средне)
		else:
			color = QColor("#e74c3c") # Красный (плохо)
		
		palette.setColor(QPalette.Highlight, color)
		self.rssi_progress.setPalette(palette)
		self.rssi_progress.setFormat("%v dBm")
	
	def log(self, type, log):
		now = datetime.now()

		row = []
		row.append(QStandardItem(QIcon(f'resources/icons/{type}.png'), log))
		row.append(QStandardItem(now.strftime("%d.%m.%Y %H:%M:%S")))

		self.log_table_model.appendRow(row)
		self.log_table.scrollTo(self.log_table_model.index(self.log_table_model.rowCount() - 1, 0), QtWidgets.QTableView.PositionAtBottom)

	def update_lost_beacons(self):
		self.update_status_label(
			self.lost_beacons_label, 
			'lost_beacons_label_key', 
			self.core.Translations.gettext(
				'lost_beacons_label_val',
				beacons=self.lost_becons
			)
		)
		self.lost_becons = 0

	def set_first_data(self, data):
		self.first_beacon_flag = True
		self.update_status_label(
			self.ssid_label,
			'ssid_label',
			data['ssid']
		)
		self.log('satellite-dish', self.core.Translations.gettext(
			'recv_beacon_msg',
			ssid=data['ssid'],
			vendor=', '.join(data['vendors'])
		))

	def update_target_ap(self, data):
		rssi = data['rssi']
		
		if self.rssi_progress:
			if self.old_ap_rssi != rssi:
				self.old_ap_rssi = rssi
				self.update_ap_rssi(rssi)

		self.lost_becons += data['beacons_lost']
		self.update_status_label(
			self.beacons_label, 
			'beacons_label',
			data['beacons']
		
		)

	def start(self):
		self.log('refresh', self.core.Translations.gettext(
			'switching_iface_channel_msg',
			interface=self.interface,
			channel=self.channel
		))

		if not self.first_beacon_flag:
			self.log('pending', self.core.Translations.gettext(
				'waiting_beacon_msg',
				target=self.target
			))

		self.core.UISignals.target.start_signal.emit()
		self.start_button.setEnabled(False)
		self.stop_button.setEnabled(True)
		self.deauth_button.setEnabled(True)
		self.deauth_direct_button.setEnabled(True)

	def stop(self):
		self.core.UISignals.target.stop_signal.emit()
		self.start_button.setEnabled(True)
		self.stop_button.setEnabled(False)
		self.deauth_button.setEnabled(False)
		self.deauth_direct_button.setEnabled(False)

	def add_sta(self, sta_data):
		self.log('signal', self.core.Translations.gettext(
			'client_found_msg',
			client_addr=self.core.VendorOUI.get_oui_name_mixed(sta_data['sta_mac'])
		))

		row = []
		
		bssid = self.bssid.lower()
		mixed_mac = self.core.VendorOUI.get_oui_name_mixed(sta_data['sta_mac'])
		sta_mac = sta_data['sta_mac'].lower()
		acks_blocks = f"{sta_data['counters']['acks']} / {sta_data['counters']['blocks']}"

		rate = f"{sta_data['rate']} MB/s"
		channel_flags = '+'.join(sta_data['channel'].flags)

		if sta_data['mcs']:
			mcs_rate = sta_data['mcs'].decoded.rate
			mcs_modulation = sta_data['mcs'].decoded.modulation
			mcs_coding = sta_data['mcs'].decoded.coding_rate
			mcs_index = sta_data['mcs'].index

			rate = f"{mcs_rate} MB/s\n{mcs_modulation}"
			channel_flags = f"{'+'.join(sta_data['channel'].flags)}\nCoding: {mcs_coding}, MCS: {mcs_index}"
		
		mac_item = QStandardItem(QIcon('resources/icons/signal.png'), mixed_mac)
		mac_item.setData(sta_mac, Qt.UserRole)

		row.append(mac_item)
		rssi_item = QStandardItem(str(sta_data['rssi']))
		rssi_item.setData('RSSI', Qt.UserRole)
		row.append(rssi_item)
		row.append(QStandardItem(str(sta_data['counters']['frames'])))
		row.append(QStandardItem(str(acks_blocks)))
		row.append(QStandardItem(rate))
		row.append(QStandardItem(channel_flags))
		row.append(QStandardItem(''))
		row.append(QStandardItem(''))
		self.stations_table_model.appendRow(row)

		row_number = self.stations_table_model.rowCount() -1
		if row_number >= 0:
			self.stations_table.setRowHeight(row_number, 40)

	def update_sta(self, sta_addr, sta_data):
		row = self.find_row_by_userrole(self.stations_table_model, 0, sta_addr, 0)
		if row != -1:
			acks_blocks = f"{sta_data['counters']['acks']} / {sta_data['counters']['blocks']}"
			rate = f"{sta_data['rate']} MB/s"
			channel_flags = '+'.join(sta_data['channel'].flags)
			flags = ' '.join(sta_data['flags'])
			probes = ','.join(sta_data['probes'])

			if sta_data['mcs']:
				mcs_rate = sta_data['mcs'].decoded.rate
				mcs_modulation = sta_data['mcs'].decoded.modulation
				mcs_coding = sta_data['mcs'].decoded.coding_rate
				mcs_index = sta_data['mcs'].index

				rate = f"{mcs_rate} MB/s\n{mcs_modulation}"
				channel_flags = f"{'+'.join(sta_data['channel'].flags)}\nCoding: {mcs_coding}, MCS: {mcs_index}"

			self.stations_table_model.item(row, 1).setText(str(sta_data['rssi']))
			self.stations_table_model.item(row, 2).setText(str(sta_data['counters']['frames']))
			self.stations_table_model.item(row, 3).setText(acks_blocks)
			self.stations_table_model.item(row, 4).setText(rate)
			self.stations_table_model.item(row, 5).setText(channel_flags)
			self.stations_table_model.item(row, 6).setText(flags)
			self.stations_table_model.item(row, 7).setText(probes)

	def probe_request(self, probe_addr, ssid):
		self.log('investigation', self.core.Translations.gettext(
			'recv_probe_msg',
			ssid=ssid,
			probe_addr=self.core.VendorOUI.get_oui_name_mixed(probe_addr)
		))
	
	def eapol_message(self, src_addr, dst_addr, message):
		self.log('message', self.core.Translations.gettext(
			'recv_eapol_message_msg',
			message=message,
			src_addr=self.core.VendorOUI.get_oui_name_mixed(src_addr),
			dst_addr=self.core.VendorOUI.get_oui_name_mixed(dst_addr)
		))

	def eapol_done(self, sta_addr):
		self.log('diskette', self.core.Translations.gettext(
			'eapol_done_msg',
			sta_addr=self.core.VendorOUI.get_oui_name_mixed(sta_addr)
		))
		
		self.update_item_role(
			baseModel=self.stations_table_model,
			col=0,
			search_role_index=0,
			search_role_val=sta_addr,
			set_role_index=1,
			set_role_val='EAPOL'
		)

	def eapol_error(self, sta_addr, err_message):
		self.log('cancelled', self.core.Translations.gettext(
			'eapol_error_msg',
			err_msg=err_message,
			sta_addr=self.core.VendorOUI.get_oui_name_mixed(sta_addr)
		))

	def on_deauth(self, ap_addr, sta_addr, reason_code):
		self.log('logout', self.core.Translations.gettext(
			'sending_deauth_msg',
			sta_addr=self.core.VendorOUI.get_oui_name_mixed(sta_addr),
			ap_addr=self.core.VendorOUI.get_oui_name_mixed(ap_addr),
			reason_code=str(reason_code)
		))

	def send_deauth(self, target="broadcast"):
		self.deauth_button.setEnabled(False)
		self.deauth_direct_button.setEnabled(False)
		selected_indexes = self.stations_table.selectionModel().selectedRows()
		if selected_indexes and target=="direct":
			row = selected_indexes[0].row()
			sta_addr = self.stations_table_model.data(self.stations_table_model.index(row, 0), Qt.UserRole)
		elif target=="broadcast":
			sta_addr = 'ff:ff:ff:ff:ff:ff'

		reason_code = int(self.deauth_reason_select.itemData(self.deauth_reason_select.currentIndex()))
		attempts = int(self.deauth_attempts_edit.value())
		retries = int(self.deauth_retries_edit.value())
		timeout = int(self.deauth_timeout_edit.value())

		self.core.UISignals.target.send_deauth_signal.emit(self.bssid, sta_addr, reason_code, retries, attempts,timeout)

	def deauth_done(self):
		self.deauth_button.setEnabled(True)
		self.deauth_direct_button.setEnabled(True)

	def on_saved_sta_found(self, ap_addr, sta_addr, date):
		self.update_item_role(
			baseModel=self.stations_table_model,
			col=0,
			search_role_index=0,
			search_role_val=sta_addr,
			set_role_index=1,
			set_role_val='SAVED'
		)
		self.update_item_role(
			baseModel=self.stations_table_model,
			col=0,
			search_role_index=0,
			search_role_val=sta_addr,
			set_role_index=2,
			set_role_val=date
		)

	def closeEvent(self, a0):
		if self.core:
			self.core.UISignals.target.close_signal.emit()
		
		return super().closeEvent(a0)