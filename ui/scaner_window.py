from PyQt5.QtWidgets import (
	QAbstractItemView, QLabel, QMainWindow, QTableView, QVBoxLayout, QHBoxLayout, QPushButton, 
	QMessageBox, QApplication, QWidget, QStatusBar, QTabWidget, QTreeView
)
from PyQt5.QtGui import QFont, QPixmap, QStandardItemModel, QStandardItem, QIcon, QPainter, QColor
from PyQt5.QtCore import Q_ARG, QMetaObject, QEvent, Qt, QSize, QItemSelection, QTimer

from ui.deligates import BSSIDDelegate, ProgressBarDelegate, WPSDelegate, MonoFontDelegate, STADelegate, ProbeBSSIDDelegate
from ui.controls import Controls

class StationsTable(QWidget, Controls):
	def __init__(self, parent=None, core=None):
		super().__init__(parent)
		layout = QVBoxLayout(self)
		self.core = core
		self.running = False
		layout.setContentsMargins(35, 5, 5, 5)

		top_layout = QHBoxLayout()
		top_layout.setContentsMargins(0, 0, 0, 0)
		
		self.assocIconLabel = QLabel()
		self.assocIconLabel.setPixmap(QPixmap('resources/icons/satellite-dish.png').scaled(24, 24, Qt.KeepAspectRatio))
		self.assocIconLabel.setFixedWidth(24)
		
		assocLabelFont = QFont()
		assocLabelFont.setBold(True)
		assocLabelFont.setPointSize(12)
		self.assocLabel = QLabel('Associated stations:')
		self.assocLabel.setFont(assocLabelFont)
		
		self.sta_table = QTableView(self)
		self.sta_table_model = QStandardItemModel(0, 6, self)
		self.sta_table_model.setHorizontalHeaderLabels(self.core.Translations.getlist('sta_table_labels'))

		self.sta_table.setModel(self.sta_table_model)
		self.sta_table.horizontalHeader().setStretchLastSection(True)
		self.sta_table.setEditTriggers(QTableView.NoEditTriggers)
		self.sta_table.setShowGrid(False)
		self.sta_table.verticalHeader().setVisible(False)
		self.sta_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.sta_table.setIconSize(QSize(32, 32))

		self.sta_table.setSelectionMode(QAbstractItemView.NoSelection)
		self.sta_table.setFocusPolicy(Qt.NoFocus)
		
		self.sta_deligate = STADelegate(self.sta_table)
		self.sta_table.setItemDelegateForColumn(0, self.sta_deligate)
		self.sta_table.setItemDelegateForColumn(1, ProgressBarDelegate(self.sta_table))

		self.sta_table.setColumnWidth(0, 200)  # MAC
		self.sta_table.setColumnWidth(1, 300)  # RSSI
		self.sta_table.setColumnWidth(2, 70)   # Frames
		self.sta_table.setColumnWidth(3, 100)  # Rate
		self.sta_table.setColumnWidth(4, 200)  # Modulation
		self.sta_table.setColumnWidth(5, 100)  # Probes

		top_layout.addWidget(self.assocIconLabel)
		top_layout.addWidget(self.assocLabel)
		layout.addLayout(top_layout)
		layout.addWidget(self.sta_table)
		self.setLayout(layout)

	def set_ssid(self, ssid):
		self.assocLabel.setText(self.core.Translations.gettext(
			'assoc_sta_label',
			ssid=ssid
		))
	
	def set_sta_saved(self, sta_addr: str, date: str):
		self.update_item_role(
			self.sta_table_model,
			col=0,
			search_role_index=2,
			search_role_val=sta_addr,
			set_role_index=0,
			set_role_val='EAPOL_DONE'
		)
		self.update_item_role(
			self.sta_table_model,
			col=0,
			search_role_index=2,
			search_role_val=sta_addr,
			set_role_index=1,
			set_role_val=date
		)

	def make_channel_mcs(self, sta_data):
		rate = 0
		if sta_data['mcs']:
			mcs_rate = sta_data['mcs'].decoded.rate
			modulation = sta_data['mcs'].decoded.modulation
			coding = sta_data['mcs'].decoded.coding_rate

			channel_flags = f"{'+'.join(sta_data['channel'].flags)}\nCoding: {coding}"
			rate = f"{mcs_rate} MB/s\n{modulation}"
		else:
			rate = f"{sta_data['rate']} MB/s"
			channel_flags = '+'.join(sta_data['channel'].flags)

		return rate, channel_flags

	def update_sta(self, sta_addr, sta_data):
		sta_mac = sta_data['addrs']['client_addr'].lower()
		if sta_mac:
			sta_addr = sta_data['addrs']['client_addr']
			row = self.find_row_by_userrole(
				baseModel=self.sta_table_model,
				col=2,
				role_val=sta_addr,
				role_index=0
			)

			rate, channel_flags = self.make_channel_mcs(sta_data)

			if row != -1:
				self.sta_table_model.item(row, 1).setText(str(sta_data['rssi']))
				self.sta_table_model.item(row, 2).setText(str(sta_data['frames']))
				self.sta_table_model.item(row, 3).setText(rate)
				self.sta_table_model.item(row, 4).setText(channel_flags)

	def add_sta(self, sta_addr, sta_data):
		sta_mac = sta_data['addrs']['client_addr'].lower()
		if sta_mac:
			sta_addr_mixed = self.core.VendorOUI.get_oui_name_mixed(sta_addr)

			rate, channel_flags = self.make_channel_mcs(sta_data)

			row = []
			mac_item = QStandardItem(QIcon('resources/icons/signal.png'), sta_addr_mixed)
			mac_item.setData(sta_addr, Qt.UserRole +2)

			row.append(mac_item)
			rssi_item = QStandardItem(str(sta_data['rssi']))
			rssi_item.setData('RSSI', Qt.UserRole)
			row.append(rssi_item)
			row.append(QStandardItem(str(sta_data['frames'])))
			row.append(QStandardItem(rate))
			row.append(QStandardItem(channel_flags))
			row.append(QStandardItem('')) # Probes - заполняется позже
				
			self.sta_table_model.appendRow(row)
			self.sta_table.setRowHeight(self.sta_table_model.rowCount() -1, 40)

class ScannerWindow(QMainWindow, Controls):
	def __init__(self, core=None):
		super().__init__()

		self.core = core
		self.signals = self.core.UISignals
		self.interface = None
		self.running = False
		self.centralWidget = QWidget()
		self.setCentralWidget(self.centralWidget)

		self.setFixedSize(1180, 620)
		self.setWindowTitle("WiFi Scanner advanced")

		self.mainLayout = QVBoxLayout(self.centralWidget)
		self.topLayout = QHBoxLayout()
		
		self.select_adapter_button = self.create_button(
			'select_adapter_button',
			'ethernet',
			self.on_select_adapter_button
		)

		self.start_button = self.create_button(
			'start_button',
			'refresh',
			self.on_start_btn,
			False
		)

		self.stop_button = self.create_button(
			'stop_button',
			'cancelled',
			self.on_stop_btn,
			False
		)

		self.target_button = self.create_button(
			'select_target_buton',
			'target',
			self.core.UISignals.target.show_signal.emit
		)

		self.hex_button = self.create_button(
			'hex_button',
			'binary-code'
		)

		self.settings_button = self.create_button(
			'settings_button',
			'settings'
		)

		self.handshakes_button = self.create_button(
			'handshakes_button',
			'key',
			self.core.UISignals.handshakes.show_signal.emit
		)

		self.topLayout.addWidget(self.select_adapter_button)
		self.topLayout.addWidget(self.start_button)
		self.topLayout.addWidget(self.stop_button)
		self.topLayout.addWidget(self.target_button)
		self.topLayout.addWidget(self.hex_button)
		self.topLayout.addWidget(self.settings_button)
		self.topLayout.addWidget(self.handshakes_button)

		self.access_points_table = QTableView(self)
		self.access_points_table_model = QStandardItemModel(0, 9, self)
		self.access_points_table_model.setHorizontalHeaderLabels(self.core.Translations.getlist('access_points_table_labels'))
		self.access_points_table.setModel(self.access_points_table_model)
		self.access_points_table.horizontalHeader().setStretchLastSection(True)
		self.access_points_table.setEditTriggers(QTableView.NoEditTriggers)
		self.access_points_table.setShowGrid(False)
		self.access_points_table.verticalHeader().setVisible(False)
		self.access_points_table.setSelectionBehavior(QTableView.SelectRows)
		self.access_points_table.setIconSize(QSize(32, 32))
		self.access_points_table.doubleClicked.connect(self.select_target)

		self.access_points_table.setColumnWidth(0, 200) # BSSID
		self.access_points_table.setColumnWidth(1, 60)  # Channel
		self.access_points_table.setColumnWidth(2, 90)  # Vendor
		self.access_points_table.setColumnWidth(3, 350) # RSSI
		self.access_points_table.setColumnWidth(4, 100) # Encryption
		self.access_points_table.setColumnWidth(5, 100) # Cipher
		self.access_points_table.setColumnWidth(6, 100) # AKM
		self.access_points_table.setColumnWidth(7, 70)  # WPS
		self.access_points_table.setColumnWidth(8, 40)  # Beacons

		self.access_points_table.setItemDelegateForColumn(0, BSSIDDelegate(self.access_points_table))
		self.access_points_table.setItemDelegateForColumn(2, MonoFontDelegate(self.access_points_table))
		self.access_points_table.setItemDelegateForColumn(3, ProgressBarDelegate(self.access_points_table))
		self.access_points_table.setItemDelegateForColumn(7, WPSDelegate(self.access_points_table))

		self.probes_tree = QTreeView(self)
		self.probes_tree_model = QStandardItemModel(0, 5, self)
		self.probes_tree_model.setHorizontalHeaderLabels(self.core.Translations.getlist('probes_table_labels'))

		self.probes_tree.setModel(self.probes_tree_model)
		self.probes_tree.setEditTriggers(QTableView.NoEditTriggers)
		self.probes_tree.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
		self.probes_tree.setIconSize(QSize(32, 32))
		self.probes_tree.setItemDelegateForColumn(0, ProbeBSSIDDelegate(self.probes_tree))
		self.probes_tree.setItemDelegateForColumn(2, MonoFontDelegate(self.probes_tree))
		self.probes_tree.setItemDelegateForColumn(3, ProgressBarDelegate(self.probes_tree))

		self.probes_tree.setColumnWidth(0, 250) # INFO
		self.probes_tree.setColumnWidth(1, 50)  # Channel
		self.probes_tree.setColumnWidth(2, 350) # Vendor
		self.probes_tree.setColumnWidth(3, 400) # RSSI
		self.probes_tree.setColumnWidth(4, 50) # Requests

		self.tabs = QTabWidget(self)

		self.scanner_tab = QWidget()
		self.scanner_layout = QVBoxLayout(self.scanner_tab)
		self.scanner_layout.addWidget(self.access_points_table)
		self.tabs.addTab(self.scanner_tab, self.core.Translations.gettext('scanner_tab'))

		self.probes_tab = QWidget()
		self.probes_layout = QVBoxLayout(self.probes_tab)
		self.probes_layout.addWidget(self.probes_tree)
		self.tabs.addTab(self.probes_tab, self.core.Translations.gettext('probes_tab'))

		self.tabs.setTabIcon(0, QIcon('resources/icons/satellite-dish.png'))
		self.tabs.setTabIcon(1, QIcon('resources/icons/broadcast-media.png'))

		self.mainLayout.addLayout(self.topLayout)
		self.mainLayout.addWidget(self.tabs)

		self.interfaceIconLabel = QLabel()
		self.interfaceIconLabel.setPixmap(QPixmap('resources/icons/cancelled.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.statusLabel = QLabel(self.core.Translations.gettext('iface_not_selected'))
		self.statusLabel.setFixedWidth(350)

		self.workIconLabel = QLabel()
		self.workIconLabel.setPixmap(QPixmap('resources/icons/clock-time.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.workLabel = QLabel('0d 00:00:00')
		self.workLabel.setFixedWidth(150)

		self.networksIconLabel = QLabel()
		self.networksIconLabel.setPixmap(QPixmap('resources/icons/menu.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.networksLabel = QLabel(self.core.Translations.gettext(
				'networks_count_label',
				found_ap_cnt=0,
				found_sta_cnt=0
			)
		)

		self.statusbar = QStatusBar()
		self.statusbar.addWidget(self.interfaceIconLabel)
		self.statusbar.addWidget(self.statusLabel)
		self.statusbar.addWidget(self.workIconLabel)
		self.statusbar.addWidget(self.workLabel)
		self.statusbar.addWidget(self.networksIconLabel)
		self.statusbar.addWidget(self.networksLabel)
		self.setStatusBar(self.statusbar)

	def update_counts(self, ap_cnt, sta_cnt):
		self.networksLabel.setText(self.core.Translations.gettext(
				'networks_count_label',
				found_ap_cnt=ap_cnt,
				found_sta_cnt=sta_cnt
			)
		)

	def on_channel_change(self, ch):
		self.statusLabel.setText(self.core.Translations.gettext(
				'hopper_status_label',
				iface=self.interface,
				channel=ch
			)
		)

	def on_select_iface(self, iface):
		self.interfaceIconLabel.setPixmap(QPixmap('resources/icons/satellite-dish.png').scaled(26, 26, Qt.KeepAspectRatio))
		self.interface = iface
		self.statusLabel.setText(self.core.Translations.gettext(
				'hopper_status_label',
				iface=iface,
				channel='?'
			)
		)
		self.start_button.setEnabled(True)
	
	def select_target(self):
		selected_indexes = self.access_points_table.selectionModel().selectedRows()
		if selected_indexes and self.interface and not self.running:
			row = selected_indexes[0].row()
			model = self.access_points_table.model()
			bssid = model.data(model.index(row, 0), Qt.UserRole +2)
			channel = model.data(model.index(row, 1))

			self.core.UISignals.target.show_signal.emit(self.interface, bssid, int(channel))

	def update_col_by_row(self, model: QStandardItemModel, row: int, col: int, val: str):
		item = model.item(row, col)
		if item:
			item.setData(val, Qt.DisplayRole)

	def on_start_btn(self):
		self.start_button.setEnabled(False)
		self.stop_button.setEnabled(True)
		self.target_button.setEnabled(False)
		self.select_adapter_button.setEnabled(False)
		self.running = True
		
		if self.signals:
			self.signals.scanner.start_signal.emit()

	def on_stop_btn(self):
		self.start_button.setEnabled(True)
		self.stop_button.setEnabled(False)
		self.target_button.setEnabled(True)
		self.select_adapter_button.setEnabled(True)
		self.running = False
		
		if self.signals:
			self.signals.scanner.stop_signal.emit()

	def on_select_adapter_button(self):
		if self.signals:
			self.signals.wifi.show_signal.emit()

	def add_ap(self, ap_data):
		row = []

		bssid = self.core.VendorOUI.get_oui_name_mixed(ap_data['bssid'])
		info_item = QStandardItem(QIcon('resources/icons/wireless-router.png'), bssid)
		info_item.setData('AP_ITEM', Qt.UserRole)
		info_item.setData(ap_data['ssid'], Qt.UserRole +1)
		info_item.setData(ap_data['bssid'], Qt.UserRole +2)
		if ap_data['ssid'] == '':
			info_item.setData('HIDDEN', Qt.UserRole +5)
		
		row.append(info_item)
		row.append(QStandardItem(str(ap_data['channel_data']['ch'])))
		row.append(QStandardItem(','.join(ap_data['vendors'])))
		rssi_item = QStandardItem(str(ap_data['rssi']))
		rssi_item.setData('RSSI', Qt.UserRole)
		row.append(rssi_item)
		row.append(QStandardItem('/'.join(ap_data['encryption']['type'])))
		row.append(QStandardItem(','.join(ap_data['encryption']['ciphers'])))
		row.append(QStandardItem(','.join(ap_data['encryption']['akm'])))
		
		wps_version = ap_data['wps']['version']
		wps_version = wps_version if wps_version else ''
	
		wps_item = QStandardItem('')
		if ap_data['wps']['enabled']:
			wps_role = 'WPS_LOCKED' if ap_data['wps']['locked'] else 'WPS_UNLOCKED' 
			wps_item.setData(str(ap_data['wps']['version']), Qt.DisplayRole)
			wps_item.setData(wps_role, Qt.UserRole)		

		row.append(wps_item)
		row.append(QStandardItem(str(ap_data['beacons'])))

		self.access_points_table_model.appendRow(row)
		self.access_points_table.setRowHeight(self.access_points_table_model.rowCount() - 1, 40)

	def update_ap(self, bssid, ap_data):
		row = self.find_row_by_userrole(
			baseModel=self.access_points_table_model,
			col=0,
			role_val=bssid,
			role_index=2
		)
		self.update_col_by_row(self.access_points_table_model, row, 1, str(ap_data['channel_data']['ch']))
		self.update_col_by_row(self.access_points_table_model, row, 3, str(ap_data['rssi']))
		self.update_col_by_row(self.access_points_table_model, row, 8, str(ap_data['beacons']))

	def set_ap_saved(self, bssid: str):
		self.update_item_role(
			baseModel=self.access_points_table_model,
			col=0,
			search_role_index=2,
			search_role_val=bssid,
			set_role_index=3,
			set_role_val='SAVED'
		)
	
	def set_ap_sta_saved(self, ap_addr: str, sta_addr: str, date: str):
		row = self.find_row_by_userrole(
			baseModel=self.access_points_table_model,
			col=0,
			role_val=ap_addr,
			role_index=2
		)
		if row != -1:
			if self.has_nested_exists(row +1):
				subitem_index = self.access_points_table_model.index(row + 1, 0)
				stations_table = self.access_points_table.indexWidget(subitem_index)
				stations_table.set_sta_saved(sta_addr, date)


	def has_nested_exists(self, row):
		for col in range(self.access_points_table_model.columnCount()):
			index = self.access_points_table_model.index(row, col)
			widget = self.access_points_table.indexWidget(index)
			if isinstance(widget, QWidget):
				return True
		
		return False

	def add_sta(self, ap_addr, sta_addr, sta_data):
		row = self.find_row_by_userrole(
			baseModel=self.access_points_table_model,
			col=0,
			role_val=ap_addr,
			role_index=2
		)
		if row != -1:
			if not self.has_nested_exists(row +1):					
				subitem = QStandardItem("")
				sub_row = [QStandardItem("") for _ in range(self.access_points_table_model.columnCount())]
				sub_row[0] = subitem
				self.access_points_table_model.insertRow(row + 1, sub_row)
				self.access_points_table.setSpan(row + 1, 0, 1, 9)
				subitem_index = self.access_points_table_model.index(row + 1, 0)
				stations_table = StationsTable(parent=self, core=self.core)
				
				first_item = self.access_points_table_model.item(row, 0)
				ssid = first_item.data(Qt.UserRole +1)
				stations_table.set_ssid(ssid)
				stations_table.add_sta(sta_addr, sta_data)

				self.access_points_table.setIndexWidget(subitem_index, stations_table)
				self.access_points_table.setRowHeight(row +1, 103)

			else:
				subitem_index = self.access_points_table_model.index(row + 1, 0)
				stations_table = self.access_points_table.indexWidget(subitem_index)
				stations_table.add_sta(sta_addr, sta_data)
					
				num_rows = stations_table.sta_table_model.rowCount()
				new_height = max(75, ((num_rows * 40) + 64))
				self.access_points_table.setRowHeight(row +1, new_height)	
	
	def update_sta(self, ap_addr, sta_addr, sta_data):
		row = self.find_row_by_userrole(
			baseModel=self.access_points_table_model,
			col=0,
			role_val=ap_addr,
			role_index=2
		)
		#print(f'[UI] Upodate STA. ROW={row}, STA={sta_addr}')
		if row != -1:
			if self.has_nested_exists(row +1):
				subitem_index = self.access_points_table_model.index(row + 1, 0)
				stations_table = self.access_points_table.indexWidget(subitem_index)
				stations_table.update_sta(sta_addr, sta_data)

	def add_probe_request(self, probe):
		row = []

		row_index = self.find_row_by_userrole(
			baseModel=self.probes_tree_model,
			col=0,
			role_val=probe['addr'],
			role_index=0
		)
		ssid = probe['ssid'].strip()

		probe_addr = self.core.VendorOUI.get_oui_name_mixed(probe['addr'])

		if row_index == -1:
			info_item = QStandardItem(
				QIcon('resources/icons/broadcast-media.png'), 
				probe_addr
			)
			info_item.setData(probe['addr'], Qt.UserRole)
			row.append(info_item)
			self.probes_tree_model.appendRow(row)

			probe_details_row = []
			ssid_item = QStandardItem(QIcon('resources/icons/signal.png'), ssid)
			
			if ssid == '' or len(ssid) == 0:
				ssid_item.setData('HIDDEN', Qt.UserRole)
			
			probe_details_row.append(ssid_item)
			probe_details_row.append(QStandardItem(str(probe['channel'])))
			probe_details_row.append(QStandardItem(','.join(probe['vendors'])))

			rssi_item = QStandardItem(str(probe['rssi']))
			rssi_item.setData('RSSI', Qt.UserRole)
			probe_details_row.append(rssi_item)
			probe_details_row.append(QStandardItem(str(probe['requests'])))

			info_item.appendRow(probe_details_row)
		else:
			info_item = self.probes_tree_model.item(row_index, 0)
			probe_details_row = []
			probe_details_row.append(QStandardItem(QIcon('resources/icons/signal.png'), ssid))
			probe_details_row.append(QStandardItem(str(probe['channel'])))
			probe_details_row.append(QStandardItem(','.join(probe['vendors'])))

			rssi_item = QStandardItem(str(probe['rssi']))
			rssi_item.setData('RSSI', Qt.UserRole)
			probe_details_row.append(rssi_item)
			probe_details_row.append(QStandardItem(str(probe['requests'])))

			info_item.appendRow(probe_details_row)

		self.probes_tree.expandAll()

	def update_probe_request(self, probe_addr, probe_ssid, probe_data):
		#print(f'[UI] Porbe update. addr={probe_addr}, ssid={probe_ssid}, data={probe_data}')
		pass

	def closeEvent(self, a0):
		if self.signals:
			self.signals.scanner.close_signal.emit()
		
		return super().closeEvent(a0)