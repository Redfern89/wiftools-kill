import sys
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, 
							 QHBoxLayout, QPushButton, QTreeView, QFileDialog)
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont, QPainter
from PyQt5.QtCore import Qt, QSize, QItemSelection
# Предполагаем, что ui.controls лежит рядом
from ui.controls import Controls
from ui.deligates import ProgressBarDelegate, MessageItemDelegate

class HandshakesDBDialog(QDialog, Controls): # Убрал Controls для примера, верни если нужно
	def __init__(self, core=None, parent=None):
		super().__init__(parent)

		self.core = core
		self.init_ui()
	
	def init_ui(self):
		self.setWindowTitle("Handshake Manager")
		self.setWindowIcon(QIcon('resources/icons/key.png'))
		self.resize(800, 500)

		# В QDialog используем setLayout напрямую для окна
		layout = QVBoxLayout(self)

		# --- Верхние кнопки ---
		button_layout = QHBoxLayout()
		
		self.btn_save = self.create_button(
			text='save_to_pcap_button',
			icon='diskette',
			enabled=False,
			callback=self.save_pcap
		)
		self.btn_delete = self.create_button(
			text='delete_handshake_button',
			icon='dustbin'
		)
		self.btn_details = self.create_button(
			text='details_button',
			icon='binary-code'
		)
		
		button_layout.addWidget(self.btn_save)
		button_layout.addWidget(self.btn_delete)
		button_layout.addWidget(self.btn_details)

		layout.addLayout(button_layout)

		# --- Дерево (AP / STA) ---
		self.handshakes_db_tree = QTreeView()
		self.handshakes_db_tree_model = QStandardItemModel()
		self.handshakes_db_tree_model.setHorizontalHeaderLabels(['Точка доступа / Клиент', 'MAC-адрес', 'Статус'])
		
		self.handshakes_db_tree.setModel(self.handshakes_db_tree_model)
		self.handshakes_db_tree.header().setStretchLastSection(True)
		self.handshakes_db_tree.setIconSize(QSize(32, 32))
		self.handshakes_db_tree.setEditTriggers(QTreeView.NoEditTriggers)
		self.handshakes_db_tree.selectionModel().selectionChanged.connect(self.on_selection_changed)

		self.handshakes_db_tree.setColumnWidth(0, 200)
		self.handshakes_db_tree.setColumnWidth(1, 330)

		self.handshakes_db_tree.setItemDelegateForColumn(0, MessageItemDelegate(self.handshakes_db_tree))
		self.handshakes_db_tree.setItemDelegateForColumn(1, ProgressBarDelegate(self.handshakes_db_tree))
		
		layout.addWidget(self.handshakes_db_tree)

	def save_pcap(self):
		role = self.get_selected_val(
			table=self.handshakes_db_tree,
			col=0,
			role=Qt.UserRole
		)
		bssid = self.get_selected_val(
			table=self.handshakes_db_tree,
			col=0,
			role=Qt.UserRole +1
		)
		sta_addr = self.get_selected_val(
			table=self.handshakes_db_tree,
			col=0,
			role=Qt.UserRole +2
		)
		if role == 'STA':
			self.save_sta(bssid=bssid, sta_addr=sta_addr)

	def save_sta(self, bssid, sta_addr):
		oui_bssid = self.core.VendorOUI.get_oui_name_mixed(bssid)
		oui_sta = self.core.VendorOUI.get_oui_name_mixed(sta_addr)
		file_name = f'{oui_bssid}_{oui_sta}'
		file_name = file_name.replace(':', '')
		file_filter = "PCAP Files (*.pcap);;Hashcat hc22000 (*.hc22000);;All files (*)"

		file_path, selected_filter = QFileDialog.getSaveFileName(
			parent=self,
			caption="Save handshake",
			directory=file_name,
			filter=file_filter
		)

		if file_path:
			self.core.UISignals.handshakes.db_get_data.emit(file_path, selected_filter, bssid, sta_addr)

	def on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
		indexes = selected.indexes()
		if not indexes:
			return
		
		index = indexes[0]
		item_type = index.data(Qt.UserRole)

		if item_type == 'STA':
			bssid    = index.data(Qt.UserRole +1)
			sta_addr = index.data(Qt.UserRole +2)
			self.btn_save.setEnabled(True)
		else:
			self.btn_save.setEnabled(False)

	def update_data(self, data):
		# Чистка блять!!!
		self.handshakes_db_tree_model.setRowCount(0)

		if data:
			for bssid, ap in data.items():
				ap_item = QStandardItem(
					QIcon("resources/icons/wireless-router.png"),
					ap['ssid']
				)
				ap_item.setData('AP', Qt.UserRole)
				ap_mac  = QStandardItem(self.core.VendorOUI.get_oui_name_mixed(bssid))
				ap_date = QStandardItem(ap['date'])
				ap_row = [ap_item, ap_mac, ap_date]

				ap_sta = ap['stations']
				for sta_addr, sta_data in ap_sta.items():
					sta_item = QStandardItem(
						QIcon("resources/icons/key.png"),
						self.core.VendorOUI.get_oui_name_mixed(sta_addr)
					)
					sta_item.setData('STA', Qt.UserRole)
					sta_item.setData(bssid, Qt.UserRole +1)
					sta_item.setData(sta_addr, Qt.UserRole +2)

					ap_item.appendRow([sta_item, QStandardItem("")])
					eapol_messages = sta_data['messages']
					
					for message_type, message_data in eapol_messages.items():
						message_item = QStandardItem(
							QIcon(f"resources/icons/message.png"),
							message_type
						)
						message_item.setData('MESSAGE', Qt.UserRole)
						message_item.setData(message_data['flags'], Qt.UserRole +1)
						message_info_item = QStandardItem(str(message_data['rssi']))
						message_info_item.setData('RSSI', Qt.UserRole)
						message_date_item = QStandardItem(message_data['date'])
						
						sta_item.appendRow([message_item, message_info_item, message_date_item])

					probes = sta_data['probes']
					for probe in probes:
						probe_item = QStandardItem(
							QIcon("resources/icons/broadcast-media.png"),
							'Probe request'
						)
						probe_ssid = QStandardItem(probe['ssid'])
						probe_date = QStandardItem(probe['date'])
						sta_item.appendRow([probe_item, probe_ssid, probe_date])

				ap_info_item = QStandardItem("WPA/WPS Info")
				ap_info_item.setData('AP_INFO', Qt.UserRole)

				ap_info_item.appendRow([QStandardItem("Enc: WPA/WPA2")])
				ap_info_item.appendRow([QStandardItem("Pair: AES,CCMP")])
				ap_info_item.appendRow([QStandardItem("AKM: SAE,802.1x")])
				ap_info_item.appendRow([QStandardItem("WPS: 1.0, Locked")])

				ap_item.appendRow([ap_info_item])
					
				self.handshakes_db_tree_model.appendRow(ap_row)
				#self.tree_view.expandAll()