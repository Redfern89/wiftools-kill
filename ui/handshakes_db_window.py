import sys
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, 
							 QHBoxLayout, QPushButton, QTreeView)
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont, QPainter
from PyQt5.QtCore import Qt, QSize
# Предполагаем, что ui.controls лежит рядом
from ui.controls import Controls
from ui.deligates import ProgressBarDelegate

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
			icon='diskette'
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
		self.tree_view = QTreeView()
		self.model = QStandardItemModel()
		self.model.setHorizontalHeaderLabels(['Точка доступа / Клиент', 'MAC-адрес', 'Статус'])
		
		self.tree_view.setModel(self.model)
		self.tree_view.header().setStretchLastSection(True)
		self.tree_view.setIconSize(QSize(24, 24))
		self.tree_view.setEditTriggers(QTreeView.NoEditTriggers)

		self.tree_view.setColumnWidth(0, 200)
		self.tree_view.setColumnWidth(1, 330)

		self.tree_view.setItemDelegateForColumn(1, ProgressBarDelegate(self.tree_view))
		
		layout.addWidget(self.tree_view)

	def update_data(self, data):
		if data:
			for bssid, ap in data.items():
				ap_item = QStandardItem(
					QIcon("resources/icons/wireless-router.png"),
					ap['ssid']
				)
				ap_mac  = QStandardItem(self.core.VendorOUI.get_oui_name_mixed(bssid))
				ap_date = QStandardItem(ap['date'])
				ap_row = [ap_item, ap_mac, ap_date]

				ap_sta = ap['stations']
				for sta_addr, sta_data in ap_sta.items():
					sta_item = QStandardItem(
						QIcon("resources/icons/key.png"),
						self.core.VendorOUI.get_oui_name_mixed(sta_addr)
					)
					ap_item.appendRow([sta_item, QStandardItem("")])
					eapol_messages = sta_data['messages']
					
					for message_type, message_data in eapol_messages.items():
						icon = 'right-arrow' if 'from_ds' in message_data['flags'] else 'left-arrow'
						message_item = QStandardItem(
							QIcon(f"resources/icons/{icon}.png"),
							f'{message_type}\nMESSAGE'
						)
						#direction = '>' if 'from_ds' in message_data['flags'] else '<'
						bssid_oui = self.core.VendorOUI.get_oui_name_mixed(bssid)
						sta_oui = self.core.VendorOUI.get_oui_name_mixed(sta_addr)

						#message_info = f"{bssid_oui} {direction} {sta_oui}\nRSSI: {message_data['rssi']} dBm"
						message_info_item = QStandardItem(str(message_data['rssi']))
						message_info_item.setData('RSSI', Qt.UserRole)
						message_date_item = QStandardItem(message_data['date'])
						
						sta_item.appendRow([message_item, message_info_item, message_date_item])
					
				self.model.appendRow(ap_row)
				self.tree_view.expandAll()