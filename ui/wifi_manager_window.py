from PyQt5.QtWidgets import (
	QDialog, QTableView, QVBoxLayout, QHBoxLayout, QPushButton, 
	QMessageBox, QApplication, QStyledItemDelegate
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont, QPainter
from PyQt5.QtCore import Qt, QSize, QItemSelection, QTimer, QRect

from ui.controls import Controls
from ui.deligates import MACDeligate

class WiFiManager(QDialog, Controls):
	def __init__(self, core=None, parent=None):
		super().__init__(parent)

		self.phys = {}

		self.core = core
		self.setFixedSize(1120, 400)
		self.setWindowTitle(self.core.Translations.gettext('wifiman_window_title'))
		self.setWindowIcon(QIcon('resources/icons/ethernet.png'))

		self.table = QTableView(self)
		self.model = QStandardItemModel(0, 7, self)
		self.model.setHorizontalHeaderLabels([
			self.core.Translations.gettext('list_col_phy'),
			self.core.Translations.gettext('list_col_interface'),
			self.core.Translations.gettext('list_col_mac'),
			self.core.Translations.gettext('list_col_driver'),
			self.core.Translations.gettext('list_col_chipset'),
			self.core.Translations.gettext('list_col_state'),
			self.core.Translations.gettext('list_col_mode')
		])

		self.table.setModel(self.model)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setEditTriggers(QTableView.NoEditTriggers)
		self.table.setShowGrid(False)
		self.table.verticalHeader().setVisible(False)
		self.table.setSelectionBehavior(QTableView.SelectRows)
		self.table.setIconSize(QSize(32, 32))
		self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)
		self.table.setItemDelegateForColumn(2, MACDeligate(self.table))
		self.table.doubleClicked.connect(self.select_iface)

		# Настройки ширины колонок
		col_widths = [90, 150, 150, None, 350, None, None]
		for i, width in enumerate(col_widths):
			if width:
				self.table.setColumnWidth(i, width)

		# Кнопки
		self.btn_refresh = self.create_button(
			'refresh_button', 
			'refresh',
			self.core.UISignals.request_phys_signal.emit
		)
		self.btn_up = self.create_button(
			'up_button',
			'upward-arrow',
			self.iface_updown
		)
		self.btn_down = self.create_button(
			'down_button',
			'down-arrow',
			self.iface_updown
		)
		self.btn_mode = self.create_button(
			'mon_mode_button',
			'connections',
			self.iface_mode_change
		)
		self.btn_random_mac = self.create_button(
			'rnd_mac_button',
			'surprise-box'
		)

		# Размещение кнопок
		top_layout = QHBoxLayout()
		top_layout.addWidget(self.btn_refresh)
		top_layout.addWidget(self.btn_up)
		top_layout.addWidget(self.btn_down)
		top_layout.addWidget(self.btn_mode)
		top_layout.addWidget(self.btn_random_mac)
		top_layout.addStretch()

		self.btn_down.setEnabled(False)
		self.btn_up.setEnabled(False)
		self.btn_mode.setEnabled(False)
		self.btn_mode.setText("-")

		# Основной layout
		main_layout = QVBoxLayout()
		main_layout.addLayout(top_layout)
		main_layout.addWidget(self.table)
		self.setLayout(main_layout)

		self.compare_timer = QTimer()
		self.compare_timer.setInterval(1000)
		self.compare_timer.timeout.connect(self.core.UISignals.request_phys_signal.emit)
		self.compare_timer.start()

	def _get_selected_row(self):
		indexes = self.table.selectionModel().selectedIndexes()
		return indexes[0].row() if indexes else None

	def _get_value(self, row, column, role=Qt.DisplayRole):
		return self.model.data(self.model.index(row, column), role)
	
	def on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection):
		row = self._get_selected_row()

		if row is None:
			self.btn_down.setEnabled(False)
			self.btn_up.setEnabled(False)
			self.btn_mode.setEnabled(False)
			return

		state = self._get_value(row, 5, Qt.DisplayRole).lower()
		mode = self._get_value(row, 6, Qt.DisplayRole).lower()
		
		self.btn_mode.setEnabled(True)

		if mode == 'monitor':
			self.btn_mode.setText(self.core.Translations.gettext('sta_mode_button'))
		else:
			self.btn_mode.setText(self.core.Translations.gettext('mon_mode_button'))

		if state == 'up':
			self.btn_up.setEnabled(False)
			self.btn_down.setEnabled(True)
		else:
			self.btn_up.setEnabled(True)
			self.btn_down.setEnabled(False)

	def select_iface(self):
		row = self._get_selected_row()
		if row is None:
			return

		phy = self._get_value(row, 0).lower()
		iface = self._get_value(row, 1)
		mac = self._get_value(row, 2, Qt.DisplayRole)
		channels = self._get_value(row, 2, Qt.UserRole +3)

		self.core.UISignals.select_interface_signal.emit({
			'phy': phy,
			'iface': iface,
			'mac': mac,
			'channels': channels
		})

		self.accept()

	def iface_updown(self):
		row = self._get_selected_row()
		if row is None:
			return
		
		state = self._get_value(row, 5, Qt.DisplayRole).lower()
		iface = self._get_value(row, 1)

		QApplication.setOverrideCursor(Qt.WaitCursor)
		self.core.UISignals.iface_updown_signal.emit(iface, state)
		self.core.UISignals.request_phys_signal.emit()
		QApplication.restoreOverrideCursor()

	def iface_mode_change(self):
		row = self._get_selected_row()
		if row is None:
			return
		
		mode = self._get_value(row, 6, Qt.DisplayRole).lower()
		phy = self._get_value(row, 0).lower()
		iface = self._get_value(row, 1)

		QApplication.setOverrideCursor(Qt.WaitCursor)
		self.core.UISignals.change_iface_mode_signal.emit(phy, iface, mode)
		self.core.UISignals.request_phys_signal.emit()
		QApplication.restoreOverrideCursor()

	def update_phys_list(self, data):
		if data != self.phys:
			self.phys = data
			self.model.setRowCount(0)
			
			for phy, phydata in data.items():
				row = []
				row.append(QStandardItem(QIcon('resources/icons/ethernet.png'), phy))
				row.append(QStandardItem(phydata['iface']))
					
				macItem = QStandardItem(phydata['mac']['iface'])
				macItem.setData('MAC', Qt.UserRole)
				macItem.setData(phydata['mac']['hw'], Qt.UserRole +1)
				macItem.setData(phydata['mac']['iface'], Qt.UserRole +2)
				macItem.setData(phydata['channels'], Qt.UserRole +3)
				row.append(macItem)

				row.append(QStandardItem(phydata['driver']))
				row.append(QStandardItem(phydata['chipset']))
				row.append(QStandardItem('UP' if phydata['state'] else 'DOWN'))
				row.append(QStandardItem(phydata['mode']))

				self.model.appendRow(row)
				self.table.setRowHeight(self.model.rowCount() - 1, 40)
	
	def closeEvent(self, a0):

		return super().closeEvent(a0)