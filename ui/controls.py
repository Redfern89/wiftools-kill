from PyQt5.QtWidgets import QPushButton, QHBoxLayout, QVBoxLayout, QCheckBox, QSpinBox, QLabel, QComboBox, QProgressBar, QTableView
from PyQt5.QtGui import QIcon, QStandardItemModel
from PyQt5.QtCore import QSize, Qt

class Controls:

	def __init__(self, core=None):
		self.core = core
	
	def create_button(self, text, icon, callback=None, enabled=True, visible=True):
		btn = QPushButton(self.core.Translations.gettext(text))
		btn.setIcon(QIcon(f'resources/icons/{icon}.png'))
		btn.setIconSize(QSize(24, 24))
		btn.setEnabled(enabled)
		btn.setVisible(visible)
		if callback:
			btn.clicked.connect(callback)
		
		return btn
	
	def create_checkbox(self, label, setting, default=True, enabled=True):
		layout = QHBoxLayout()
		checkbox = QCheckBox()

		checkbox.stateChanged.connect(lambda v: self.core.Settings.set(setting, bool(v)))

		checkbox.setText(label)
		checkbox.setChecked(self.core.Settings.get(setting, default))
		checkbox.setEnabled(enabled)
		layout.addWidget(checkbox)
		layout.addStretch()

		return layout, checkbox

	def create_spinbox(self, label, min_val, max_val, settings_key, default, suffix=''):
		layout = QHBoxLayout()
		spinbox = QSpinBox()
		spinbox.setRange(min_val, max_val)
		
		val = int(self.core.Settings.get(settings_key, default))
		spinbox.setValue(val)
		spinbox.valueChanged.connect(lambda v: self.core.Settings.set(settings_key, v))

		layout.addWidget(QLabel(label))
		layout.addWidget(spinbox)
		if suffix:
			layout.addWidget(QLabel(suffix))
		layout.addStretch()

		return layout, spinbox

	def create_combobox(self, label, items, settings_key, default):
		layout = QHBoxLayout()
		layout.addWidget(QLabel(label))
		combobox = QComboBox()

		for key, val in items.items():
			combobox.addItem(f'{key}: {val}', key)

		combobox.currentIndexChanged.connect(
			lambda v: self.core.Settings.set(settings_key, combobox.itemData(v))
		)

		setting = int(self.core.Settings.get(settings_key, default))
		index = combobox.findData(setting)
		
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
		item = self.core.Translations.gettext(item)
		qLabel.setText(f"<b>{item}: </b>{val}")

	def get_table_selected_row(self, baseTable: any):
		indexes = baseTable.selectionModel().selectedIndexes()
		return indexes[0].row() if indexes else None

	def find_row_by_userrole(self, baseModel: QStandardItemModel, col: int, value: any, role_index: int):
		for row in range(baseModel.rowCount()):
			item = baseModel.item(row, col)
			if item and item.data(Qt.UserRole + role_index) == value:
				return row
		return -1

	def update_item_role(self, baseModel: QStandardItemModel, col: any, search_role_index: int, search_role_val: any, set_role_index: int, set_role_val: any):
		row = self.find_row_by_userrole(
			baseModel=baseModel,
			col=col,
			value=search_role_val,
			role_index=search_role_index
		)
		if row != -1:
			item = baseModel.item(row, col)
			item.setData(set_role_val, Qt.UserRole + set_role_index)
	
	def get_item_value(self, baseModel: QStandardItemModel, row: int, col: int, role=Qt.DisplayRole):
		return baseModel.data(baseModel.index(row, col), role)

	def get_selected_val(self, table: any, col: int, role=Qt.DisplayRole):
		index = table.currentIndex()
		if not index.isValid():
			return None
		
		if index.column() == col:
			index = index.sibling(index.row(), col)
			return index.data(role)