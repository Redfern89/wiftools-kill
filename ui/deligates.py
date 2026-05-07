from PyQt5.QtWidgets import (
	QStyledItemDelegate, QStyleOptionProgressBar, QStyle
)

from PyQt5.QtGui import QIcon, QPainter, QColor, QFont, QPalette
from PyQt5.QtCore import Qt, QRect

from datetime import datetime

def scale_rssi(rssi_value, min_rssi=-90, max_rssi=-40, new_min=0, new_max=100):
	return max(new_min, min(new_max, (rssi_value - min_rssi) * (new_max - new_min) / (max_rssi - min_rssi) + new_min))

class MACDeligate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		state = index.data(Qt.UserRole)
		hwmac = index.data(Qt.UserRole +1)
		mac = index.data(Qt.UserRole +2)

		if state == 'MAC':
			painter.save()

			font = QFont()
			font.setBold(True)
			painter.setFont(font)
			icon = QIcon('resources/icons/chip.png')
			icon_rect = QRect(option.rect.left(), option.rect.top() + 20, 16, 16)
			icon.paint(painter, icon_rect, Qt.AlignLeft | Qt.AlignVCenter)
			painter.drawText(option.rect.adjusted(0, -20, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, mac.upper())
			
			font.setBold(False)
			painter.setFont(font)
			painter.setPen(Qt.gray)
			painter.drawText(option.rect.adjusted(18, 15, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, hwmac.upper())

			painter.restore()
		else:
			super().paint(painter, option, index)

class BSSIDDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		mixed_mac = index.data(Qt.DisplayRole)
		item_type = index.data(Qt.UserRole)
		ssid = index.data(Qt.UserRole +1)
		bssid = index.data(Qt.UserRole +2)
		saved = index.data(Qt.UserRole +3)
		saved_date = index.data(Qt.UserRole +4)
		hidden_net = index.data(Qt.UserRole +5)
		
		if item_type == 'AP_ITEM':
			painter.save()

			icon = QIcon('resources/icons/wireless-router.png')
			icon.paint(painter, option.rect.adjusted(1, 1, -1, -1), Qt.AlignLeft | Qt.AlignVCenter)
			font = QFont()
			font.setBold(True)
			painter.setFont(font)

			if saved == 'SAVED':
				icon = QIcon('resources/icons/diskette.png')
				rect = QRect(option.rect.x() +20, option.rect.y() +20, 16, 16)
				icon.paint(painter, rect, Qt.AlignLeft | Qt.AlignVCenter)
				painter.setPen(QColor('#3B9400'))
				font.setUnderline(True)
				painter.setFont(font)

			if option.state & QStyle.State_Selected:
				#painter.fillRect(option.rect, option.palette.highlight())
				painter.setPen(option.palette.highlightedText().color())

			if hidden_net == 'HIDDEN':
				font.setUnderline(True)
				painter.setFont(font)
				painter.setPen(Qt.red)
				font.setUnderline(False)
				ssid = '<hidden>'

			painter.drawText(option.rect.adjusted(40, -20, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, ssid)
			font.setBold(False)
			font.setUnderline(False)
			painter.setFont(font)
			if option.state & QStyle.State_Selected:
				painter.setPen(option.palette.highlightedText().color())
			else:
				painter.setPen(Qt.gray)
			
			mac_text_font = QFont("Courier New", 10)
			painter.setFont(mac_text_font)
			painter.drawText(option.rect.adjusted(40, 25, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, mixed_mac)

			painter.restore()
		else:
			super().paint(painter, option, index)

class ProgressBarDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
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

		progress_option.palette = option.palette

		if progress_option.progress > 55:
			color = QColor("#2ecc71") # Зеленый
		elif progress_option.progress > 45:
			color = QColor("#f1c40f") # Желтый
		else:
			color = QColor("#e74c3c") # Красный

		progress_option.palette.setColor(QPalette.Highlight, color) # Зеленый
		progress_option.palette.setColor(QPalette.HighlightedText, Qt.white)
		progress_option.state |= QStyle.State_Enabled

		painter.save()
		painter.setRenderHint(QPainter.Antialiasing)
		option.widget.style().drawControl(QStyle.CE_ProgressBar, progress_option, painter)
		painter.restore()

	def createEditor(self, parent, option, index):
		return None

class WPSDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		state = index.data(Qt.UserRole)
		version = index.data(Qt.DisplayRole)
		if version:
			version = float(version)
			version = f'{version:.1f}'
		
		if state in ['WPS_LOCKED', 'WPS_UNLOCKED']:
			font = QFont(option.font)
			painter.save()
			
			painter.setFont(font)
			if state == 'WPS_LOCKED':
				painter.setPen(Qt.red)
				font.setUnderline(True)
				icon = QIcon('resources/icons/padlock.png')
			else:
				icon = QIcon('resources/icons/unlocked.png')

			if option.state & QStyle.State_Selected:
				painter.setPen(Qt.white)

			painter.setFont(font)

			icon_size = 16
			wps_rect = option.rect.adjusted(20, 0, 0, 0)
			icon_rect = QRect(option.rect.left(), option.rect.top()+12, icon_size, icon_size)
			icon.paint(painter, icon_rect, Qt.AlignLeft | Qt.AlignVCenter)
			painter.drawText(wps_rect, Qt.AlignLeft | Qt.AlignVCenter, version)
			painter.restore()
		else:
			super().paint(painter, option, index)
			
class MonoFontDelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def initStyleOption(self, option, index):
		super().initStyleOption(option, index)
		option.font = QFont("Courier New", 10)

		if index.data(Qt.DisplayRole) == 'Unknown':
			option.palette.setColor(QPalette.Text, Qt.red)

class STADelegate(QStyledItemDelegate):
	def __init__(self, parent=None):
		super().__init__(parent)

	def paint(self, painter, option, index):
		state = index.data(Qt.UserRole)
		mac = index.data(Qt.DisplayRole)
		date = index.data(Qt.UserRole +1)
		#if date:
		#	date = datetime.fromtimestamp(date).strftime('%d.%m.%Y %H:%M')

		if state == 'EAPOL_DONE':
			painter.save()
			font = QFont()
			font.setBold(True)
			font.setUnderline(True)
			painter.setPen(QColor("#3b9400"))
			painter.setFont(font)
			icon = QIcon('resources/icons/signal.png')
			icon.paint(painter, option.rect.adjusted(4, 4, -4, -4), Qt.AlignLeft | Qt.AlignVCenter)
			icon_done = QIcon('resources/icons/check-mark.png')
			icon_done_rect = QRect(option.rect.left() + 20, option.rect.top() +24, 16, 16)
			icon_done.paint(painter, icon_done_rect, Qt.AlignLeft | Qt.AlignVCenter)
			painter.drawText(option.rect.adjusted(40, -20, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, mac)

			font.setBold(False)
			font.setUnderline(False)
			font.setItalic(True)
			painter.setFont(font)
			painter.setPen(Qt.gray)

			icon = QIcon('resources/icons/diskette.png')
			icon_rect = QRect(option.rect.left() + 37, option.rect.top() + 20, 16, 16)
			icon.paint(painter, icon_rect, Qt.AlignLeft | Qt.AlignVCenter)
			painter.drawText(option.rect.adjusted(57, +18, 0, 0), Qt.AlignLeft | Qt.AlignVCenter, date)
			painter.restore()
		else:
			super().paint(painter, option, index)

class TargetSTADelegate(QStyledItemDelegate):
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
		saved_date = index.data(Qt.UserRole +2)
		if saved_date:
			saved_date = datetime.fromtimestamp(saved_date).strftime('%d.%m.%Y %H:%M')
		else:
			saved_date = '(SAVED)'

		if index.column() == 0 and eapol_flag in ['EAPOL', 'SAVED']:

			states = {
				'EAPOL': {
					'color': '#FF0000',
					'icon': 'resources/icons/key.png',
					'text': '(EAPOL)'
				},
				'SAVED': {
					'color': '#3B9400',
					'icon': 'resources/icons/diskette.png',
					'text': saved_date
				}
			}

			text = index.data(Qt.DisplayRole)
			painter.save()

			icon = index.data(Qt.DecorationRole)
			icon_size = option.decorationSize.width() if icon else 0
			padding = 5
			text_x = option.rect.x() + icon_size + (padding if icon else 0)
			text_y = option.rect.y() + 2

			font_metrics = painter.fontMetrics()
			line_height = font_metrics.height()

			if icon:
				icon_rect = QRect(option.rect.x() +3, option.rect.y() +3, icon_size, icon_size)
				icon.paint(painter, icon_rect, Qt.AlignVCenter)
			
			font = QFont()
			font.setBold(True)
			font.setUnderline(True)
			painter.setFont(font)
			painter.setPen(QColor(states[eapol_flag]['color']))
			
			painter.drawText(text_x, text_y-1, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, text)
			font.setUnderline(False)
			font.setBold(False)
			font.setItalic(True)
			painter.setFont(font)
			painter.setPen(QColor(Qt.gray))
			painter.drawText(text_x +17, text_y + line_height + 3, option.rect.width() - text_x, line_height, Qt.AlignLeft | Qt.AlignTop, states[eapol_flag]['text'])

			eapol_icon = QIcon(states[eapol_flag]['icon'])
			eapol_icon_rect = QRect(option.rect.x() + icon_size +2, option.rect.y() + line_height +5, 16, 16)
			eapol_icon.paint(painter, eapol_icon_rect, Qt.AlignVCenter)

			icon_done = QIcon('resources/icons/check-mark.png')
			icon_done_rect = QRect(option.rect.left() + 18, option.rect.top() +24, 16, 16)
			icon_done.paint(painter, icon_done_rect, Qt.AlignLeft | Qt.AlignVCenter)

			painter.restore()
		else:
			super().paint(painter, option, index)