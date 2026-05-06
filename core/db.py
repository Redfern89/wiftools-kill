import sqlite3

class Database:
	def __init__(self):
		# Сразу подключаемся при создании объекта
		self.connection = sqlite3.connect('resources/db/wifi_scanner.db')
		self.init_tables()

	def execute_write(self, query, params=None):
		"""Для INSERT, UPDATE, DELETE"""
		cursor = self.connection.cursor()
		cursor.execute(query, params or ())
		self.connection.commit()
		return cursor

	def execute_read(self, query, params=None):
		"""Для SELECT (без commit)"""
		cursor = self.connection.cursor()
		cursor.execute(query, params or ())
		return cursor

	def init_tables(self):
		self.execute_write('''
			CREATE TABLE IF NOT EXISTS access_points (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				bssid TEXT NOT NULL,
				beacon BLOB,
				date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
		''')
		self.execute_write('''
			CREATE TABLE IF NOT EXISTS stations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ap_id INTEGER NOT NULL,
				sta TEXT NOT NULL,
				eapol BLOB,
				message_type TEXT,
				date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
		''')
		# Индекс ускорит поиск в sta_exists в сотни раз, когда база вырастет
		self.execute_write('CREATE INDEX IF NOT EXISTS idx_ap_id_sta ON stations(ap_id, sta);')
		self.execute_write('CREATE UNIQUE INDEX IF NOT EXISTS idx_bssid ON access_points(bssid);')

	def sta_exists(self, ap_id, sta):
		cursor = self.execute_read('SELECT 1 FROM stations WHERE ap_id = ? AND sta = ? LIMIT 1;', (ap_id, sta))
		return cursor.fetchone() is not None

	def get_ap_id(self, bssid):
		cursor = self.execute_read('SELECT id FROM access_points WHERE bssid = ? LIMIT 1;', (bssid,))
		result = cursor.fetchone()
		if result:
			return result[0]
		
		# Делаем вставку и сразу забираем ID до коммита или через спец. метод
		cursor = self.connection.cursor()
		cursor.execute('INSERT INTO access_points (bssid) VALUES (?);', (bssid,))
		ap_id = cursor.lastrowid
		self.connection.commit()
		return ap_id

	def insert_handshake(self, bssid, sta, eapol_data, message_type):
		ap_id = self.get_ap_id(bssid)
		if not self.sta_exists(ap_id, sta):
			self.execute_write('''
				INSERT INTO stations (ap_id, sta, eapol, message_type) 
				VALUES (?, ?, ?, ?);
			''', (ap_id, sta, eapol_data, message_type))

	def get_handshake(self, ap_id, sta):
		cursor = self.execute_read(''''
			SELECT eapol, message_type FROM stations 
			WHERE ap_id = ? AND sta = ? LIMIT 1;
		''', (ap_id, sta))
		return cursor.fetchone()  # Вернет (eapol, message_type) или None

	def close(self):
		if self.connection:
			self.connection.close()