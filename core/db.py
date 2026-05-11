import os
import sqlite3

class Database:
	def __init__(self):
		# Fucked directory
		if not os.path.exists('resources/db'):
			os.mkdir('resources/db')

		# Сразу подключаемся при создании объекта
		self.connection = sqlite3.connect(
			'resources/db/wifi_scanner.db',
			check_same_thread=False
		)
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
		self.execute_write('''
			CREATE TABLE IF NOT EXISTS probes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				probe_addr TEXT NOT NULL,
				ssid TEXT NOT NULL,
				date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			);
		''')
		# Индекс ускорит поиск в sta_exists в сотни раз, когда база вырастет
		self.execute_write('CREATE INDEX IF NOT EXISTS idx_ap_id_sta ON stations(ap_id, sta);')
		self.execute_write('CREATE UNIQUE INDEX IF NOT EXISTS idx_bssid ON access_points(bssid);')

	def sta_exists(self, ap_id, sta):
		cursor = self.execute_read('SELECT 1 FROM stations WHERE ap_id = ? AND sta = ? LIMIT 1;', (ap_id, sta))
		return cursor.fetchone() is not None

	def insert(self, table: str, fields: dict) -> int:
		columns = ', '.join(fields.keys())
		placeholders = ', '.join(['?'] * len(fields))
		values = tuple(fields.values())

		query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
		cursor = self.execute_write(query, values)

		return cursor.lastrowid

	def row_exists(self, table: str, criteria: dict) -> bool:
		keys = criteria.keys()
		where_clause = " AND ".join([f"{key} = ?" for key in keys])
		values = tuple(criteria.values())

		query = f"SELECT 1 FROM {table} WHERE {where_clause} LIMIT 1"
		
		cursor = self.execute_read(query, values)
		return cursor.fetchone() is not None

	def get_row(self, table: str, search_data: dict) -> dict:
		conditions = " AND ".join([f"{key} = ?" for key in search_data.keys()])
		values = tuple(search_data.values())
		
		query = f'SELECT * FROM {table} WHERE {conditions} LIMIT 1'
		cursor = self.execute_read(query, values)
		row = cursor.fetchone()

		if row:
			columns = [column[0] for column in cursor.description]
			return dict(zip(columns, row))
		
		return None
	
	def get_rows(self, table: str, search_data: dict = None, group_by: str = None, limit: int = None, logic: str = "AND") -> list:
		query = f'SELECT * FROM {table}'
		values = ()

		if search_data:
			conditions = f" {logic} ".join([f"{key} = ?" for key in search_data.keys()])
			query += f' WHERE {conditions}'
			values = tuple(search_data.values())

		if group_by:
			query += f' GROUP BY {group_by}'

		if limit:
			query += f' LIMIT {limit}'

		cursor = self.execute_read(query, values)
		rows = cursor.fetchall()

		if rows:
			columns = [column[0] for column in cursor.description]
			return [dict(zip(columns, row)) for row in rows]
		
		return []
	
	def get_field(self, table: str, field: str, search_data: dict = None, logic: str = "AND") -> str:
		qery = f'SELECT {field} FROM {table}'
		if search_data:
			conditions = f' {logic} '.join([f"{key} = ?" for key in search_data.keys()])
			qery += f' WHERE {conditions}'
			values = tuple(search_data.values())
		
		cursor = self.execute_read(qery, values)
		result = cursor.fetchone()

		return result[0] if result else None

	def insert(self, table: str, data: dict) -> int:
		columns = ', '.join(data.keys())
		placeholders = ', '.join(['?' for _ in data])
		
		query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
		cursor = self.connection.execute(query, tuple(data.values()))
		self.connection.commit()
		
		return cursor.lastrowid

	def delete(self, table: str, search_data: dict = None, logic: str = "AND"):
		query = f'DELETE FROM {table}'
		values = ()

		if search_data:
			conditions = f" {logic} ".join([f"{key} = ?" for key in search_data.keys()])
			query += f' WHERE {conditions}'
			values = tuple(search_data.values())

		self.execute_write(query, values)

	def remove_sta(self, ap_id, sta):
		self.execute_write('DELETE FROM stations WHERE ap_id = ? AND sta = ?;', (ap_id, sta))

	def insert_handshake(self, ap_id, sta, eapol_data, message_type):
		self.execute_write('''
			INSERT INTO stations (ap_id, sta, eapol, message_type) 
			VALUES (?, ?, ?, ?);
		''', (ap_id, sta, eapol_data, message_type))

	def get_handshake(self, ap_id, sta):
		cursor = self.execute_read('''
			SELECT eapol, message_type FROM stations 
			WHERE ap_id = ? AND sta = ? LIMIT 1;
		''', (ap_id, sta))
		return cursor.fetchone()  # Вернет (eapol, message_type) или None

	def close(self):
		if self.connection:
			self.connection.close()