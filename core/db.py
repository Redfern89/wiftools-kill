import os
import sqlite3

class Database:
	def __init__(self):
		# Fucked directory
		if not os.path.exists('resources/db'):
			os.mkdir('resources/db')

		self.connection = sqlite3.connect(
			'resources/db/wifi_scanner.db',
			check_same_thread=False
		)
		self.init_tables()

	def execute_write(self, query, params=None):
		cursor = self.connection.cursor()
		cursor.execute(query, params or ())
		self.connection.commit()
		
		return cursor

	def execute_read(self, query, params=None):
		cursor = self.connection.cursor()
		cursor.execute(query, params or ())

		return cursor
	
	def make_conditions(self, search_data: dict = None, logic: str = "AND"):
		if not search_data:
			return "", ()

		cond_list = [f"{key} = ?" for key in search_data.keys()]
		conditions = f" {logic.upper()} ".join(cond_list)
		values = tuple(search_data.values())

		return conditions, values

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

		self.execute_write('CREATE INDEX IF NOT EXISTS idx_ap_id_sta ON stations(ap_id, sta);')
		self.execute_write('CREATE UNIQUE INDEX IF NOT EXISTS idx_bssid ON access_points(bssid);')
		self.execute_write('CREATE INDEX IF NOT EXISTS idx_probe ON probes(probe_addr);')
	
	def row_exists(self, table: str, search_data: dict, logic: str = "AND") -> bool:
		if search_data:
			query = f'SELECT 1 FROM {table}'
			conditions, values = self.make_conditions(search_data=search_data, logic=logic)
			query += f' WHERE {conditions} LIMIT 1'
			cursor = self.execute_read(query, values)
			
			if cursor:
				return cursor.fetchone() is not None
		
		return False

	def get_row(self, table: str, search_data: dict = None, logic: str = "AND") -> dict:
		query = f'SELECT * FROM {table}'

		conditions, values = self.make_conditions(search_data=search_data, logic=logic)
		if conditions:
			query += f' WHERE {conditions}'
		
		query += ' LIMIT 1'
		cursor = self.execute_read(query, values)
		if cursor:
			row = cursor.fetchone()

			if row:
				columns = [column[0] for column in cursor.description]
				return dict(zip(columns, row))
		
		return None
	
	def get_rows(self, table: str, search_data: dict = None, group_by: str = None, limit: int = None, logic: str = "AND") -> list:
		query = f'SELECT * FROM {table}'
		conditions, values = self.make_conditions(search_data=search_data, logic=logic)

		if conditions:
			query += f' WHERE {conditions}'

		if group_by:
			query += f' GROUP BY {group_by}'

		if limit:
			query += f' LIMIT {limit}'

		cursor = self.execute_read(query, values)
		if cursor:
			rows = cursor.fetchall()

			if rows:
				columns = [column[0] for column in cursor.description]
				return [dict(zip(columns, row)) for row in rows]
		
		return []
	
	def get_field(self, table: str, field: str, search_data: dict = None, logic: str = "AND") -> any:
		query = f'SELECT {field} FROM {table}'
		
		conditions, values = self.make_conditions(search_data=search_data, logic=logic)
		if conditions:
			query += f' WHERE {conditions}'

		cursor = self.execute_read(query, values)
		if cursor:
			result = cursor.fetchone()
			return result[0] if result else None

		return None

	def insert(self, table: str, data: dict) -> int:
		columns = ', '.join(data.keys())
		placeholders = ', '.join(['?' for _ in data])
		
		query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
		cursor = self.execute_write(query, tuple(data.values()))

		if cursor:
			return cursor.lastrowid

		return None

	def delete(self, table: str, search_data: dict = None, logic: str = "AND"):
		if not search_data:
			return
		
		query = f'DELETE FROM {table}'

		conditions, values = self.make_conditions(search_data=search_data, logic=logic)
		if conditions:
			query += f' WHERE {conditions}'

		self.execute_write(query, values)

	def close(self):
		if self.connection:
			self.connection.close()