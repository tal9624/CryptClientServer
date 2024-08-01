import sqlite3
class DatabaseHandler:
    __instance = None

    def __init__(self):
        raise RuntimeError("singleton class, call Persistance.get_instance()")

    def row_to_dictionary(cursor, row):
        """ convert row to a dictionary"""
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def create_table_clients(self):
        sql_clients = """CREATE TABLE clients(
        ID INT NOT NULL PRIMARY KEY,
        Name varchar(255),
        PublicKey varchar(160),
        LastSeen  varchar(50),
        AES varchar(16)
        )"""
        self.conn.executescript(sql_clients)

    def create_table_files(self):
        sql_files = """CREATE TABLE files(
        ID int ,
        File_Name varchar(255),
        Path_Name varchar(255),
        Verified INT
        )"""
        self.conn.executescript(sql_files)

    def init_database(self):
        """initiate database connection and create tables if they do not exist"""
        self.conn = sqlite3.connect('defensive.db')
        # Set the row factory
        self.conn.row_factory = DatabaseHandler.row_to_dictionary
        self.conn.text_factory = bytes  # represent char as byte
        # initialization
        try:
            self.create_table_clients()  # creating the matrixes if not exists
            self.create_table_files()
        except:
            print("Tables were not created.possibly already exists.")


    @classmethod
    def get_instance(cls):
        """ get the single existing instance or create if it does not exist """
        if cls.__instance == None:
            cls.__instance = cls.__new__(cls)
            cls.__instance.init_database()
        return cls.__instance

    def get_client_by_name(self, name):
        cur = self.conn.cursor()  # מבצע פעולות על נתונים
        cur.execute("""SELECT * from clients where Name = ?""",
                    [name])
        res = cur.fetchall()
        return res

    def get_client_by_id(self, client_id):
        cursor = self.conn.cursor()
        cursor.execute("""SELECT * from clients where ID = ?""",
                       (client_id,))
        res = cursor.fetchall()
        if len(res) == 0:
            return False
        return res

    def get_clients(self):
        cor = self.conn.cursor()  # מבצע פעולות על נתונים
        cor.execute("""select * from clients""")
        res = cor.fetchall()
        return res

    def insert_client(self, ID, Name, PublicKey, LastSeen, AES):
        sql = """INSERT INTO clients VALUES(?,?,?,?,?)"""
        cor = self.conn.cursor()
        cor.execute(sql, [ID, Name, PublicKey, LastSeen, AES])
        self.conn.commit()

    def get_files(self):
        cor = self.conn.cursor()  # מבצע פעולות על נתונים
        cor.execute("""SELECT * from files""")
        res = cor.fetchall()
        return res

    def insert_files(self, ID, File_Name, Path_Name, Verified):
        print("insert_file", ID, File_Name, Path_Name, Verified)
        sql = """INSERT INTO files VALUES(?,?,?,?)"""
        cor = self.conn.cursor()
        cor.execute(sql, [str(ID.int),
                          File_Name, Path_Name, Verified])
        self.conn.commit()

    def get_aes_by_costumer_name(self, name):
        cor = self.conn.cursor()  # מבצע פעולות על נתונים
        cor.execute("""select AES from clients where name =?""",
                    (name,))
        res = cor.fetchall()
        return res

    def update_public_key(self, name, public_key, aes_key):
        sql = """UPDATE clients SET PublicKey = ? , AES = ? where Name = ?"""
        cursor = self.conn.cursor()
        cursor.execute(sql, [public_key, aes_key, name])
        self.conn.commit()
