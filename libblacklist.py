BLACKLIST_DB = 'blacklist.db'

import sqlite3

class BlacklistHandler:
    '''黑名单处理类'''
    conn:sqlite3.Connection  # sqlite3连接
    def __init__(self,db_path:str=BLACKLIST_DB):
        self.conn = sqlite3.connect(db_path,check_same_thread=False) # XXX: 线程不安全
        self.create_table()
    def __del__(self):
        '''析构函数'''
        self.conn.close()
    def create_table(self):
        '''创建黑名单表'''
        c = self.conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS blacklist (ip VARCHAR(16) PRIMARY KEY)')
        self.conn.commit()
    def get_all(self):
        '''加载黑名单'''
        c = self.conn.cursor()
        blacklist = set()
        for row in c.execute('SELECT ip FROM blacklist'):
            blacklist.add(row[0])
        return blacklist
    def add(self,ip:str):
        '''添加ip到黑名单'''
        c = self.conn.cursor()
        c.execute('''INSERT INTO blacklist (ip) SELECT ?
                     WHERE NOT EXISTS (
                       SELECT 1 FROM blacklist WHERE ip = ?
                     )''',(ip,ip))
        self.conn.commit()
    def is_in_blacklist(self,ip:str)->bool:
        '''判断ip是否在黑名单'''
        return self.conn.cursor().execute('SELECT 1 FROM blacklist WHERE ip=?',(ip,)).fetchone() is not None
    def remove_ip(self,ip:str):
        '''从黑名单中删除ip'''
        c = self.conn.cursor()
        c.execute('DELETE FROM blacklist WHERE ip=?',(ip,))
        self.conn.commit()
