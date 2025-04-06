BLACKLIST_DB = 'blacklist.db'

import sqlite3

class BlacklistHandler:
    '''黑名单处理类'''
    _blacklist:set  # ip黑名单
    conn:sqlite3.Connection  # sqlite3连接
    def __init__(self,db_path:str=BLACKLIST_DB):
        self.conn = sqlite3.connect(db_path,check_same_thread=False) # XXX: 线程不安全
        self._blacklist = set()
        self.create_table()
        self.load_blacklist()
    def __del__(self):
        '''析构函数'''
        self.conn.close()
    def create_table(self):
        '''创建黑名单表'''
        c = self.conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS blacklist (ip VARCHAR(16) PRIMARY KEY)')
        self.conn.commit()
    def load_blacklist(self):
        '''加载黑名单'''
        c = self.conn.cursor()
        for row in c.execute('SELECT ip FROM blacklist'):
            self._blacklist.add(row[0])
        return self._blacklist
    def add(self,ip:str):
        '''添加ip到黑名单'''
        if ip not in self._blacklist:
            c = self.conn.cursor()
            self._blacklist.add(ip)
            c.execute('INSERT INTO blacklist (ip) VALUES (?)',(ip,))
            self.conn.commit()
    def is_in_blacklist(self,ip:str)->bool:
        '''判断ip是否在黑名单'''
        return ip in self._blacklist
    def remove_ip(self,ip:str):
        '''从黑名单中删除ip'''
        if ip in self._blacklist:
            c = self.conn.cursor()
            self._blacklist.remove(ip)
            c.execute('DELETE FROM blacklist WHERE ip=?',(ip,))
            self.conn.commit()
