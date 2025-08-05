from typing import override
from .interface import IBlacklistHandler, IBlocker
from ..config import GlobalConfig
import sqlite3, flask, random, pyotp


class BlacklistHandler(IBlacklistHandler):
    '''黑名单处理类'''
    conn: sqlite3.Connection    # sqlite3连接
    domain: str # 该处理器所管理的域名

    def __init__(self,config: GlobalConfig, domain: str = 'GLOBAL'):
        assert config.blacklist_db
        self.conn = sqlite3.connect(config.blacklist_db, check_same_thread=False) # XXX: 线程不安全
        self.domain = domain
        self.create_table()

    def __del__(self):
        '''析构函数'''
        self.conn.close()

    def create_table(self):
        '''创建黑名单表'''
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS blacklist (
                       ip TEXT PRIMARY KEY,
                       domain TEXT NOT NULL DEFAULT 'GLOBAL',
                       created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime'))
                     )''')
        self.conn.commit()

    @override
    def get_all(self) -> set[str]:
        '''加载黑名单'''
        c = self.conn.cursor()
        return {i[0] for i in c.execute('SELECT ip FROM blacklist WHERE domain = "GLOBAL" OR domain = ?', (self.domain,)).fetchall()}

    @override
    def add(self,ip:str):
        '''添加ip到黑名单'''
        c = self.conn.cursor()
        c.execute('INSERT OR IGNORE INTO blacklist (ip, domain) VALUES (?, ?)',(ip, self.domain))
        self.conn.commit()

    @override
    def is_in_blacklist(self,ip:str)->bool:
        '''判断ip是否在黑名单'''
        return self.conn.cursor().execute('SELECT 1 FROM blacklist WHERE ip=? AND (domain = "GLOBAL" OR domain = ?)', (ip, self.domain)).fetchone() is not None

    @override
    def remove_ip(self,ip:str):
        '''从黑名单中删除ip'''
        c = self.conn.cursor()
        c.execute('DELETE FROM blacklist WHERE ip=?', (ip,))
        self.conn.commit()


class Blocker(IBlocker):
    config: GlobalConfig
    blacklist_handler: IBlacklistHandler

    def __init__(self, config: GlobalConfig, blacklist_handler: IBlacklistHandler):
        self.config = config
        self.blacklist_handler = blacklist_handler

    def check_unban(self, request: flask.Request):
        if 'Unban-Code' in request.headers:
            self.unban(request.headers['Unban-Code'])
            return '已解封'

    @override
    def ban(self, ip: str, msg: str | None = None) -> flask.Response:
        if msg is None:
            msg = '检测到你有违规操作，已禁止访问。如有疑问，请咨询Bail。' + ' '*random.randint(1,10)
        print('已封禁↓')
        self.blacklist_handler.add(ip)
        ##return self.send_zip_boom()
        return flask.make_response(
            flask.render_template('banned.html',msg=msg)
        )

    @override
    def unban(self, unban_code:str):
        '''取消封禁'''
        assert flask.request.remote_addr and self.config.unban_code_secret
        # 验证pyotp
        if not pyotp.TOTP(self.config.unban_code_secret).verify(unban_code):
            print('解封失败↓')
            flask.abort(403,'解封码错误')
        print('已解封↓')
        self.blacklist_handler.remove_ip(flask.request.remote_addr)
