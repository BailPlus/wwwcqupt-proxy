from typing import Optional

class ProxyError(Exception):
    """反代异常"""

class BanThisIp(ProxyError):
    """封禁这个ip"""
    def __init__(self, msg: Optional[str] = None):
        self.msg = msg
