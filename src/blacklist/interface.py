from abc import ABC, abstractmethod
import flask


class IBlacklistHandler(ABC):
    '''黑名单处理类'''
    @abstractmethod
    def get_all(self) -> set[str]:
        '''加载黑名单'''

    @abstractmethod
    def add(self, ip: str):
        '''添加ip到黑名单'''

    @abstractmethod
    def is_in_blacklist(self, ip: str) -> bool:
        '''判断ip是否在黑名单'''

    @abstractmethod
    def remove_ip(self, ip: str):
        '''从黑名单中删除ip'''


class IBlocker(ABC):
    """封禁处理类"""
    @abstractmethod
    def ban(self, ip: str, msg: str | None = None) -> flask.Response:
        """封禁请求者，返回封禁响应或字符串"""

    @abstractmethod
    def unban(self, unban_code: str):
        """取消封禁"""
