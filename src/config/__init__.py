from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Optional
import flask, time


@dataclass(frozen=True)
class LogLevel():
    time: bool = True   # 请求时间
    remote_addr: bool = True    # 请求者ip
    method: bool = True # 是否记录请求方法
    route: bool = True  # 是否记录请求路由
    headers: bool = True  # 是否记录请求头
    body: bool = True   # 是否记录请求体
    customize: bool = False # 是否使用自定义日志记录逻辑


@dataclass(frozen=True)
class FreqRestrictItem:
    window_size: int    # 窗口大小，单位为秒
    max_requests: int   # 最大请求数


class FreqRestrict(dict[str, FreqRestrictItem]):
    """频率限制字典"""
    def __init__(self, default: FreqRestrictItem, **kwargs: FreqRestrictItem):
        super().__init__(**kwargs)
        self.default = default

    def __missing__(self, key):
        return self.default # 如果没有指定ip，则使用默认限制


class SiteConfig(ABC):
    __required_properties = ('domain', 'target_url')
    domain: str  # 域名
    target_url: str  # 目标url
    ban404: bool = False    # 是否封禁试图访问不存在的页面的ip
    log_file: Optional[str] = None  # 日志文件路径
    log_level: Optional[LogLevel] = None    # 日志级别
    freq_restrict: Optional[FreqRestrict] = None    # 频率限制字典

    @abstractmethod
    def customize_log(self, request: flask.Request) -> bytes:
        """用于在loglevel.customize为True时自定义日志记录逻辑
返回值：可直接写入文件的字符串"""
        assert self.log_level
        request_time = time.strftime('%Y.%m.%d %H:%M:%S') if self.log_level.time else ''
        ip = request.remote_addr if self.log_level.remote_addr else ''
        method = request.method if self.log_level.method else ''
        route = request.full_path if self.log_level.route else ''
        headers = str(request.headers) if self.log_level.headers else ''
        body = request.get_data() if self.log_level.body else b''
        return f'''----- {request_time} {ip} -----
{method} {route}
{headers}

'''.encode() + body + b'\n'

    def __init_subclass__(cls):
        for p in cls.__required_properties:
            if not hasattr(cls, p):
                raise TypeError(f'必须定义字段 {', '.join(i for i in cls.__required_properties)}')
        if cls.log_level is None and cls.log_file is not None:
            raise TypeError('进行日志记录的配置必须定义日志级别')
        return super().__init_subclass__()


@dataclass(frozen=True)
class GlobalConfig:
    host: str  # 监听地址
    port: int  # 监听端口
    blacklist_db: str   # 黑名单数据库路径
    unban_code_secret: str  # 解封码密钥
    ssl_context: Optional[tuple[str, str]] = None   # ssl证书
