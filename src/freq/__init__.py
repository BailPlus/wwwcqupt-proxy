from typing import override
from .interface import IFreqChecker
from ..config import SiteConfig
from ..errors import BanThisIp
import time


class FreqArray:
    """每个站点每个客户端ip的频率数组"""
    freqlst: list[int]
    updlst: list[int]
    window_size: int    # 窗口大小

    def __init__(self, window_size: int):
        self.window_size = window_size
        self.freqlst = [0] * window_size
        self.updlst = [0] * window_size

    def _getidx(self):
        return int(time.time()) % self.window_size

    def _clear(self, idx):
        ts = int(time.time())
        if self.updlst[idx] != ts:
            self.freqlst[idx] = 0
            self.updlst[idx] = ts

    @property
    def freq(self):
        idx = self._getidx()
        self._clear(idx)
        return self.freqlst[idx]

    @freq.setter
    def freq(self, value):
        idx = self._getidx()
        self._clear(idx)
        self.freqlst[idx] = value

    @property
    def summary(self):
        return sum(self.freqlst)


class FreqChecker(IFreqChecker):
    """请求频率检查器"""
    config: SiteConfig
    now_frequency: dict[str, FreqArray]

    def __init__(self, config: SiteConfig):
        self.config = config
        self.now_frequency = {}

    @override
    def check(self, ip: str):
        assert self.config.freq_restrict is not None
        restrict = self.config.freq_restrict[ip]
        now = self.now_frequency.get(ip, FreqArray(restrict.window_size))
        now.freq += 1
        self.now_frequency[ip] = now
        if now.summary > restrict.max_requests:
            raise BanThisIp('请求频率过高')
