from abc import ABC, abstractmethod


class IFreqChecker(ABC):
    """请求频率检查器"""
    @abstractmethod
    def check(self, ip: str):
        """检查请求频率"""
