from abc import ABC, abstractmethod
import flask


class ILogger(ABC):
    """日志记录器"""
    @abstractmethod
    def log(self, request: flask.Request):
        """记录日志"""
