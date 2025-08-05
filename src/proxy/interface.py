from abc import ABC, abstractmethod
import flask


class IProxyHandler(ABC):
    @abstractmethod
    def proxy(self, request: flask.Request) -> flask.Response:
        """进行代理"""
