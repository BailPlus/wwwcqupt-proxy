from typing import override
from .interface import ILogger
from ..config import SiteConfig, LogLevel
import flask


class Logger(ILogger):
    """日志记录器"""
    config: SiteConfig

    def __init__(self, config: SiteConfig) -> None:
        assert config.log_file and config.log_level
        self.config = config

    @override
    def log(self, request: flask.Request):
        assert self.config.log_file
        with open(self.config.log_file, 'ab') as file:
            file.write(
                self.config.customize_log(request)
            )
