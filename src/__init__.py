from typing import Optional
from flask import Request, Response, abort
from .config import SiteConfig, GlobalConfig
from .blacklist.interface import IBlacklistHandler, IBlocker
from .freq.interface import IFreqChecker
from .log.interface import ILogger
from .proxy.interface import IProxyHandler
from .blacklist import BlacklistHandler, Blocker
from .freq import FreqChecker
from .log import Logger
from .proxy import ProxyHandler
from .errors import BanThisIp
import httpx


class Site:
    """每个站点各自的代理类"""
    config: SiteConfig # 代理配置信息
    blacklist_handler: IBlacklistHandler  # 黑名单处理器
    blocker: IBlocker   # ip封禁器
    freq_checker: Optional[IFreqChecker]  # 请求频率检查器
    logger: Optional[ILogger] # 日志记录器
    proxy_handler: IProxyHandler    # 转发处理器

    def __init__(self,
                 config: SiteConfig,
                 blacklist_handler: IBlacklistHandler,
                 blocker: IBlocker,
                 freq_checker: Optional[IFreqChecker],
                 logger: Optional[ILogger],
                 proxy_handler: IProxyHandler):
        self.config = config
        self.blacklist_handler = blacklist_handler
        self.blocker = blocker
        self.freq_checker = freq_checker
        self.logger = logger
        self.proxy_handler = proxy_handler

    def handle(self, request: Request) -> Response:
        assert (ip := request.remote_addr)

        if self.blacklist_handler is not None and self.blocker is not None:
            if self.blacklist_handler.is_in_blacklist(ip):
                return self.blocker.ban(ip)
        if self.freq_checker is not None:
            try:
                self.freq_checker.check(ip)
            except BanThisIp as e:
                if self.blocker is not None:
                    return self.blocker.ban(ip, e.msg)

        if self.logger is not None:
            self.logger.log(request)

        try:
            return self.proxy_handler.proxy(request)
        except BanThisIp as e:
            if self.blocker is not None:
                return self.blocker.ban(ip, e.msg)
            else:
                abort(400)


class Proxy:
    gconfig: GlobalConfig
    sites: dict[str, Site]  # 已注册的站点字典，通过域名匹配
    blacklist_handler: IBlacklistHandler
    blocker: IBlocker

    def __init__(self, global_config: GlobalConfig):
        self.gconfig = global_config
        self.sites = {}
        self.blacklist_handler = BlacklistHandler(self.gconfig)
        self.blocker = Blocker(self.gconfig, self.blacklist_handler)

    def add_site(self, site_config: SiteConfig):
        blacklist_handler = BlacklistHandler(self.gconfig, site_config.domain)
        self.sites[site_config.domain] = Site(
            config=site_config,
            blacklist_handler=blacklist_handler,
            blocker=Blocker(self.gconfig, blacklist_handler),
            freq_checker=FreqChecker(site_config) if site_config.freq_restrict is not None else None,
            logger=Logger(site_config) if site_config.log_file is not None else None,
            proxy_handler=ProxyHandler(site_config, httpx.Client())
        )
    
    def proxy(self, request: Request) -> Response:
        assert request.remote_addr
        if request.host not in self.sites:
            print('Host头错误↓')
            return self.blocker.ban(request.remote_addr, '我实在告诉你们：我不认识你们。——[太25:12]')
        return self.sites[request.host].handle(request)
