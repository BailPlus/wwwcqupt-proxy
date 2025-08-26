from typing import override
from .interface import IProxyHandler
from ..config import SiteConfig
from ..errors import BanThisIp
from httpx import Client
import flask, httpx


class ProxyHandler(IProxyHandler):
    """处理转发"""
    config: SiteConfig
    client: Client

    def __init__(self, config: SiteConfig, httpx_client: Client):
        self.config = config
        self.client = httpx_client

    @override
    def proxy(self, request: flask.Request) -> flask.Response:
        assert request.remote_addr
        if 'X-Real-IP' in request.headers:
            raise BanThisIp('你从哪里来？')
        req_headers = request.headers.to_wsgi_list()
        req_headers.append(('X-Real-IP',request.remote_addr)) # type: ignore
        # 进行转发
        try:
            resp = self.client.request(
                method=request.method,
                url=self.config.target_url+request.environ['RAW_URI'],
                headers=req_headers,
                data=request.get_data(), # type: ignore
                timeout=(1,60,30,10)
            )
        except httpx.LocalProtocolError:
            raise BanThisIp('请使用正确浏览器访问')
        except (httpx.ConnectError,httpx.ConnectTimeout,httpx.ReadTimeout):
            flask.abort(503, '服务器掉线，请联系Bail，谢谢')
        ready_resp = flask.make_response(resp.content,f'{resp.status_code} {resp.reason_phrase}')
        ready_resp.headers.update(resp.headers.items())
        # ready_resp.headers.add_header('Strict-Transport-Security', 'max-age=86400')
        del ready_resp.headers['Content-Encoding']
        del ready_resp.headers['Transfer-Encoding']
        del ready_resp.headers['Set-Cookie']
        for cookie in resp.headers.get_list('Set-Cookie'):
            ready_resp.headers.add('Set-Cookie', cookie)
        # 处理来自主服务器的拉黑请求
        if resp.status_code == 601:
            raise BanThisIp('你在搞什么？')
        elif resp.status_code == 404 and self.config.ban404:
            raise BanThisIp('页面走丢了捏')
        return ready_resp
