#Copyright Bail 2025
#wwwcqupt-proxy Bail的重邮内部小站反向代理 v1.0_1
#2025.1.7

TARGET = 'http://localhost:5000'

from flask import Flask,request,make_response,abort
import httpx,sys

ip_blacklist = []   # ip黑名单，用于过滤频繁访问

class Proxy(Flask):
    def __init__(self):
        super().__init__(__name__)
        self.before_request(self._before_request)
    def _before_request(self):
        # 过滤黑名单ip
        if request.remote_addr in ip_blacklist:
            abort(403,'检测到你有违规操作，已禁止访问。如有疑问，请咨询Bail。')
        # 打印请求
        with open('traffic.log', 'ab') as requests_log_file:
            requests_log_file.write(
                b'-' * 5 + request.remote_addr.encode() + b' ' + request.method.encode() + b' ' + request.full_path.encode() + b'\n')
            requests_log_file.write(str(request.headers).encode() + b'\n\n')
            requests_log_file.write(request.get_data() + b'\n')
        # 处理请求
        req_headers = request.headers.to_wsgi_list()
        req_headers.append(('X-Real-IP',request.remote_addr))
        resp = httpx.request(request.method,TARGET+request.full_path,headers=req_headers,data=request.get_data())
        ready_resp = make_response(resp.content,f'{resp.status_code} {resp.reason_phrase}')
        ready_resp.headers = dict(resp.headers)
        # 处理来自主服务器的拉黑请求
        if resp.status_code == 601:
            ip_blacklist.append(request.remote_addr)
        return ready_resp

if __name__ == '__main__':
    Proxy().run('0.0.0.0',80)
