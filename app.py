#Copyright Bail 2025
#wwwcqupt-proxy Bail的重邮内部小站反向代理 v1.0_1
#2025.1.7-2025.1.15

TARGET = 'http://localhost:5000'
TRAFFIC_LOG_FILE = 'traffic.log'
SSL_CONTEXT = ('fullchain.pem','privkey.pem')

from flask import Flask,request,make_response,Response
import httpx,time

ip_blacklist = set()   # ip黑名单，用于过滤频繁访问

class Proxy(Flask):
    def __init__(self):
        super().__init__(__name__)
        self.before_request(self._before_request)
        self.after_request(self._after_request)
    def _before_request(self):
        # 过滤黑名单ip
        if request.remote_addr in ip_blacklist:
            return Proxy.ban()
        # 打印请求
        self.log()
        # 处理请求
        req_headers = request.headers.to_wsgi_list()
        req_headers.append(('X-Real-IP',request.remote_addr))
        resp = httpx.request(request.method,TARGET+request.full_path,headers=req_headers,data=request.get_data())
        ready_resp = make_response(resp.content,f'{resp.status_code} {resp.reason_phrase}')
        ready_resp.headers = dict(resp.headers)
        # 处理来自主服务器的拉黑请求
        if resp.status_code == 601:
            ip_blacklist.add(request.remote_addr)
        return ready_resp
    @staticmethod
    def _after_request(res:Response):
        global ip_blacklist
        if res.status_code == 404:
            return Proxy.ban()
        return res
    @staticmethod
    def ban():
        print('已封禁↓')
        ip_blacklist.add(request.remote_addr)
        return make_response('检测到你有违规操作，已禁止访问。如有疑问，请咨询Bail。')
    def log(self):
        '''打印请求'''
        with open(TRAFFIC_LOG_FILE, 'ab') as requests_log_file:
            nowtime = time.strftime('%Y%m%dT%H%M%S')
            requests_log_file.write(b'-'*5 + b' '.join(i.encode() for i in (nowtime,request.remote_addr))+b'\n')
            requests_log_file.write(request.method.encode() + b' ' + request.full_path.encode() + b'\n')
            requests_log_file.write(str(request.headers).encode())
            requests_log_file.write(request.get_data() + b'\n')


if __name__ == '__main__':
    Proxy().run('0.0.0.0',443,ssl_context=SSL_CONTEXT)
