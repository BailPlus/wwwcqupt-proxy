#Copyright Bail 2025
#wwwcqupt-proxy Bail的重邮内部小站反向代理 v1.0_1
#2025.1.7-2025.1.15

TARGET = 'http://localhost:5000'
TRAFFIC_LOG_FILE = 'traffic.log'
SSL_CONTEXT = ('fullchain.pem','privkey.pem')
FREQUENCY_RESTRICT = {'222.177.140.114':(300,500),'*':(60,50)}    # 请求频率限制具体数值，[0]秒内最多[1]个请求

from flask import Flask,request,make_response,Response,abort
import httpx,time,os,random

ip_blacklist = set()   # ip黑名单
ip_frequency:dict[str:[int,int]] = {}   # 访问频率统计，{ip:[最近访问时间,访问次数]}

class Proxy(Flask):
    def __init__(self):
        super().__init__(__name__)
        self.before_request(self._before_request)
        self.after_request(self._after_request)
    def _before_request(self):
        # 过滤黑名单ip
        if request.remote_addr in ip_blacklist:
            return Proxy.ban()
        if not self.check_frequency():
            print('请求频率过高↓')
            return Proxy.ban('请求频率过高，已禁止访问。')
        # 校验Host头
        if request.headers.get('Host') not in ('cy.bail.asia','cqupt.cpu.bail.asia'):
            print('Host头错误↓')
            return Proxy.ban('我实在告诉你们：我不认识你们。——[太25:12]')
        # 打印请求
        self.log()
        # 处理请求
        req_headers = request.headers.to_wsgi_list()
        req_headers.append(('X-Real-IP',request.remote_addr))
        try:
            resp = httpx.request(request.method,TARGET+request.full_path,headers=req_headers,data=request.get_data())
        except httpx.LocalProtocolError:
            print('浏览器不正确↓')
            abort(403,'请使用正确的浏览器访问，谢谢')
        except (httpx.ConnectError,httpx.ConnectTimeout,httpx.ReadTimeout):
            abort(502,'服务器掉线，请联系Bail，谢谢')
        ready_resp = make_response(resp.content,f'{resp.status_code} {resp.reason_phrase}')
        ready_resp.headers.update(resp.headers.items())
        ready_resp.headers.add_header('Strict-Transport-Security', 'max-age=86400')
        # 处理来自主服务器的拉黑请求
        if resp.status_code == 601:
            ip_blacklist.add(request.remote_addr)
            resp.status_code = 400
        return ready_resp
    @staticmethod
    def _after_request(res:Response):
        if res.status_code == 404:
            return Proxy.ban()
        return res
    @staticmethod
    def ban(msg:str|None=None) -> Response:
        if msg is None:
            msg = '检测到你有违规操作，已禁止访问。如有疑问，请咨询Bail。' + os.urandom(random.randint(1,10)).hex()
        print('已封禁↓')
        ip_blacklist.add(request.remote_addr)
        return make_response(msg)
    def log(self):
        '''打印请求'''
        with open(TRAFFIC_LOG_FILE, 'ab') as requests_log_file:
            nowtime = time.strftime('%Y%m%dT%H%M%S')
            requests_log_file.write(b'-'*5 + b' '.join(i.encode() for i in (nowtime,request.remote_addr))+b'\n')
            requests_log_file.write(request.method.encode() + b' ' + request.full_path.encode() + b'\n')
            requests_log_file.write(str(request.headers).encode())
            requests_log_file.write(request.get_data() + b'\n')
    @staticmethod
    def check_frequency()->bool:
        '''检查请求频率
返回值：可继续访问性(bool)'''
        global ip_frequency
        restrict = FREQUENCY_RESTRICT.get(request.remote_addr,FREQUENCY_RESTRICT['*'])
        now_frequency = ip_frequency.get(request.remote_addr,[time.time(),0])
        if time.time() - now_frequency[0] < restrict[0]:
            now_frequency[1] += 1
            if now_frequency[1] > restrict[1]:
                return False
        else:
            now_frequency = [time.time(),1]
        ip_frequency[request.remote_addr] = now_frequency
        return True

if __name__ == '__main__':
    Proxy().run('0.0.0.0',443,ssl_context=SSL_CONTEXT)
