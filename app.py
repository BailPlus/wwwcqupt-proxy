#Copyright Bail 2025
#wwwcqupt-proxy Bail的重邮内部小站反向代理 v1.0_1
#2025.1.7

TARGET = 'http://localhost:5000'

from flask import Flask,request,make_response
import httpx,sys

blacklist = []

class Proxy(Flask):
    def __init__(self):
        super().__init__(__name__)
        self.before_request(self._before_request)
    def _before_request(self):
        req_headers = request.headers.to_wsgi_list()
        req_headers.append(('X-Real-IP',request.remote_addr))
        resp = httpx.request(request.method,TARGET+request.full_path,headers=req_headers,data=request.get_data())
        if resp.status_code == 600:
            print('600 status code received!')
        ready_resp = make_response(resp.content,f'{resp.status_code} {resp.reason_phrase}')
        ready_resp.headers = dict(resp.headers)
        return ready_resp

if __name__ == '__main__':
    Proxy().run(
        host=sys.argv[1] if len(sys.argv) == 3 else 'localhost',
        port=sys.argv[-1] if len(sys.argv) >= 2 and sys.argv[-1].isdigit() else 8080
    )
