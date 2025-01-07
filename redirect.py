#Copyright Bail 2025
#wwwcqupt-proxy:redirect 迁移重定向服务 v1.0_1
#2025.1.7

from flask import Flask,render_template

class Server(Flask):
    def __init__(self):
        super().__init__(__name__)
        self.before_request(self._before_request)
    def _before_request(self):
        return render_template('redirect.html')

if __name__ == '__main__':
    Server().run('cqupt.cpu.bail.asia',8080)
