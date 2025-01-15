#Copyright Bail 2025
#wwwcqupt-proxy:force-https 强制https v1.0_1
#2025.1.15

from flask import Flask,redirect,request

class ForceHttps(Flask):
    def __init__(self):
        super().__init__(__name__)
        self.before_request(self._before_request)
    @staticmethod
    def _before_request():
        return redirect(request.url.replace('http://','https://',1),301)

if __name__ == '__main__':
    ForceHttps().run('0.0.0.0',port=80)
