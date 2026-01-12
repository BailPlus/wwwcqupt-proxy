from flask import Flask, request
from . import Proxy
from data.configs import global_config, sites


app = Flask(__name__, template_folder='views')
proxy = Proxy(
    global_config=global_config,
)
any(proxy.add_site(site) for site in sites)

@app.before_request
def handle():
    """处理请求"""
    return proxy.proxy(request)


if __name__ == '__main__':
    app.run(
        host=global_config.host,
        port=global_config.port,
        ssl_context=global_config.ssl_context
    )
