from gunicorn.app.base import BaseApplication
from .app import app, global_config

class WwwcquptProxy(BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self) -> None:
        config = {key: value for key, value in self.options.items() if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def main():
    options = {
        'bind': global_config.host + ':' + str(global_config.port),
        'workers': global_config.workers,
        'accesslog': '-',
        'errorlog': '-'
    }
    if global_config.ssl_context is not None:
        options['certfile'] = global_config.ssl_context[0]
        options['keyfile'] = global_config.ssl_context[1]

    WwwcquptProxy(app, options).run()


if __name__ == '__main__':
    main()
