# coding: utf-8

import os.path

import tornado.web
import tornado.httpserver
import tornado.database
import tornado.options
import tornado.ioloop

from tornado.options import define, options
from tornado.web import url

from core.ext import db
from apps.loud import LoudHandler, SearchLoudHandler
from apps.reply import ReplyHandler
from apps.message import MessageHandler
from apps.prize import PrizeAddHandler
from apps.user import UserHandler, UploadHandler
from apps.auth import WeiboHandler, CancelWeiboHandler

# server
define('port', default=8000, help="run on the given port", type=int)

#URI
#define('site_uri', default="http://i.n2u.in", type=str, help="site uri") 
#define('static_uri', default="http://s.n2u.in", type=str, help="static uri")
define('site_uri', default="http://i2.n2u.in", type=str, help="site uri") 
define('static_uri', default="http://s.n2u.in", type=str, help="static uri")

# avatar dir  path
define('path', default="/data/web/help_static/", type=str, help="recommend default one")


# main logic
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
                url(r'^/s$', SearchLoudHandler),
                url(r'^/l/(?P<lid>[a-z0-9]*|)$', LoudHandler, name='Loud'),
                url(r'^/u/(?P<uid>[a-z0-9]*|)$', UserHandler, name='User'),
                url(r'^/reply/(?P<rid>[a-z0-9]*|)$', ReplyHandler, name='Reply'),
                url(r'^/msg/(?P<mid>[a-z0-9]*|)$', MessageHandler, name='Message'),
                url(r'^/prize/$', PrizeAddHandler),
                url(r'^/upload$', UploadHandler),
                # third party login or authorize
                url(r'^/auth/weibo$', WeiboHandler),
                url(r'^/auth/weibo/cancel$', CancelWeiboHandler),
                ]
        settings = dict(
                static_path=os.path.join(os.path.dirname(__file__), 'static'),
                # secure cookies
                cookie_secret="5b05a25df33a4609ca4c14caa6a8594b",
                # OAuth's key and secret
                weibo_app_key="563114544",
                weibo_app_secret="ac88e78e4c5037839cbbb9c92369bdef",
                # le bang key value
                nausicaa="3afb9fb7f605476d92b9ee7000b41ba0",
                # mongodb config
                MONGOALCHEMY_DATABASE="apple3",
                debug=True,
                )
        super(Application, self).__init__(handlers, **settings)


def main():
    tornado.options.parse_command_line()

    app = Application()

    # init the modual
    db.init_app(app)

    # server 
    http_server = tornado.httpserver.HTTPServer(app, xheaders=True)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()
