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

#from apps.loud import LoudHandler, SearchLoudHandler, OfferHelpUsersHandler
#from apps.user import UserHandler, UploadHandler
#from apps.auth import AuthHandler, DoubanHandler, WeiboHandler, RenrenHandler
#from apps.app import AppClientHandler, DeviceHandler
#from apps.reply import ReplyHandler
#from apps.admin import AdminAvatarHandler, CheckAdminHandler
#from apps.notify import MessageHandler, LoudUpdatedHandler, MessageUpdatedHandler, PrizeUpdatedhandler
#from apps.rdbm import rdb_init_app

# server
define('port', default=8000, help="run on the given port", type=int)

#URI
define('site_uri', default="http://i.n2u.in", type=str, help="site uri") 
define('static_uri', default="http://s.n2u.in", type=str, help="static uri")
#define('site_uri', default="http://192.168.0.124", type=str, help="site uri") 
#define('static_uri', default="http://192.168.0.124/static", type=str, help="static uri")
define('geo_uri', default="http://l.n2u.in", type=str, help="locaiton and address parser uri")

#args
define('er', default=6378137, type=float, help="the earth radius.")
define('cr', default=3000, type=float, help="the cycle radius.")

# avatar dir  path
define('path', default="/data/web/static/", type=str, help="recommend default one")


# main logic
class Application(tornado.web.Application):
    def __init__(self):
        handlers = []
        settings = dict(
                static_path=os.path.join(os.path.dirname(__file__), 'static'),
                # secure cookies
                cookie_secret="5b05a25df33a4609ca4c14caa6a8594b",
                # OAuth's key and secret
                douban_consumer_key="0855a87df29f2eac1900f979d7dd8c04",
                douban_consumer_secret="7524926f6171b225",
                weibo_app_key="563114544",
                weibo_app_secret="ac88e78e4c5037839cbbb9c92369bdef",
                renren_app_key="8f9607b8f2d4446fbc798597dc1dcdd4",
                renren_app_secret="c8bfb41852ae40589f268007205fce13",
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
