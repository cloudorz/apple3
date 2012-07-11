# coding: utf-8

import datetime

import tornado.web
from tornado.web import HTTPError
from apps import BaseRequestHandler, WeiboMixin
from apps.documents import User


now = datetime.datetime.utcnow


class WeiboHandler(BaseRequestHandler, WeiboMixin):

    @tornado.web.asynchronous
    def get(self):

        code = self.get_argument("code", None)
        if code:
            self.get_authenticated_user(code, self._on_auth)
            return

        self.weibo_authorize_redirect()

    def _on_auth(self, outer_user):
        if not outer_user:
            raise HTTPError(500, "Weibo auth failed.")

        auth_id = "%s_%s" % ('weibo', outer_user['access_token']['uid'])
        user = User.query.filter(User.site_label==auth_id).first()

        # create or update the user
        if user is None:

            # user data
            user_data = {}
            #user_data['userkey'] = auth_id
            user_data['name'] = outer_user['screen_name']
            user_data['avatar'] = outer_user['avatar']
            user_data['brief'] = outer_user['brief']
            if 'dtoken' in outer_user:
                auth_data['dtoken'] = outer_user['dtoken']
            user_data['site_label'] = auth_id
            user_data['access_token'] = outer_user['access_token']['access_token']
            user_data['access_secret'] = "weibo oauth2"
            user_data['expired'] = outer_user['access_token']['expires_in'] 

            # think about new one TODO

            user = User()
            user.populate(user_data)
            user.generate_secret()
            user.created = now()

            user.maybe_save()

        self.render_json(user.dict4auth())
        self.finish()


class CancelWeiboHandler(BaseRequestHandler):

    def get(self):
        uid = self.args.get('uid', None)
        print 'Return back', uid

        self.set_status(200)
        self.finish()
