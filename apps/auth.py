# coding: utf-8

import tornado.web

from tornado.web import HTTPError
from tornado.httputil import url_concat
from tornado.options import options
from tornado import httpclient

from apps import BaseRequestHandler, DoubanMixin, WeiboMixin, RenrenMixin
from apps.models import User, Auth
from utils.decorator import authenticated, admin
from utils.tools import QDict


class DoubanHandler(BaseRequestHandler, DoubanMixin):

    @tornado.web.asynchronous
    def get(self):

        if self.current_user:
            self.set_secure_cookie('userkey', self.current_user.userkey)

        if self.get_argument("oauth_token", None):
            self.get_authenticated_user(self._on_auth)
            return
        else:
            if not self.current_user:
                self.set_secure_cookie('uid', self.get_argument('uid'))

        self.authorize_redirect(self.reverse_url('douban'))

    def _on_auth(self, outer_user):
        if not outer_user:
            raise HTTPError(500, "Douban auth failed.")

        auth_id = "%s_%s" % (Auth.DOUBAN, outer_user['access_token']['douban_user_id'])
        auth = Auth.query.get(auth_id)
        user = User.query.get_by_userkey(self.get_secure_cookie('userkey', None)) or auth and auth.user
        self.clear_cookie('userkey')

        # create or update the user
        if user is None and auth is None:
            did = self.get_secure_cookie('uid', None)
            self.clear_cookie('uid')
            if not did:
                raise HTTPError(500, "Douban auth failed.")
            # user data
            user_data = {}
            user_data['userkey'] = auth_id
            user_data['name'] = outer_user['name']
            user_data['avatar'] = outer_user['avatar']
            user_data['brief'] = outer_user['brief']
            user_data['deviceid'] = did

            user = User()
            user.from_dict(user_data)

            user.maybe_save()

        # auth data
        auth_data = {}
        auth_data['user'] = user
        auth_data['site_outer'] = Auth.WEIBO
        auth_data['site_label'] = auth_id
        auth_data['access_token'] = outer_user['access_token']['key']
        auth_data['access_secret'] = outer_user['access_token']['secret']
        auth_data['expired'] = outer_user['expired']

        # create or update the auth
        if auth is None:
            auth = Auth()

        auth.from_dict(auth_data)
        auth.maybe_save()

        self.render_json(auth.user.user2dict4auth() if auth.user.id>0 else {})
        self.finish()


class WeiboHandler(BaseRequestHandler, WeiboMixin):

    @tornado.web.asynchronous
    def get(self):

        if self.current_user:
            self.set_secure_cookie('userkey', self.current_user.userkey)

        code = self.get_argument("code", None)
        if code:
            self.get_authenticated_user(code, self._on_auth)
            return
        else:
            if not self.current_user:
                self.set_secure_cookie('uid', self.get_argument('uid'))

        self.weibo_authorize_redirect()

    def _on_auth(self, outer_user):
        if not outer_user:
            raise HTTPError(500, "Weibo auth failed.")

        auth_id = "%s_%s" % (Auth.WEIBO, outer_user['access_token']['uid'])
        auth = Auth.query.get(auth_id)
        user = User.query.get_by_userkey(self.get_secure_cookie('userkey', None)) or auth and auth.user
        self.clear_cookie('userkey')

        # create or update the user
        if user is None and auth is None:
            did = self.get_secure_cookie('uid', None)
            self.clear_cookie('uid')
            if not did:
                raise HTTPError(500, "Weibo auth failed.")

            # user data
            user_data = {}
            user_data['userkey'] = auth_id
            user_data['name'] = outer_user['screen_name']
            user_data['avatar'] = outer_user['avatar']
            user_data['brief'] = outer_user['brief']
            user_data['deviceid'] = did
            user_data['location'] = (0.0, 0.0) # TODO maybe other 

            user = User()
            user.from_dict(user_data)

            user.generate_secret()
            if not user.save():
                raise HTTPError(500, 'Save auth user info error.')

        # auth data
        auth_data = {}
        auth_data['site_label'] = Auth.WEIBO
        auth_data['access_token'] = outer_user['access_token']['access_token']
        auth_data['access_secret'] = "weibo oauth2"
        auth_data['expired'] = outer_user['access_token']['expires_in'] # maybe error
        auth_data['site_user_id'] = auth_id
        auth_data['user_id'] = user.id

        # create or update the auth
        if auth is None:
            auth = Auth()

        auth.from_dict(auth_data)
        if not auth.save():
            raise HTTPError(500, "Failed auth with weibo account.")

        # send to weibo 
        #sns_data = {
        #        'token': auth.access_token,
        #        'secret': auth.access_secret,
        #        'label': auth.WEIBO,
        #        'content': u"我正在使用乐帮，乐帮是一款基于LBS的帮助应用, 旨在让你在有困难时能更容易地得到帮助。请关注@-乐帮- http://whohelp.me",
        #        }
        #http_client = httpclient.HTTPClient()
        #try:
        #    http_client.fetch(
        #            options.mquri,
        #            body="queue=snspost&value=%s" % self.json(sns_data),
        #            method='POST',
        #            )
        #except httpclient.HTTPError, e:
        #    pass

        self.render_json(auth.user.user2dict4auth() if auth.user.id>0 else {})
        self.finish()


class RenrenHandler(BaseRequestHandler, RenrenMixin):

    @tornado.web.asynchronous
    def get(self):

        if self.current_user:
            self.set_secure_cookie('userkey', self.current_user.userkey)

        code = self.get_argument("code", None)
        if code:
            self.get_authenticated_user(code, self._on_auth)
            return
        else:
            if not self.current_user:
                self.set_secure_cookie('uid', self.get_argument('uid'))

        self.renren_authorize_redirect()

    def _on_auth(self, outer_user):
        if not outer_user:
            raise HTTPError(500, "Renren auth failed.")

        auth_id = "%s_%s" % (Auth.RENREN, outer_user['uid'])
        auth = Auth.query.get(auth_id)
        user = User.query.get_by_userkey(self.get_secure_cookie('userkey', None)) or auth and auth.user
        self.clear_cookie('userkey')

        # create or update the user
        if user is None and auth is None:
            did = self.get_secure_cookie('uid', None)
            self.clear_cookie('uid')
            if not did:
                raise HTTPError(500, "Renren auth failed.")
            # user data
            user_data = {}
            user_data['userkey'] = auth_id
            user_data['name'] = outer_user['name']
            user_data['avatar'] = outer_user['avatar']
            user_data['brief'] = outer_user['brief']
            user_data['deviceid'] = did

            user = User()
            user.from_dict(user_data)

            user.generate_secret()
            if not user.save():
                raise HTTPError(500, 'Save auth user info error.')

        # auth data
        auth_data = {}
        auth_data['site_label'] = Auth.RENREN
        auth_data['access_token'] = outer_user['access_token']['access_token']
        auth_data['access_secret'] = outer_user['access_token']["refresh_token"] # for 
        auth_data['expired'] = outer_user['access_token']['expires_in'] # maybe error
        auth_data['site_user_id'] = auth_id
        auth_data['user_id'] = user.id

        # create or update the auth
        if auth is None:
            auth = Auth()

        auth.from_dict(auth_data)
        if not auth.save():
            raise HTTPError(500, "Failed auth with renren account.")

        # send to renren 
        #sns_data = {
        #        'token': auth.access_token,
        #        'secret': auth.access_secret,
        #        'label': auth.RENREN,
        #        'content': u"我正在使用乐帮，乐帮是一款基于LBS的帮助应用, 旨在让你在有困难时能更容易地得到帮助。关注@乐帮 - http://whohelp.me",
        #        }
        #http_client = httpclient.HTTPClient()
        #try:
        #    http_client.fetch(
        #            options.mquri,
        #            body="queue=snspost&value=%s" % self.json(sns_data),
        #            method='POST',
        #            )
        #except httpclient.HTTPError, e:
        #    pass

        self.render_json(auth.user.user2dict4auth() if auth.user.id>0 else {})
        self.finish()


class AuthHandler(BaseRequestHandler):

    @authenticated
    @admin
    def get(self, aid):
        if aid:
            auth = Auth.query.get(aid)
            if not auth: raise HTTPError(404)

            info = auth.auth2dict()
            self.render_json(info)
        else:
            q = QDict(
                    q=self.get_argument('q', ""),
                    sort=self.get_argument('qs'),
                    start=int(self.get_argument('st')),
                    num=int(self.get_argument('qn')),
                    )

            query_auths = Auth.query.filter(user_id==self.current_user.id)
            if q.q:
                query_auths = query_auths.filter(Auth.site_user_id.like('%'+q.q+'%'))

            auth_collection = {
                    'auths': [e.auth2dict() for e in query_auths.order_by(q.sort).limit(q.num).offset(q.start)],
                    'total': self.current_user.count(),
                    'link': self.full_uri(),
                    }

            if q.start + q.num < total:
                query_dict['st'] = q.start + q.num
                auth_collection['next'] = self.full_uri(query_dict)

            if q.start > 0:
                query_dict['st'] = max(q.start - q.num, 0)
                auth_collection['prev'] = self.full_uri(query_dict)


            self.render_json(auth_collection)

    @authenticated
    def delete(self, aid):
        auth = Auth.query.get(aid)

        if auth is not None:
            if len(auth.user.auths) > 1:
                if auth.admin_by(self.current_user):
                    self.db.delete(auth)
                    self.db.commit()
                else:
                    raise HTTPError(403, "Admin permission required.")
            else:
                raise HTTPError(412, "Last one can't del.")

        self.set_status(200)
        self.finish()

