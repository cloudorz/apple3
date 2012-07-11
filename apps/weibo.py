# coding: utf-8

import tornado.web

from tornado.web import HTTPError

from apps import BaseRequestHandler, WeiboMixin
from apps.documents import User
from utils.tools import QDict


class POIHandler(BaseRequestHandler, WeiboMixin):

    @authenticated
    @tornado.web.asynchronous
    def get(self, lat, lon, page=1):

        user = User.query.get('xxxxxxx') # FIXME let me real
        if page < 0: page = 1

        q = self.args.get('q', None)
        args = dict(
                access_token=user.access_token,
                lat=lat,
                long=lon,
                range=3000,
                p=page,
                )
        if q:
            args['q'] = q

        self.weibo_request('place/nearby/pois',
                self.poi_response,
                **args
                )

    def poi_response(self, data):
        self.render_string(data)
        self.finish()


class NearbyUserHandler(BaseRequestHandler, WeiboMixin):

    @authenticated
    @tornado.web.asynchronous
    def get(self, lat, lon, page=1):

        if page < 0: page = 1

        user = User.query.get('xxxxxxx') # FIXME let me real
        self.weibo_request('place/nearby/users', 
                self.nearby_user_response,
                access_token=user.access_token,
                lat=lat,
                long=lon,
                range=3000,
                p=page,
                count=50,
                sort=0, # 排序方式，0：按时间、1：按距离，默认为0
                )

    def nearby_user_response(self, data):
        self.render_string(data)
        self.finish()
