# coding: utf-8

import hashlib, logging

import tornado.httpclient

from tornado.web import HTTPError
from apps import BaseRequestHandler
from apps.documents import User, Loud, Reply, Message
from utils.decorator import authenticated
from utils.tools import QDict, HashIdDict


class PrizeAddHandler(BaseRequestHandler):

    @authenticated
    def post(self):

        data = self.get_data()
        loud = Loud.query.get_or_404_by_urn(data['loud_urn'])
        if not loud.owner_by(self.current_user):
            raise HTTPError(412)

        user_dict = HashIdDict(data['user'])

        loud.thanks.add(user_dict)
        loud.save()

        user_urn = data['user']['id']
        prefix, source, _id = user_urn.split(':')
        if source == 'User':
            user = User.query.get_or_404_by_urn(user_urn)
            user.stars.add(loud.mongo_id)
            user.save()
            self.set_status(200)
            self.finish()
        else:
            # TODO thansk use weibo
            raise HTTPError(412, 'not implatation')

