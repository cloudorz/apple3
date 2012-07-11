# coding: utf-8

import hashlib, datetime, logging

import tornado.httpclient

from tornado import gen
from tornado.web import asynchronous, HTTPError
from tornado.options import options

from apps import BaseRequestHandler
from apps.documents import User, Loud, Reply
from utils.decorator import authenticated
from utils.tools import QDict, pretty_time_str


now = datetime.datetime.utcnow

class LoudHandler(BaseRequestHandler):

    def get(self, lid):
        loud = Loud.query.get_or_404(lid)

        info = loud.dict4show()
        self.render_json(info)

    @authenticated
    def post(self, lid):

        loud_data = self.get_data()

        loud = Loud()
        loud.populate(loud_data)
        loud.user = self.current_user
        loud.created = now()

        loud.maybe_save()
        if 'location' in loud_data:
            self.current_user.location = loud_data['location']
            self.current_user.save()

        self.set_status(201)
        self.set_header('Location', loud.link)
        self.finish()

    @authenticated
    def put(self, lid):

        loud = Loud.query.get(lid)
        if loud and loud.owner_by(self.current_user):
            data = self.get_data()
            loud.populate(data)
            loud.maybe_save()
        else:
            raise HTTPError(403, "The loud is not existed or No permission to operate")

        self.set_status(200)
        self.finish()

    @authenticated
    def delete(self, lid):
        loud = Loud.query.get(lid)
        if loud and loud.owner_by(self.current_user):
            any(e.remove() for e in loud.replies)
            loud.remove()

        self.set_status(200)
        self.finish()


class SearchLoudHandler(BaseRequestHandler):

    def get(self):
        condition = self.get_argument('q')
        if ':' in condition:
            field, value = condition.split(':')
        else:
            raise HTTPError(400, "condition's format field:value")

        handle_q = {
                'author': lambda userkey: Loud.query.get_by_userkey(userkey),
                'position': lambda data: \
                        Loud.query.get_by_position(data.split(',')),
                'key': lambda data: \
                        Loud.query.get_by_position_key(*data.split(',')),
                'all': lambda data: Loud.query,
                }

        if field in handle_q:
            q = QDict(
                    q=condition,
                    v=value,
                    start=int(self.get_argument('st')),
                    num=int(self.get_argument('qn')),
                    )

            query_louds = handle_q[field](q.v)

            # composite the results collection
            total = query_louds.count()
            query_dict = {
                    'q': q.q,
                    'st': q.start,
                    'qn': q.num,
                    }

            loud_collection = {
                    'louds': [e.snapshot() for e in query_louds.\
                            descending(Loud.created).\
                            limit(q.num).skip(q.start)],
                    'total': total,
                    'link': self.full_uri(query_dict),
                    }

            if q.start + q.num < total:
                query_dict['st'] = q.start + q.num
                loud_collection['next'] = self.full_uri(query_dict)

            if q.start > 0:
                query_dict['st'] = max(q.start - q.num, 0)
                loud_collection['prev'] = self.full_uri(query_dict)

            gmt_now = datetime.datetime.utcnow()
            self.set_header('Last-Modified', pretty_time_str(gmt_now))
	    # make etag prepare
	    self.cur_louds = loud_collection['louds']

        else:
            raise HTTPError(400, "Bad Request, search condtion is not allowed.")

        self.render_json(loud_collection)

    def compute_etag(self):
        hasher = hashlib.sha1()
        if 'cur_louds' in self.__dict__:
            any(hasher.update(e)
                    for e in
                    sorted(loud['id'] for loud in self.cur_louds))

        return '"%s"' % hasher.hexdigest()
