# coding: utf-8

import hashlib, logging, datetime

import tornado.httpclient

from apps import BaseRequestHandler
from apps.documents import User, Loud, Reply, Message
from utils.decorator import authenticated
from utils.tools import QDict


now = datetime.datetime.utcnow


class ReplyHandler(BaseRequestHandler):

    def get(self, rid):
        if rid:
            reply = Reply.query.get_or_404(rid)

            info = reply.dict4show()
            self.render_json(info)
        else:
            q = QDict(
                    lid=self.get_argument('lid'),
                    start=int(self.get_argument('st')),
                    num=int(self.get_argument('qn')),
                    )
            loud = Loud.query.get_or_404(q.lid)

            total = loud.replies.count()
            query_dict = {
                    'lid': q.lid,
                    'st': q.start,
                    'qn': q.num,
                    }

            reply_collection = {
                    'replies':
                    [e.dict4show() for e in loud.replies.\
                            descending(Reply.created).\
                            limit(q.num).\
                            skip(q.start)],
                    'total': total,
                    'link': self.full_uri(query_dict),
                    'thanks': list(loud.thanks),
                    }

            if q.start + q.num < total:
                query_dict['st'] = q.start + q.num
                reply_collection['next'] = self.full_uri(query_dict)

            if q.start > 0:
                query_dict['st'] = max(q.start - q.num, 0)
                reply_collection['prev'] = self.full_uri(query_dict)
           
            self.cur_replies = reply_collection['replies']
            self.render_json(reply_collection)

    @authenticated
    def post(self, rid):

        # the loud precondtion OK
        reply_data = self.get_data()
        loud = Loud.query.get_or_404_by_urn(reply_data['loud_urn'])
        if loud.is_closed:
            self.set_status(412)
            self.render_json({'status': 'close',
                'msg': 'Precondition error, loud status changed'})
            self.finish()
            return

        if self.current_user.role != 'admin' or 'user' not in reply_data:
            # TODO about weibo user
            reply_data['user'] = self.current_user.snapshot() 

        reply = Reply()
        reply.loud = loud
        reply.populate(reply_data)
        reply.created = now()
        reply.maybe_save()

        # add to helps mark help others
        if not loud.owner_by(self.current_user):
            self.current_user.helps.add(loud.mongo_id)
            self.current_user.save()

        if 'ats' in reply_data:
            for e in set(reply_data['ats']):
                # TODO other people come from weibo?
                user = User.query.get_by_urn(e)
                if user and user.mongo_id != self.current_user.mongo_id:
                    msg = Message()
                    msg.category = 'reply'
                    msg.user = user
                    msg.obj_link = loud.link
                    msg.created = now()
                    msg.content = u'在信息"%s"中%s给你作出了回应, 点击查看' % \
                    (loud.content[:100], self.current_user.name)
                    msg.save()


        self.set_status(201)
        self.set_header('Location', reply.link)
        self.finish()

    def compute_etag(self):
        hasher = hashlib.sha1()
        if 'cur_replies' in self.__dict__:
            any(hasher.update(e)
                    for e in
                    sorted(reply['id'] for reply in self.cur_replies))

        return '"%s"' % hasher.hexdigest()
