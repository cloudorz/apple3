# coding: utf-8

import hashlib
from apps import BaseRequestHandler
from apps.documents import User, Message
from utils.decorator import authenticated
from utils.tools import QDict


class MessageHandler(BaseRequestHandler):

    @authenticated
    def get(self, mid):
        if mid:
            msg = Message.query.get_or_404(rid)

            data = msg.dict4show()
            self.render_json(data)
        else:
            q = QDict(
                    start=int(self.get_argument('st')),
                    num=int(self.get_argument('qn')),
                    )

            messages = self.current_user.messages

            total = messages.count()
            query_dict = {
                    'st': q.start,
                    'qn': q.num,
                    }

            msg_collection = {
                    'messages':
                    [e.dict4show() for e in messages.\
                            descending(Message.created).\
                            limit(q.num).\
                            skip(q.start)],
                    'total': total,
                    'link': self.full_uri(query_dict),
                    }

            if q.start + q.num < total:
                query_dict['st'] = q.start + q.num
                msg_collection['next'] = self.full_uri(query_dict)

            if q.start > 0:
                query_dict['st'] = max(q.start - q.num, 0)
                msg_collection['prev'] = self.full_uri(query_dict)
           
            self.cur_messages = msg_collection['messages']
            self.render_json(msg_collection)

    def compute_etag(self):
        hasher = hashlib.sha1()
        if 'cur_messages' in self.__dict__:
            any(hasher.update(e)
                    for e in
                    sorted(msg['id'] for msg in self.cur_messages))

        return '"%s"' % hasher.hexdigest()
