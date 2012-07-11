# coding: utf-8

import datetime, re, operator, uuid, urlparse
from tornado.options import options
from tornado.httputil import url_concat
from core.ext import db, BaseQuery
from utils.escape import json_encode, json_decode
from utils.tools import HashIdDict


now = datetime.datetime.utcnow

class HashIdDictField(db.DictField):
    def validate_unwrap(self, value):
        # check 'id' in value
        if not isinstance(value, dict) or 'id' not in value:
            self._fail_validation_type(value, dict)
        for k, v in value.iteritems():
            self._validate_key_unwrap(k)
            try:
                self.value_type.validate_unwrap(v)
            except BadValueException, bve:
                self._fail_validation(value,
                        'Bad value for key %s' % k,
                        cause=bve)
        
    def validate_wrap(self, value):
        if not isinstance(value, dict) or 'id' not in value:
            self._fail_validation_type(value, dict)
        for k, v in value.iteritems():
            self._validate_key_wrap(k)
            try:
                self.value_type.validate_wrap(v)
            except BadValueException, bve:
                self._fail_validation(value,
                        'Bad value for key %s' % k,
                        cause=bve)
    
    def wrap(self, value):
        self.validate_wrap(value)
        ret = HashIdDict()
        for k, v in value.iteritems():
            ret[k] = self.value_type.wrap(v)
        return ret
    
    def unwrap(self, value):
        self.validate_unwrap(value)
        ret = HashIdDict()
        for k, v in value.iteritems():
            ret[k] = self.value_type.unwrap(v)
        return ret


class UserQuery(BaseQuery):

    def get_by_urn(self, urn):
        prefix, user_id = urn.rsplit(':', 1)
        return self.get(user_id)

    def get_or_404_by_urn(self, urn):
        prefix, user_id = urn.rsplit(':', 1)
        return self.get_or_404(user_id)


class LoudQuery(BaseQuery):

    def get_by_urn(self, urn):
        prefix, loud_id = urn.rsplit(':', 1)
        return self.get(loud_id)

    def get_or_404_by_urn(self, urn):
        prefix, loud_id = urn.rsplit(':', 1)
        return self.get_or_404(loud_id)

    def get_by_userkey(self, userkey):
        user = User.query.get_or_404(userkey)
        return self.filter(Loud.user_id==user.mongo_id)

    def get_by_position(self, lat, lon):
        # distance TODO 
        return self.filter({'$maxDistance': 0.091, '$near': [float(lon), float(lat)]})

    def get_by_position_key(self, lat, lon, key):
        rqs = [e.lower() for e in re.split('\s+', q) if e]
        regex = re.compile(r'%s' % '|'.join(rqs), re.IGNORECASE)

        # distance TODO 
        return self.filter({
            {'$maxDistance': 0.091, '$near': [float(lon), float(lat)]},
            {'$or': [{'content': regex}, {'tags': {'$in': rqs}}] }
            })


class DeviceQuery(BaseQuery):

    def get_by_uid(self, uid):
        return self.filter(Device.uid==uid)


class User(db.Document):

    query_class = UserQuery

    # person info
    name = db.StringField(max_length=20)
    avatar = db.StringField(default='')
    brief = db.StringField(default='')
    email = db.StringField(default='')
    phone = db.StringField(default='')
    location = db.TupleField(db.FloatField(), db.FloatField(), default=())
    # honer 
    helps = db.SetField(db.ObjectIdField(), default=set())
    stars = db.SetField(db.ObjectIdField(), default=set())
    # auth info
    secret = db.StringField(max_length=32)
    dtoken = db.StringField(default='')
    # third party info
    site_label = db.StringField()
    access_token = db.StringField()
    access_secret = db.StringField()
    expired = db.IntField()
    # addtional
    block = db.BoolField(default=False)
    role = db.EnumField(db.StringField(max_length=10), 'user', 'admin',
            'merchant', default='user')
    @db.computed_field(db.DateTimeField())
    def updated(self):
        return now()
    created = db.DateTimeField(default=now())

    @property
    def louds(self):
        return Loud.query.filter(Loud.user_id==self.mongo_id)

    @property
    def messages(self):
        return Message.query.filter(Message.user_id==self.mongo_id)

    @property
    def userkey(self):
        return str(self.mongo_id)

    def generate_secret(self):
        self.secret = uuid.uuid4().get_hex()

    def dict4show(self):
        data = self.to_dict('name', 'link', 'avatar_link',
                'brief', 'role', 'updated', 'created')
        data['loud_num'] = self.louds.count()
        data['star_num'] = len(self.stars)
        data['help_num'] = len(self.helps)

        return data

    def dict4auth(self):
        data = self.to_dict('name', 'link', 'avatar_link', 'userkey',
                'secret', 'updated', 'phone', 'brief')

        return data

    def dict4link(self):
        data = self.to_dict('name', 'link', 'avatar_link')
        data['loud_num'] = self.louds.count()
        data['star_num'] = len(self.stars)
        data['help_num'] = len(self.helps)

        return data

    def snapshot(self):
        data = self.to_dict('name', 'link', 'avatar_link')
        return data

    @property
    def link(self):
        return urlparse.urljoin(options.site_uri,
                self.reverse_url('User', self.pk))

    @property
    def avatar_link(self):
        return urlparse.urljoin(options.static_uri, self.avatar)

    def owner_by(self, user):
        return self.pk == user.pk


class Message(db.Document):
     
    #user = db.DocumentField('User')
    user_id = db.ObjectIdField()
    category = db.StringField()
    content = db.StringField()
    obj_link = db.StringField(default='')
    is_read = db.BoolField(default=False)
    created = db.DateTimeField(default=now())

    def _get_user(self):
        return User.query.get(self.user_id)

    def _set_user(self, user):
        self.user_id = user.mongo_id

    user = property(_get_user, _set_user)

    def dict4show(self):
        data = self.to_dict('category', 'content', 'obj_link',
                 'is_read', 'created', 'link')
        #data['user'] = self.user.snapshot()

        return data

    @property
    def link(self):
        return urlparse.urljoin(options.site_uri,
                self.reverse_url('Message', self.pk))


class Loud(db.Document):

    query_class = LoudQuery
    
    #user = db.DocumentField('User')
    user_id = db.ObjectIdField()
    content = db.StringField()
    tags = db.SetField(db.StringField(), max_capacity=10, default=set())
    image = db.StringField(default='')
    status = db.EnumField(db.StringField(max_length=15),
            'err', 'close', 'wait', 'processing', default='wait')
    category = db.StringField()
    # posiiton poi location
    location = db.TupleField(db.FloatField(), db.FloatField(), default=())
    poi = db.StringField(default='')
    address = db.StringField(default='')
    # about people {'id': 'urn:user:xxxxxx'/'urn:weibo:xxxxxx', 'avatar_link':
    # xxx, # 'link': xxxx, 'name':xxx}
    candidates = db.SetField(HashIdDictField(db.AnythingField()), default=set())
    thanks = db.SetField(HashIdDictField(db.AnythingField()), default=set())
    @db.computed_field(db.DateTimeField())
    def updated(self):
        return now()
    created = db.DateTimeField(default=now())

    def _get_user(self):
        return User.query.get(self.user_id)

    def _set_user(self, user):
        self.user_id = user.mongo_id

    user = property(_get_user, _set_user)
    def _get_tag_content(self):
        return self.content

    def _set_tag_content(self, data):
        if isinstance(data, basestring):
            self.content = data
            regex = re.compile(r'#\s*(.*?)\s*#', re.IGNORECASE)
            self.tags = set(e.lower() for e in regex.findall(data) if e)

    tag_content = property(_get_tag_content, _set_tag_content)

    @property
    def replies(self):
        return Reply.query.filter(Reply.loud_id==self.mongo_id)

    def dict4show(self):
        # get full url for next
        st = 0
        qn = 20
        def full_url(**qdict):
            return url_concat(urlparse.urljoin(options.site_uri,
                self.reverse_url('Reply', '')), 
                qdict
                )

        data = self.to_dict('content', 'image', 'status', 'location',
                'poi', 'address', 'category', 'candidates', 'updated',
                'created', 'link')
        total = self.replies.count()
        data['reply_num'] = total
        data['user'] = self.user.dict4link()
        data['reply_collection'] = {
                'replies': [e.dict4show() for e in
                    self.replies.descending(Reply.created).limit(qn)],
                'total': total,
                'link': full_url(st=st, qn=qn, lid=self.pk),
                'thanks': list(self.thanks),
                } 

        if total > qn:
            data['reply_collection']['next'] = full_url(st=st+qn, qn=qn,
                    lid=self.pk)
        return data

    def snapshot(self):
        data = self.to_dict('content', 'image', 'status', 'location', 'poi',
                'address', 'category', 'created', 'link')
        data['reply_num'] = self.replies.count()
        data['user'] = self.user.dict4link()

        return data

    @property
    def link(self):
        return urlparse.urljoin(options.site_uri,
                self.reverse_url('Loud', self.pk))

    @property
    def is_closed(self):
        return self.status == 'close'

    def owner_by(self, user):
        return self.user.pk == user.pk


class Reply(db.Document):

    user = db.DictField(db.AnythingField())
    loud_id = db.ObjectIdField()
    has_phone = db.BoolField(default=False)
    content = db.StringField()
    created = db.DateTimeField(default=now())

    def _get_loud(self):
        return Loud.query.get(self.loud_id)

    def _set_loud(self, loud):
        self.loud_id = loud.mongo_id

    loud = property(_get_loud, _set_loud)

    def dict4show(self):
        data = self.to_dict('user', 'has_phone', 'content', 'created')
        return data

    @property
    def link(self):
        return urlparse.urljoin(options.site_uri,
                self.reverse_url('Reply', self.pk))

