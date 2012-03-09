# coding: utf-8

import datetime, re, operator, uuid

from tornadomongoalchemy.mongoalchemy import BaseQuery

from core.ext import db


now = datetime.datetime.utcnow


class UserQuery(BaseQuery):

    def get_by_userkey(self, uk):
        user = self.filter(User.userkey==uk, User.status!=User.BLOCK).first()
        return user


class Device(db.Document):

    deviceid = db.StringField(max_length=50)
    dtoken = db.StringField(80)


class User(db.Document):

    query_class = UserQuery

    BLOCK, NORMAL, ADMIN, SA = 0, 100, 200, 300

    userkey = db.StringField(max_length=30)
    name = db.StringField(max_length=20)
    avatar = db.StringField(max_length=100)
    phone = db.StringField(max_length=15, default="")
    deviceid = db.StringField(max_length=50, default="")
    brief = db.StringField(max_length=120, default="")
    location = db.TupleField(db.FloatField(), db.FloatField())
    role = db.EnumField(db.IntField(), BLOCK, NORMAL, ADMIN, SA, default=NORMAL)
    prizes = db.SetField(db.ObjectIdField())

    @db.computed_field(db.StringField(max_length=32))
    def secret(self):
        return uuid.uuid4().get_hex()

    @db.computed_field(db.DateTimeField())
    def updated(self):
        return now()


class Auth(db.Document):

    WEIBO, RENREN, DOUBAN = 'weibo', 'renren', 'douban'

    site_outer = db.StringField()
    user = db.DocumentField(User)
    site_label = db.EnumField(db.StringField(), WEIBO, RENREN, DOUBAN)
    access_token = db.StringField(max_length=64)
    access_secret = db.StringField(max_length=64)
    expired = db.IntField()


class App(db.Document):

    name = db.StringField(max_length=15)

    @db.computed_field(db.StringField(32))
    def secret(self):
        return uuid.uuid4().get_hex()


class LoudCate(db.Document):

    no = db.IntField() 
    label = db.StringField(max_length=10)
    name = db.StringField(max_length=20)
    desc = db.StringField(max_length=70)


class School(db.Document):

    label = db.StringField(max_length=20)
    name = db.StringField(max_length=60)
    location = db.TupleField(db.FloatField(), db.FloatField())
    group_no = db.IntField() 


class Loud(db.Document):
    
    ERR, OVERDUE, SHOW, DONE = 0, 100, 200, 300

    user = db.DocumentField(User)
    school = db.DocumentField(School)
    loudcate = db.DocumentField(LoudCate)
    _content = db.StringField(db_field="content", max_length=120)
    replies = db.ListField(db.DictField(db.AnythingField()))
    tags = db.SetField(item_type=db.StringField(), max_capacity=8)
    thanks = db.SetField(db.ObjectIdField())
    expired = db.DateTimeField()
    image = db.StringField(max_length=100)
    status = db.EnumField(db.IntField, ERR, OVERDUE, SHOW, DONE, default=SHOW)

    @db.computed_field(db.DateTimeField())
    def updated(self):
        return now()

    def _get_content(self):
        return self._content

    def _set_content(self, data):
        if isinstance(data, basestring):
            self._content = data
            regex = re.compile(r'#\s*(.*?)\s*#', re.IGNORECASE)
            self.tags = set(e.lower() for e in regex.finditer(data) if e)

    content = property(_get_tags, _set_tags)