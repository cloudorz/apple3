# coding: utf-8

import datetime, re, operator, uuid

from core.ext import db
from utils.escape import json_encode, json_decode


now = datetime.datetime.utcnow


class Basic(object):
    pass


class Device(Basic):

    deviceid = db.StringField(max_length=50)
    dtoken = db.StringField(80)


class User(Basic):

    attrs = {
            'userkey': True,
            'secret': True,
            'name': True,
            'role': True,
            'school': True,
            'deviceid': False,
            'avatar': False,
            'phone': False,
            'brief': False,
            'location': False,
            'prizes': False,
            'updated': True,
            'created': True,
            }

    rights = ('normal', 'admin', 'sa', 'block')

    tpl = {'_id':1, 'name': 1, 'avatar': 1, 'brief': 1, 'role': 1, 'prizes': 1}

    def __init__(self, data, *args, **kwargs):
        pass

    def can_save(self):
        pass

    def _secret(self):
        return uuid.uuid4().get_hex()

    def get(self):
        pass

    def put(self):
        pass

    def post(self):
        pass

    def delete(self):
        pass


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
