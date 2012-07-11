# coding: utf-8

from tornadoext.mongoalchemy import MongoAlchemy, BaseQuery

__all__ = ['db', 'BaseQuery']

db = MongoAlchemy()
