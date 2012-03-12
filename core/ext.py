# coding: utf-8

from pymongo import Connection, ASCENDING, DESCENDING

__all__ = ['db', 'ASCENDING', 'DESCENDING']

db = Connection('localhost', 27017)['apple3']
