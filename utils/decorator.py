# coding: utf-8

import functools

from tornado.web import HTTPError

def authenticated(method):
    """Decorate methods with this to require that the user be logged in."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user: 
            self.set_header('WWW-Authenticate', 'Basic realm="userkey/token"')
            self.set_status(401)
            return
            #raise HTTPError(401)
        return method(self, *args, **kwargs)
    return wrapper

def validclient(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.check_valid_client():
            raise HTTPError(403)
        return method(self, *args, **kwargs)
    return wrapper

def admin(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user.is_admin:
            raise HTTPError(403, "Need admin permission.")
        return method(self, *args, **kwargs)
    return wrapper
