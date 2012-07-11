# coding: utf-8

import uuid, re

from tornado.web import HTTPError

from apps import BaseRequestHandler
from apps.documents import User, Loud
from utils.decorator import authenticated
from utils.imagepp import save_images
from utils.tools import generate_password, QDict
from utils.escape import json_encode, json_decode


class UserHandler(BaseRequestHandler):

    def get(self, uid):
        user = User.query.get_or_404(uid)

        info = user.dict4show()
        self.render_json(info)

    @authenticated
    def put(self, uid):
        ''' The User object can't modify phone
        '''
        user = User.query.get(uid)
        if not user: raise HTTPError(404)

        data = self.get_data()
        if  user.owner_by(self.current_user) and \
                not ({'userkey', 'role', 'token', 'avatar'} & set(data)):
            user.populate(data)
            user.maybe_save()
        else:
            raise HTTPError(403, "No permission.")

        self.set_status(200)
        self.finish()

    @authenticated
    def delete(self, uid):
        user = User.query.get(uid)

        if user:
            if user.owner_by(self.current_user):
                any(e.remove() for e in user.louds) # rmove louds 
                user.remove()
            else:
                raise HTTPError(403, "No permission.")

        self.set_status(200)
        self.finish()


class UploadHandler(BaseRequestHandler):

    @authenticated
    def post(self):
        if 'photo' in self.request.files:
            if not save_images(self.request.files['photo'], self.current_user):
                raise HTTPError(501, "save image error.")
        else:
            raise HTTPError(400, 'upload parameters dismatch')

        self.finish()
