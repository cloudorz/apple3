# coding: utf-8

import os.path, hashlib
from tornado.options import options

def save_images(http_files, user):

    for http_file in http_files:
        prefix, ext = http_file['filename'].rsplit('.', 1)
        filename = "i/%s.%s" % (user.userkey, ext)
        file_path = os.path.join(options.path, filename)
        with open(file_path, 'wb') as f:
            f.write(http_file['body'])
            user.avatar = filename
            user.save()

        if not os.path.exists(file_path):
            return False

    return True
