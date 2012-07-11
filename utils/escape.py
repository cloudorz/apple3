# coding: utf-8

import json, datetime, re
from bson.objectid import ObjectId
from tornado.escape import recursive_unicode, to_basestring


is_objecid = re.compile(r'^<ObjectId:([a-e0-9]{24})>$')

class JSONDateTimeObjectIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        elif isinstance(obj, ObjectId):
            return "<ObjectId:%s>" % str(obj)
        else:
            #return json.JSONEncoder.default(self, obj)
            return super(JSONDateObjectTimeEncoder, self).default(obj)

def datetime_objectid_decoder(d):
    if isinstance(d, list):
        pairs = enumerate(d)
    elif isinstance(d, dict):
        pairs = d.items()
    result = []
    for k,v in pairs:
        if isinstance(v, basestring):
            try:
                # The %f format code is only supported in Python >= 2.6.
                # For Python <= 2.5 strip off microseconds
                # v = datetime.datetime.strptime(v.rsplit('.', 1)[0],
                #     '%Y-%m-%dT%H:%M:%S')
                v = datetime.datetime.strptime(v, '%Y-%m-%dT%H:%M:%S.%f')
            except ValueError:
                try:
                    v = datetime.datetime.strptime(v, '%Y-%m-%d').date()
                except ValueError:
                    # ObjectId check TODO test
                    re_obj = is_objecid.match(v)
                    if re_obj:
                        v = re_obj.groups()[0]

        elif isinstance(v, (dict, list)):
            v = datetime_objectid_decoder(v)
        result.append((k, v))
    if isinstance(d, list):
        return [x[1] for x in result]
    elif isinstance(d, dict):
        return dict(result)

def json_encode(value):
    return json.dumps(recursive_unicode(value),
            cls=JSONDateTimeObjectIDEncoder).replace("</", "<\\/")

def json_decode(value):
    return json.loads(to_basestring(value),
            object_hook=datetime_objectid_decoder)


if __name__ == '__main__':
    # test
    mytimestamp = datetime.datetime.utcnow()
    mydate = datetime.date.today()
    data = dict(
        foo = 42,
        bar = [mytimestamp, mydate],
        date = mydate,
        timestamp = mytimestamp,
        struct = dict(
            date2 = mydate,
            timestamp2 = mytimestamp
        )
    )

    print repr(data)
    jsonstring = json_encode(data)
    print jsonstring
    print repr(json_decode(jsonstring))
