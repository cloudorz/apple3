# coding: utf-8

import httplib, traceback, urlparse, urllib, base64, hmac, hashlib
import logging

import tornado.web
import tornado.httpclient

from tornado.web import HTTPError
from tornado.options import options
from tornado.httputil import url_concat
from tornado.auth import OAuthMixin, OAuth2Mixin, OpenIdMixin
from tornado.escape import url_escape, utf8
#from tornado.escape import url_unescape

from utils.escape import json_encode, json_decode
from apps.models import User, App

# The base request handler class
class BaseRequestHandler(tornado.web.RequestHandler):
    """the base RequestHandler for All."""

    def get_data(self):
        ''' parse the data from request body
        now, only convert json data to python type
        '''
        # the content type is not "application/json"
        if not self.is_json:
            raise HTTPError(415)

        try:
            data = self.dejson(self.request.body)
        except (ValueError, TypeError), e:
            raise HTTPError(415) # the data is not the right json format

        return data

    @property
    def is_json(self):
        return self.request.headers.get('Content-Type', '').split(';').pop(0).strip().lower() == 'application/json'

    def write_error(self, status_code, **kwargs):
        if self.settings.get("debug") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            for line in traceback.format_exception(*kwargs["exc_info"]):
                self.write(line)
        else:
            self.write("code: %s \n " % status_code)
            self.write("message: %s \n " % httplib.responses[status_code])

        self.set_header('Content-Type', 'text/plain')
        self.finish()

    def render_json(self, data, **kwargs):
        ''' Render data string(json) for response.
        '''
        self.set_header('Content-Type', 'Application/json; charset=UTF-8')
        self.write(self.json_encode(data))

    def get_current_user(self):

        auth_header = self.parse_auth_header()

        if auth_header:
            required_params = {
                    "auth_app_key",
                    "auth_user_key",
                    "auth_once",
                    "auth_timestamp",
                    "auth_signature_method",
                    "auth_signature",
                    }
            given_params = set(auth_header)

            if not (required_params <= given_params):
                raise HTTPError(400, "Bad Request. Lack params: %s" % 
                        ', '.join(required_params - given_params)
                        )

            app = App.query.get(auth_header['auth_app_key'])
            user = User.query.get_by_userkey(auth_header['auth_user_key'])

            if not (user and app):
                raise HTTPError(400, "Bad Reques, user not exists.")

            token = {
                    'key': user.userkey,
                    'secret': user.secret
                    }

            client = {
                    'key': app.pk,
                    'secret': app.secret,
                    }

            reauth_signature = self.build_signature(client, token, auth_header)
            auth_signature = urllib.unquote(auth_header['auth_signature'])
            if auth_signature == reauth_signature:
                return user
            else:
                raise HTTPError(400,
                        "Bad Request. signature dismatch, expect %s, but given %s" %
                        (reauth_signature, auth_header['auth_signature'])
                        )

        return None

    def parse_auth_header(self):

        auth_value = self.request.headers.get('Authorization', None)
        if auth_value and auth_value.startswith('Auth '):
            prefix, value = auth_value.split(" ", 1)
            value = value.strip()

            res = {}
            for e in value.split(','):
                k, v = e.strip().split('=', 1)
                res[k] = v.strip('"')
            return res

        return None

    def get_normalized_http_method(self):
        res = self.request.method.upper()
        return res
    
    def get_normalized_http_url(self):
        req = self.request
        res = "%s://%s%s" % (req.protocol, req.host, req.path)
        return res

    def _query_args_a0(self, s):
        query_args = urlparse.parse_qs(s, keep_blank_values=False)
        return {k: urllib.unquote(v[0]) for k, v in query_args.items()}

    def get_normalized_parameters(self, auth_header):
        # from header 
        args = self._query_args_a0(self.request.query)
        args.update({k: v for k, v in auth_header.items()
            if k[:5] == 'auth_' and k != 'auth_signature'})
        key_values = args.items()
        key_values.sort()

        res = '&'.join('%s=%s' % (self._url_escape(str(k)), self._url_escape(str(v))) for k, v in key_values)
        return res

    def build_signature(self, client, token, auth_header):
        sig = (
                self._url_escape(self.get_normalized_http_method()),
                self._url_escape(self.get_normalized_http_url()),
                self._url_escape(self.get_normalized_parameters(auth_header)),
                )
        key = '%s&%s' % (self._url_escape(client['secret']), self._url_escape(token['secret']))
        raw = '&'.join(sig)

        # hmac object
        hashed = hmac.new(key, raw, hashlib.sha1)

        return base64.b64encode(hashed.digest())

    def _url_escape(self, s):
        return urllib.quote(s, safe='~')

    def full_uri(self, query_dict=None):
        #return url_unescape(url_concat("%s%s" % (options.site_uri, self.request.path), query_dict))
        #return url_concat(self.request.full_url(), query_dict)
        return url_concat(self.get_normalized_http_url(), query_dict)


class DoubanMixin(OAuthMixin):

    _OAUTH_REQUEST_TOKEN_URL = "http://www.douban.com/service/auth/request_token"
    _OAUTH_AUTHORIZE_URL = "http://www.douban.com/service/auth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "http://www.douban.com/service/auth/access_token"
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_VERSION = "1.0"

    def douban_request(self, path, callback, method='GET', access_token=None,
            body=None, **args):

        url = urlparse.urljoin("http://api.douban.com", urllib.quote(path))

        headers = None
        if access_token:
            # douban's signa must encode the url
            if method != 'GET':
                oauth = self._oauth_request_parameters(url, access_token, method=method)
                headers = self.to_header(parameters=oauth)
                if method in ('POST', 'PUT'):
                    headers['Content-Type'] = 'Application/atom+xml; charset=utf-8'
            else:
                oauth = self._oauth_request_parameters(url, access_token, args, method=method)
                args.update(oauth)

        if args: 
            url = url_concat(url, args)

        callback = self.async_callback(self._on_douban_request, callback)

        http_client = tornado.httpclient.AsyncHTTPClient()
        http_client.fetch(url, method=method, headers=headers, body=body, callback=callback)

    def to_header(self, realm='', parameters=None):
        """Serialize as a header for an HTTPAuth request."""
        auth_header = 'OAuth realm="%s"' % realm
        # Add the oauth parameters.
        if parameters:
            auth_header = "%s, %s" % (auth_header, ', '.join('%s="%s"' % (k, urllib.quote(str(v))) for
                k,v in parameters.items() if k[:6] == 'oauth_'))
        return {'Authorization': auth_header}

    def _on_douban_request(self, callback, response):
        if response.error:
            logging.warning("Error response %s fetching %s", response.error, response.request.url)
            callback(None)
            return

        try:
            res = json_decode(response.body)
        except (ValueError, TypeError):
            res = response.body

        callback(res)

    def _oauth_consumer_token(self):
        self.require_setting('douban_consumer_key', "Douban OAuth")
        self.require_setting('douban_consumer_secret', "Douban OAuth")

        return dict(
                key=self.settings['douban_consumer_key'],
                secret=self.settings['douban_consumer_secret'],
                )
    
    def _oauth_get_user(self, access_token, callback):
        callback = self.async_callback(self._parse_user_response, callback)
        self.douban_request(
                "/people/@me",
                access_token=access_token,
                callback=callback,
                alt='json',
                )

    def _parse_user_response(self, callback, user):
        if user:
            user['name'] = user['title']['$t']
            user['brief'] = user['content']['$t'][:70]
            user['avatar'] = self._find_icon(user['link'])
            user['expired'] = -1
        callback(user)

    def _find_icon(self, links):
        for e in links:
            if e['@rel'] == 'icon':
                return e['@href']


class WeiboMixin(OAuth2Mixin):

    _OAUTH_AUTHORIZE_URL = "https://api.weibo.com/oauth2/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://api.weibo.com/oauth2/access_token"

    def weibo_request(self, path, callback, method='GET', access_token=None, **args):

        url = urlparse.urljoin("https://api.weibo.com/2/", "%s.json" % path)

        if method in ('POST', 'PUT'):
            body = urllib.urlencode(args)
        else:
            url = url_concat(url, args)
            body = None

        callback = self.async_callback(self._on_weibo_request, callback)

        http_client = tornado.httpclient.AsyncHTTPClient()
        http_client.fetch(url, method=method,
                body=body,
                headers={'Authorization': "OAuth2 %s" % access_token},
                callback=callback,
                )

    def _on_weibo_request(self, callback, response):
        if response.error:
            logging.warning("Warn: response %s fetching %s", response.error, response.request.url)
            callback(None)
            return

        info = json_decode(response.body)
        if 'error' in info:
            logging.warning("Warn! code: %s, message: %s", info['error_code'], info['error'])
            callback(None)
            return

        callback(info)

    def weibo_authorize_redirect(self, redirect_uri=None):
        client = self._client_token()
        #redirect_uri = urlparse.urljoin(self.request.full_url(), redirect_uri)
        redirect_uri = urlparse.urljoin(self._full_uri_or_ip(), redirect_uri)

        self.authorize_redirect(
                redirect_uri=redirect_uri, 
                client_id=client['key'],
                client_secret=client['secret'],
                extra_params={'response_type': 'code'},
                )

    def get_authenticated_user(self, code, callback, redirect_uri=None, http_client=None):

        client = self._client_token()

        #redirect_uri = urlparse.urljoin(self.request.full_url(), redirect_uri)
        redirect_uri = urlparse.urljoin(self._full_uri_or_ip(), redirect_uri)

        url = self._OAUTH_ACCESS_TOKEN_URL

        extra_params = {
                'grant_type': 'authorization_code',
                }

        args = dict(
            redirect_uri=redirect_uri,
            code=code,
            client_id=client['key'],
            client_secret=client['secret'],
            )
        args.update(extra_params)

        body = urllib.urlencode(args)

        if http_client is None:
            http_client = tornado.httpclient.AsyncHTTPClient()

        callback = self.async_callback(self._on_access_token, callback)

        http_client.fetch(url, method='POST', body=body, callback=callback)

    def _on_access_token(self, callback, response):
        if response.error:
            logging.warning("Error response %s fetching %s", response.error, response.request.url)
            callback(None)
            return

        access_token = json_decode(response.body)
        self._oauth_get_user(access_token, self.async_callback(
             self._on_oauth_get_user, access_token, callback))

    def _on_oauth_get_user(self, access_token, callback, user):
        if not user:
            callback(None)
            return
        user["access_token"] = access_token
        callback(user)

    def _oauth_get_user(self, access_token, callback):
        callback = self.async_callback(self._parse_user_response, callback)
        self.weibo_request(
                "users/show",
                callback,
                access_token=access_token['access_token'],
                uid=access_token['uid'],
                )

    def _parse_user_response(self, callback, user):
        if user:
            user['avatar'] = user['profile_image_url']
            user['brief'] = user['description']
        callback(user)

    def _client_token(self):
        self.require_setting('weibo_app_key', "Weibo OAuth2")
        self.require_setting('weibo_app_secret', "Weibo OAuth2")

        return dict(
                key=self.settings['weibo_app_key'],
                secret=self.settings['weibo_app_secret'],
                )
    
    def _full_uri_or_ip(self):
        if self.request.host == 'localhost':
            url = "http://192.168.0.124/weibo/auth"
        else:
            req = self.request
            url = "%s://%s%s" % (req.protocol, req.host, req.path)

        return url


class RenrenMixin(OAuth2Mixin):

    _OAUTH_AUTHORIZE_URL = "https://graph.renren.com/oauth/authorize"
    _OAUTH_ACCESS_TOKEN_URL = "https://graph.renren.com/oauth/token"

    def renren_request(self, method, callback, fields, access_token=None, **args):

        url = "http://api.renren.com/restserver.do"

        params = {
                'method': method,
                'v': "1.0",
                'format': "JSON",
                'fields': fields,
                'access_token': access_token,
                }
        params['sig'] = self.sig(params)

        body = urllib.urlencode(params)

        callback = self.async_callback(self._on_renren_request, callback)

        http_client = tornado.httpclient.AsyncHTTPClient()
        http_client.fetch(url, method='POST',  callback=callback, body=body)

    def sig(self, params):
        client = self._client_token()
        params_str = ''.join(sorted("%s=%s" % (k, utf8(v)) for k,v in params.items()))
        v = "%s%s" % (params_str, client['secret'])

        return hashlib.md5(v).hexdigest()

    def _on_renren_request(self, callback, response):
        if response.error:
            logging.warning("Warn: response %s fetching %s", response.error, response.request.url)
            callback(None)
            return

        info = json_decode(response.body)
        if 'error' in info or 'error_code' in info:
            logging.warning("Warn! code: %s, message: %s", info['error_code'], info.get('error', info.get('error_msg')))
            callback(None)
            return

        callback(info[0])

    def renren_authorize_redirect(self, redirect_uri=None):
        client = self._client_token()
        #redirect_uri = urlparse.urljoin(self.request.full_url(), redirect_uri)
        redirect_uri = urlparse.urljoin(self._full_uri_or_ip(), redirect_uri)

        self.authorize_redirect(
                redirect_uri=redirect_uri, 
                client_id=client['key'],
                client_secret=client['secret'],
                extra_params={'response_type': 'code',
                              'scope': 'status_update'},
                )

    def get_authenticated_user(self, code, callback, redirect_uri=None, http_client=None):

        client = self._client_token()

        #redirect_uri = urlparse.urljoin(self.request.full_url(), redirect_uri)
        redirect_uri = urlparse.urljoin(self._full_uri_or_ip(), redirect_uri)

        url = self._OAUTH_ACCESS_TOKEN_URL

        extra_params = {
                'grant_type': 'authorization_code',
                }

        args = dict(
            redirect_uri=redirect_uri,
            code=code,
            client_id=client['key'],
            client_secret=client['secret'],
            )
        args.update(extra_params)

        body = urllib.urlencode(args)

        if http_client is None:
            http_client = tornado.httpclient.AsyncHTTPClient()

        callback = self.async_callback(self._on_access_token, callback)

        http_client.fetch(url, method='POST', body=body, callback=callback)

    def _on_access_token(self, callback, response):
        if response.error:
            logging.warning("Error response %s fetching %s", response.error, response.request.url)
            callback(None)
            return

        access_token = json_decode(response.body)
        self._oauth_get_user(access_token, self.async_callback(
             self._on_oauth_get_user, access_token, callback))

    def _on_oauth_get_user(self, access_token, callback, user):
        if not user:
            callback(None)
            return
        user["access_token"] = access_token
        callback(user)

    def _oauth_get_user(self, access_token, callback):
        callback = self.async_callback(self._parse_user_response, callback)
        self.renren_request(
                "users.getInfo",
                callback,
                "uid,name,tinyurl",
                access_token['access_token'],
                )

    def _parse_user_response(self, callback, user):
        if user:
            user['avatar'] = user['tinyurl']
            user['brief'] = ""
        callback(user)

    def _client_token(self):
        self.require_setting('renren_app_key', "Renren OAuth2")
        self.require_setting('renren_app_secret', "Renren OAuth2")

        return dict(
                key=self.settings['renren_app_key'],
                secret=self.settings['renren_app_secret'],
                )
    
    def _full_uri_or_ip(self):
        if self.request.host == 'localhost':
            url = "http://192.168.0.124/renren/auth"
        else:
            req = self.request
            url = "%s://%s%s" % (req.protocol, req.host, req.path)

        return url

