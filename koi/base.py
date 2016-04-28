# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

import json
import logging
import urllib

import tornado.httpclient
from tornado.gen import coroutine, Return
from tornado.web import RequestHandler
from tornado.options import options

from chub import API

from .exceptions import HTTPError
from .configure import ssl_server_options

def _get_http_error(kwargs):
    if 'exc_info' in kwargs and hasattr(kwargs['exc_info'][1], 'errors'):
        return kwargs['exc_info'][1]


class CorsHandler(RequestHandler):
    """Shared code for handling CORS"""
    def set_default_headers(self):
        """Set the default headers

        If the 'cors' option is True, will set the 'Access-Control-Allow-Origin'
        header to '*'
        """
        if getattr(options, 'cors', False):
            # Allow requests from any origin, can implement white-list later
            self.set_header('Access-Control-Allow-Origin', '*')

    def options(self, *args, **kwargs):
        """Default OPTIONS response

        If the 'cors' option is True, will respond with an empty response and
        set the 'Access-Control-Allow-Headers' and
        'Access-Control-Allow-Methods' headers
        """
        if getattr(options, 'cors', False):
            self.set_header('Access-Control-Allow-Headers',
                            'Content-Type, Authorization, '
                            'Accept, X-Requested-With')
            self.set_header('Access-Control-Allow-Methods',
                            'OPTIONS, TRACE, GET, HEAD, POST, '
                            'PUT, PATCH, DELETE')

        self.finish()


class JsonHandler(RequestHandler):
    """Shared code for handling JSON requests"""
    def write_error(self, status_code, **kwargs):
        """Override `write_error` in order to output JSON errors

        :param status_code: the response's status code, e.g. 500
        """
        http_error = _get_http_error(kwargs)
        if http_error:
            self.finish(self._error_template(status_code,
                                             http_error.errors,
                                             http_error.source))
        else:
            source = kwargs.get('source', getattr(options, 'name', None))
            # Slightly annoyed that have to rely on the internal self._reason
            # to deal with unhandled exceptions. On the dev version of
            # tornado self._reason is always set, while in the current version
            # a reason kwarg is passed down from `send_error` but not set
            # on the instance.
            reason = kwargs.get('reason', self._reason)
            self.finish(self._error_template(status_code, reason, source))

    @classmethod
    def _error_template(cls, status_code, errors, source=None):
        """Construct JSON error response

        :param status_code: the http status code
        :param errors: string or list of error strings
        :param source: source of the error
        :returns: dictionary, e.g.
            {
                'status': 400,
                'errors': [
                    {
                        'source': 'accounts' ,
                        'message':'errormsg1'
                    },
                    {
                        'source': 'accounts',
                        'message':'errormsg2'
                    }
                ]
            }
        """
        # this handles unhandled exceptions
        if isinstance(errors, basestring):
            errors_out = {'errors': [{'message': errors}]}
        elif isinstance(errors, (list, tuple)):
            errors_out = {'errors': [{'message': e} for e in errors]}
        else:
            errors_out = errors
        errors_out['status'] = status_code

        for error in errors_out['errors']:
            if not error.get('source'):
                error['source'] = source

        logging.error(json.dumps(errors_out))
        return errors_out

    def get_json_body(self, required=None, validators=None):
        """Get JSON from the request body

        :param required: optionally provide a list of keys that should be
        in the JSON body (raises a 400 HTTPError if any are missing)
        :param validator: optionally provide a dictionary of items that should
        be in the body with a method that validates the item.
        The method must be synchronous and return a boolean, no exceptions.
        :raises: HTTPError
        """
        content_type = self.request.headers.get('Content-Type',
                                                'application/json')
        if 'application/json' not in content_type.split(';'):
            raise HTTPError(415, 'Content-Type should be application/json')
        if not self.request.body:
            error = 'Request body is empty'
            logging.warning(error)
            raise HTTPError(400, error)

        try:
            body = json.loads(self.request.body)
        except (ValueError, TypeError):
            error = 'Error parsing JSON'
            logging.warning(error)
            raise HTTPError(400, error)

        if required:
            _check_required(body, required)

        if validators:
            _validate(body, validators)

        return body


class AuthHandler(RequestHandler):
    UNAUTHENTICATED_ACCESS = "unauthenticated"
    READ_ACCESS = "r"
    WRITE_ACCESS = "w"
    READ_WRITE_ACCESS = "rw"

    # Default required access levels for handler methods.
    # Can be overridden by individual service handlers
    METHOD_ACCESS = {
        "GET": READ_ACCESS,
        "HEAD": READ_ACCESS,
        "POST": WRITE_ACCESS,
        "PATCH": WRITE_ACCESS,
        "PUT": WRITE_ACCESS,
        "DELETE": WRITE_ACCESS
    }

    def endpoint_access(self, method):
        """
        Determine access level needed for endpoint
        :param method: The request verb
        :return: String representing access type.
        """
        if method == 'OPTIONS':
            # The CORS pre-flight checks should not require authentication
            return self.UNAUTHENTICATED_ACCESS
        elif method not in self.METHOD_ACCESS:
            logging.error('Cannot determine access needed for %s method', method)
            raise HTTPError(500, 'Internal Server Error')

        return self.METHOD_ACCESS[method]

    @coroutine
    def verify_token(self, token, requested_access):
        """
        Check the token bearer is permitted to access the resource

        :param token: Access token
        :param requested_access: the access level the client has requested
        :returns: boolean
        """
        client = API(options.url_auth,
                     auth_username=options.service_id,
                     auth_password=options.client_secret,
                     ssl_options=ssl_server_options())
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json'}
        body = urllib.urlencode({'token': token, 'requested_access': requested_access})

        client.auth.verify.prepare_request(headers=headers, request_timeout=180)

        try:
            result = yield client.auth.verify.post(body=body)
        except tornado.httpclient.HTTPError as ex:
            # Must be converted to a tornado.web.HTTPError for the server
            # to handle it correctly
            logging.exception(ex.message)
            raise HTTPError(500, 'Internal Server Error')

        raise Return(result['has_access'])

    @coroutine
    def prepare(self):
        """If OAuth verification is required, validate provided token

        :raise: HTTPError if token does not have access
        """
        requested_access = self.endpoint_access(self.request.method)
        use_oauth = getattr(options, 'use_oauth', None)
        if use_oauth and requested_access is not self.UNAUTHENTICATED_ACCESS:
            token = self.request.headers.get('Authorization', '').split(' ')[-1]
            if token:
                has_access = yield self.verify_token(token, requested_access)
                if not has_access:
                    msg = "'{}' access not granted.".format(requested_access)
                    raise HTTPError(403, msg)
            else:
                msg = 'OAuth token not provided'
                raise HTTPError(401, msg)


class BaseHandler(AuthHandler, CorsHandler, JsonHandler):
    pass


def _check_required(body, keys):
    msg = 'Please provide a {}'
    errors = [msg.format(k) for k in keys if k not in body]

    if errors:
        raise HTTPError(400, errors)


def _validate(body, validators):
    msg = 'Invalid data element {}'
    errors = [msg.format(key) for key, func in validators.items()
              if not func(body.get(key))]

    if errors:
        raise HTTPError(400, errors)
