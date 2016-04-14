# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

"""
Provides a auth_required decorator to check a request is authenticated,
and an authorised decorator to check a request is authorised
"""
import functools
import inspect
import logging

from tornado import gen
from tornado.concurrent import Future

from .exceptions import HTTPError


def auth_required(validator):
    """Decorate a RequestHandler or method to require that a request is authenticated

    If decorating a coroutine make sure coroutine decorator is first.
    eg.::

        class Handler(tornado.web.RequestHandler):

            @auth_required(validator)
            @coroutine
            def get(self):
                pass

    :param validator: a coroutine that will validate the token and return True/False
    """
    def _auth_decorator(handler):
        if inspect.isclass(handler):
            return _wrap_class(handler, validator)
        return _auth_required(handler, validator)

    return _auth_decorator


def _wrap_class(request_handler, validator):
    """Decorate each HTTP verb method to check if the request is authenticated

    :param request_handler: a tornado.web.RequestHandler instance
    """
    METHODS = ['get', 'post', 'put', 'head', 'options', 'delete', 'patch']
    for name in METHODS:
        method = getattr(request_handler, name)
        setattr(request_handler, name, _auth_required(method, validator))

    return request_handler


def _get_token(request):
    """
    Gets authentication token from request header
    Will raise 401 error if token not found
    :return token: an authorization token.
    """
    token = request.headers.get('Authorization')
    if not token:
        message = 'Token not in Authorization header'
        logging.warning(message)
        raise HTTPError(401, message)
    return token


def _auth_required(method, validator):
    """Decorate a HTTP verb method and check the request is authenticated

    :param method: a tornado.web.RequestHandler method
    :param validator: a token validation coroutine, that should return
    True/False depending if token is or is not valid
    """
    @gen.coroutine
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        token = _get_token(self.request)
        valid_token = yield validator(token)
        if not valid_token:
            message = 'Invalid token: {}'.format(token)
            logging.warning(message)
            raise HTTPError(401, message)
        result = method(self, *args, **kwargs)

        if isinstance(result, Future):
            result = yield result

        raise gen.Return(result)

    return wrapper


def authorized(validator):
    """Decorate a RequestHandler or method to require that a request is authorized

    If decorating a coroutine make sure coroutine decorator is first.
    eg.::

        class Handler(tornado.web.RequestHandler):

            @authorized(validator)
            @coroutine
            def get(self):
                pass

    :param validator: a coroutine that will authorize the user associated with the token and return True/False
    """
    def _authorized_decorator(method):
        @gen.coroutine
        def wrapper(self, *args, **kwargs):
            token = _get_token(self.request)
            authorized = yield validator(token, **kwargs)
            if not authorized:
                message = 'Token is not authorised for this action: {}'.format(token)
                logging.warning(message)
                raise HTTPError(403, message)

            result = method(self, *args, **kwargs)

            if isinstance(result, Future):
                result = yield result

            raise gen.Return(result)

        return wrapper
    return _authorized_decorator
