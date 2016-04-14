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

import pytest
from mock import Mock, patch
from tornado.web import Application
from tornado import testing

from koi import base
from koi.exceptions import HTTPError
from koi.auth import auth_required, authorized, _get_token
from ..util import return_fake_future


def test_get_token():
    request = Mock()
    request.headers = {
        'Authorization': 'token12345'
    }
    result = _get_token(request)
    assert result == 'token12345'


def test_get_token_no_token():
    request = Mock()
    request.headers = {}
    with pytest.raises(HTTPError):
        _get_token(request)


class _AuthenticateBase(object):
    def assert_status_code(self, expected, response):
        msg = 'Expected {} status code, got {}'.format(expected,
                                                       response.code)
        self.assertEqual(expected, response.code, msg)

    def assert_json_error(self, response):
        result = json.loads(response.body)
        self.assertIn('errors', result)

    def get_app(self):
        return Application([('/', self.Handler)])

    def test_get_decorated_method_with_token(self):
        """Test decorated GET method when there is an auth token"""

        self.is_valid = True
        test_token = 'token'

        response = self.fetch('/', headers={'Authorization': test_token})

        self.assert_status_code(200, response)
        assert self.get_method.called

    @patch('koi.auth.logging')
    def test_get_decorated_method_with_invalid_token(self, logging):
        """Test decorated GET method when there is an auth invalid token"""
        test_token = 'token'
        self.is_valid = False

        response = self.fetch('/', headers={'Authorization': test_token})

        self.assert_status_code(401, response)
        self.assert_json_error(response)
        assert logging.warning.call_count == 1
        assert not self.get_method.called

    @patch('koi.auth.logging')
    def test_decorated_method_without_token(self, logging):
        """Test the decorated method when there is not an auth token"""
        response = self.fetch('/')

        self.assert_status_code(401, response)
        self.assert_json_error(response)
        assert logging.warning.call_count == 1
        assert not self.get_method.called


class TestAuthenticateMethodDecorator(_AuthenticateBase, testing.AsyncHTTPTestCase):
    def setUp(self):
        self.get_method = Mock(return_value=None)
        self.get_method.__name__ = 'get'

        class Handler(base.BaseHandler):
            pass

        @return_fake_future
        def fake_validator(token):
            return self.is_valid

        setattr(Handler, 'get', auth_required(fake_validator)(self.get_method))
        self.Handler = Handler

        super(TestAuthenticateMethodDecorator, self).setUp()


class TestAuthenticateClassDecorator(_AuthenticateBase, testing.AsyncHTTPTestCase):
    def setUp(self):
        self.get_method = Mock(return_value=None)
        self.get_method.__name__ = 'get'

        class Handler(base.BaseHandler):
            def not_a_http_verb(self):
                pass

        @return_fake_future
        def fake_validator(token):
            return self.is_valid

        setattr(Handler, 'get', self.get_method)
        self.Handler = auth_required(fake_validator)(Handler)

        super(TestAuthenticateClassDecorator, self).setUp()

    def test_only_http_verbs_decorated(self):
        request = Mock()
        handler = self.Handler(self.get_app(), request)

        handler.not_a_http_verb()

        assert not request.called


class TestAsyncAuthenticateMethodDecorator(_AuthenticateBase, testing.AsyncHTTPTestCase):
    def setUp(self):
        self.get_method = Mock()

        @return_fake_future
        def fake_coroutine(self):
            return None

        self.get_method.side_effect = fake_coroutine
        self.get_method.__name__ = 'get'

        class Handler(base.BaseHandler):
            pass

        @return_fake_future
        def fake_validator(token):
            return self.is_valid

        setattr(Handler, 'get', auth_required(fake_validator)(self.get_method))
        self.Handler = Handler

        super(TestAsyncAuthenticateMethodDecorator, self).setUp()


class TestAsyncWrongDecoratorOrder(testing.AsyncHTTPTestCase):
    def setUp(self):
        self.get_method = Mock()

        @return_fake_future
        def fake_validator(token):
            return self.is_valid

        @return_fake_future
        @auth_required(fake_validator)
        def fake_coroutine(self):
            return None

        self.get_method.side_effect = fake_coroutine
        self.get_method.__name__ = 'get'

        class Handler(base.BaseHandler):
            pass

        setattr(Handler, 'get', self.get_method)
        self.Handler = Handler

        super(TestAsyncWrongDecoratorOrder, self).setUp()

    def get_app(self):
        return Application([('/', self.Handler)])

    def assert_status_code(self, expected, response):
        msg = 'Expected {} status code, got {}'.format(expected,
                                                       response.code)
        self.assertEqual(expected, response.code, msg)

    def test_get_decorated_method_with_token(self):
        """Test decorated GET method when there is an auth token"""

        self.is_valid = True
        test_token = 'token'

        response = self.fetch('/', headers={'Authorization': test_token})

        self.assert_status_code(500, response)
        assert self.get_method.called


class _AuthorizeBase(_AuthenticateBase):
    @patch('koi.auth.logging')
    def test_get_decorated_method_with_invalid_token(self, logging):
        """Test decorated GET method when there is invalid authorization"""
        test_token = 'token'
        self.is_valid = False

        response = self.fetch('/', headers={'Authorization': test_token})

        self.assert_status_code(403, response)
        self.assert_json_error(response)
        assert logging.warning.call_count == 1
        assert not self.get_method.called


class TestAuthorizeMethodDecorator(_AuthorizeBase, testing.AsyncHTTPTestCase):
    def setUp(self):
        self.get_method = Mock(return_value=None)
        self.get_method.__name__ = 'get'

        class Handler(base.BaseHandler):
            pass

        @return_fake_future
        def fake_validator(token):
            return self.is_valid

        setattr(Handler, 'get', authorized(fake_validator)(self.get_method))
        self.Handler = Handler

        super(TestAuthorizeMethodDecorator, self).setUp()


class TestAsyncAuthorizeMethodDecorator(_AuthorizeBase, testing.AsyncHTTPTestCase):
    def setUp(self):
        self.get_method = Mock()

        @return_fake_future
        def fake_coroutine(self):
            return None

        self.get_method.side_effect = fake_coroutine
        self.get_method.__name__ = 'get'

        class Handler(base.BaseHandler):
            pass

        @return_fake_future
        def fake_validator(token):
            return self.is_valid

        setattr(Handler, 'get', authorized(fake_validator)(self.get_method))
        self.Handler = Handler

        super(TestAsyncAuthorizeMethodDecorator, self).setUp()
