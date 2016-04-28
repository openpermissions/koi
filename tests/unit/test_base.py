# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

from functools import partial
import json
import logging

from mock import MagicMock, Mock, patch, call
import pytest
from tornado import testing
from tornado.ioloop import IOLoop
from tornado.web import Application
import tornado.httpclient

from koi import base
from koi.test_helpers import make_future, gen_test
from koi.exceptions import HTTPError


def setup_module(module):
    """Patch options and disable logging ounotput"""
    base_options = patch('koi.base.options').start()
    exc_options = patch('koi.exceptions.options').start()
    base_options.name = 'accounts'
    exc_options.name = 'accounts'
    base.options.use_oauth = False
    base_options.cors = False
    logging.disable(logging.CRITICAL)


def teardown_module(module):
    """Stop patches and enable logging output"""
    patch.stopall()
    logging.disable(logging.NOTSET)


def mock_handler(handler_class):
    handler = handler_class(MagicMock(), MagicMock())
    handler.METHOD_ACCESS = {
        "GET": "r",
        "HEAD": "r",
        "OPTIONS": "r",
        "POST": "w",
        "PATCH": "w",
        "PUT": "w",
        "DELETE": "w"
    }
    handler.finish = MagicMock()
    handler.set_header = MagicMock()

    return handler


class TestErrorHandling(testing.AsyncHTTPTestCase):
    def setUp(self):
        self.error = None

        def raise_error(x):
            self.error(x)

        self.raise_error = raise_error
        super(TestErrorHandling, self).setUp()

    def get_app(self):
        raise_error = self.raise_error

        class Handler(base.JsonHandler):
            post = raise_error

        return Application([('/', Handler)])

    def test_400_error_message(self):
        def error(x):
            raise base.HTTPError(400, 'this is an error')

        self.error = error
        response = self.fetch('/', method='POST', body='{"test": "value"}',
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(response.code, 400)
        expected_body = {
            u'status': 400,
            u'errors': [
                {
                    u'message': u'this is an error',
                    u'source': u'accounts'
                }
            ]
        }
        self.assertEqual(json.loads(response.body), expected_body)
        self.assertEqual(response.headers['Content-Type'],
                         'application/json; charset=UTF-8')

    def test_500_error_message(self):
        def error(x):
            raise base.HTTPError(500, 'this is an error')

        self.error = error
        response = self.fetch('/', method='POST', body='{"test": "value"}',
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(response.code, 500)
        expected_body = {
            u'status': 500,
            u'errors': [
                {u'message': u'this is an error', u'source': u'accounts'}
            ]
        }
        self.assertEqual(json.loads(response.body), expected_body)
        self.assertEqual(response.headers['Content-Type'],
                         'application/json; charset=UTF-8')

    def test_multiple_error_messages(self):
        def error(x):
            raise base.HTTPError(400, ['this is an error', 'another error'])

        self.error = error
        response = self.fetch('/', method='POST', body='{"test": "value"}',
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(response.code, 400)
        expected_body = {
            u'status': 400,
            u'errors': [
                {u'message': u'this is an error', u'source': u'accounts'},
                {u'message': u'another error', u'source': u'accounts'}
            ]
        }
        self.assertEqual(json.loads(response.body), expected_body)
        self.assertEqual(response.headers['Content-Type'],
                         'application/json; charset=UTF-8')

    def test_unhandled_exception(self):
        def error(x):
            raise ValueError('Wrong value')

        self.error = error
        response = self.fetch('/', method='POST', body='{"test": "value"}',
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(response.code, 500)
        expected_body = {
            u'status': 500,
            u'errors': [
                {u'message': u'Internal Server Error', u'source': u'accounts'}
            ]
        }
        self.assertEqual(json.loads(response.body), expected_body)
        self.assertEqual(response.headers['Content-Type'],
                         'application/json; charset=UTF-8')

    def test_send_error(self):
        def error(x):
            x.send_error(400, reason='test')

        self.error = error
        response = self.fetch('/', method='POST', body='{"test": "value"}',
                              headers={'Content-Type': 'application/json'})
        self.assertEqual(response.code, 400)
        expected_body = {
            u'status': 400,
            u'errors': [
                {u'message': u'test', u'source': u'accounts'}
            ]
        }
        self.assertEqual(json.loads(response.body), expected_body)
        self.assertEqual(response.headers['Content-Type'],
                         'application/json; charset=UTF-8')


def test_http_error():
    data = {'test': 'value'}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}


def test_get_valid_json_body():
    data = {'test': 'value'}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}

    result = handler.get_json_body()

    assert result == data


def test_get_missing_json_body():
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.headers = {'Content-Type': 'application/json'}

    with pytest.raises(base.HTTPError) as exc:
        handler.get_json_body()

    assert exc.value.status_code == 400
    assert exc.value.errors == 'Error parsing JSON'


def test_get_empty_json_body():
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = ''
    handler.request.headers = {'Content-Type': 'application/json'}

    with pytest.raises(base.HTTPError) as exc:
        handler.get_json_body()

    assert exc.value.status_code == 400
    assert exc.value.errors == 'Request body is empty'


def test_get_invalid_json_body():
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = 'this is not JSON'
    handler.request.headers = {'Content-Type': 'application/json'}

    with pytest.raises(base.HTTPError) as exc:
        handler.get_json_body()

    assert exc.value.status_code == 400
    assert exc.value.errors == 'Error parsing JSON'


def test_get_json_wrong_content_type():
    handler = base.JsonHandler(MagicMock(), MagicMock())
    data = {'test': 'value'}
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/jsonatoehus'}

    with pytest.raises(base.HTTPError) as exc:
        handler.get_json_body()

    assert exc.value.status_code == 415
    assert exc.value.errors == 'Content-Type should be application/json'


def test_get_json_body_with_required_keys():
    data = {'test': 'value', 'a': 1, 'b': 2}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}

    result = handler.get_json_body(required=['a', 'b'])

    assert result == data


def test_get_json_body_missing_required_keys():
    data = {'test': 'value'}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}

    with pytest.raises(base.HTTPError) as exc:
        handler.get_json_body(required=['a', 'b'])

    assert exc.value.status_code == 400
    assert len(exc.value.errors) == 2


def test_get_json_body_with_valid_keys():
    data = {'test': 'value', 'a': 1, 'b': 2}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}

    def an_int(x):
        return isinstance(x, int)

    result = handler.get_json_body(validators={'a': an_int, 'b': an_int})

    assert result == data


def test_get_json_body_with_valid_optional_keys():
    data = {'test': 'value', 'a': 1}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}

    def an_optional_int(x):
        return not x or isinstance(x, int)

    result = handler.get_json_body(validators={'a': an_optional_int, 'b': an_optional_int})

    assert result == data


def test_get_json_body_with_invalid_keys():
    data = {'test': 'value', 'a': 1, 'b': 2}
    handler = base.JsonHandler(MagicMock(), MagicMock())
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json'}

    def a_string(x):
        return isinstance(x, basestring)

    with pytest.raises(base.HTTPError) as exc:
        result = handler.get_json_body(validators={'a': a_string, 'b': a_string})

    assert exc.value.status_code == 400
    assert len(exc.value.errors) == 2


def test_get_json_charset_in_content_type():
    handler = base.JsonHandler(MagicMock(), MagicMock())
    data = {'test': 'value'}
    handler.request.body = json.dumps(data)
    handler.request.headers = {'Content-Type': 'application/json; charset=UTF-8'}

    result = handler.get_json_body()

    assert result == data


def test_missing_content_type():
    """If content type is not set, then should default to application/json"""
    handler = base.JsonHandler(MagicMock(), MagicMock())
    data = {'test': 'value'}
    handler.request.body = json.dumps(data)
    handler.request.headers = {}

    result = handler.get_json_body()

    assert result == data


@patch('koi.base.options')
def test_cors_enabled_preflight_request(options):
    """Test CORS headers set correctly for preflight requests"""
    options.cors = True
    handler = mock_handler(base.CorsHandler)

    # MUT
    handler.options()

    assert handler.finish.call_count == 1
    assert handler.set_header.call_args_list == [
        call('Access-Control-Allow-Headers',
             'Content-Type, Authorization, Accept, X-Requested-With'),
        call('Access-Control-Allow-Methods',
             'OPTIONS, TRACE, GET, HEAD, POST, PUT, PATCH, DELETE')
    ]


def test_cors_disabled_preflight_request():
    """Test CORS headers set correctly for preflight requests"""
    handler = mock_handler(base.CorsHandler)

    # MUT
    handler.options()
    assert handler.finish.call_count == 1
    assert not handler.set_header.called


@patch('koi.base.options')
def test_cors_enabled_default_headers(options):
    """Test CORS headers set in default headers if options.cors = True"""
    options.cors = True
    handler = mock_handler(base.CorsHandler)

    # MUT
    handler.set_default_headers()
    assert handler.set_header.call_args_list == [
        call('Access-Control-Allow-Origin', '*')
    ]


def test_cors_disabled_default_headers():
    """Test CORS headers not set in default headers if options.cors = False"""
    handler = mock_handler(base.CorsHandler)

    # MUT
    handler.set_default_headers()
    assert not handler.set_header.called


access_levels = [
    ("GET", "r"),
    ("POST", "w"),
    ("PUT", "rw"),
    ("OPTIONS", "unauthenticated"),
]


@pytest.mark.parametrize('method, expected', access_levels)
def test_endpoint_access(method, expected):
    handler = mock_handler(base.AuthHandler)
    handler.METHOD_ACCESS = {
        "GET": "r",
        "HEAD": "r",
        "POST": "w",
        "PATCH": "rw",
        "PUT": "rw",
        "DELETE": "w"
    }
    func = partial(handler.endpoint_access, method)
    result = IOLoop.instance().run_sync(func)
    assert result == expected


def test_endpoint_access_no_match():
    handler = mock_handler(base.AuthHandler)
    handler.METHOD_ACCESS = {
        "GET": "r",
        "HEAD": "r",
        "POST": "w",
        "PUT": "rw",
        "DELETE": "w"
    }

    func = partial(handler.endpoint_access, "PATCH")
    with pytest.raises(base.HTTPError) as exc:
        IOLoop.instance().run_sync(func)

    assert exc.value.status_code == 500


@patch('koi.base.options')
@patch('koi.base.API')
@gen_test
def test_verify_token_valid(API, options):
    options.service_id = 'serviceid'
    options.client_secret = 'clientsecret'

    handler = mock_handler(base.AuthHandler)

    client = Mock()
    API.return_value = client
    client.auth.verify.post.return_value = make_future({'status': 200, 'has_access': True})

    result = yield handler.verify_token('token1234', 'r')

    assert result is True
    API.assert_called_once_with(options.url_auth,
                                auth_username='serviceid',
                                auth_password='clientsecret',
                                ca_certs=options.ssl_ca_cert)
    assert client.auth.verify.prepare_request.call_count == 1
    client.auth.verify.post.assert_called_once_with(
        body='requested_access=r&token=token1234'
    )


@patch('koi.base.options')
@patch('koi.base.API')
@gen_test
def test_verify_token_invalid(API, options):
    options.service_id = 'serviceid'
    options.client_secret = 'clientsecret'
    handler = mock_handler(base.AuthHandler)

    client = Mock()
    API.return_value = client
    client.auth.verify.post.return_value = make_future({'status': 200, 'has_access': False})

    result = yield handler.verify_token('token1234', 'r')

    assert result is False
    API.assert_called_once_with(options.url_auth,
                                auth_username='serviceid',
                                auth_password='clientsecret',
                                ca_certs=options.ssl_ca_cert)
    assert client.auth.verify.prepare_request.call_count == 1
    client.auth.verify.post.assert_called_once_with(
        body='requested_access=r&token=token1234'
    )


@patch('koi.base.options')
@patch('koi.base.API')
@gen_test
def test_verify_token_raise_web_httperror(API, options):
    handler = mock_handler(base.AuthHandler)
    client = Mock()
    API.return_value = client
    client.auth.verify.post.side_effect = tornado.httpclient.HTTPError(401)

    with pytest.raises(HTTPError) as exc:
        yield handler.verify_token('token1234', 'r')
    assert exc.value.status_code == 500


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_oauth_required_valid(verify_token, options):
    verify_token.return_value = make_future(True)
    options.use_oauth = True
    handler = mock_handler(base.AuthHandler)
    handler.request.method = 'GET'
    handler.request.headers = {'Authorization': 'Bearer token1234'}

    IOLoop.instance().run_sync(handler.prepare)

    verify_token.assert_called_once_with('token1234', 'r')


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_oauth_required_missing_bearer(verify_token, options):
    verify_token.return_value = make_future(True)
    options.use_oauth = True
    handler = mock_handler(base.AuthHandler)
    handler.request.method = 'GET'
    handler.request.headers = {'Authorization': 'token1234'}

    IOLoop.instance().run_sync(handler.prepare)

    verify_token.assert_called_once_with('token1234', 'r')


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_oauth_required_invalid(verify_token, options):
    verify_token.return_value = make_future(False)
    options.use_oauth = True
    handler = mock_handler(base.AuthHandler)
    handler.request.method = 'GET'
    handler.request.headers = {'Authorization': 'Bearer token1234'}

    with pytest.raises(base.HTTPError) as exc:
        IOLoop.instance().run_sync(handler.prepare)

    verify_token.assert_called_once_with('token1234', 'r')
    assert exc.value.status_code == 403


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_oauth_required_missing_header(verify_token, options):
    options.use_oauth = True
    handler = mock_handler(base.AuthHandler)
    handler.request.method = 'GET'
    handler.request.headers = {}

    with pytest.raises(base.HTTPError) as exc:
        IOLoop.instance().run_sync(handler.prepare)
    assert exc.value.status_code == 401
    assert not verify_token.called


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_oauth_required_unauthenticated_endpoint(verify_token, options):
    options.use_oauth = True
    handler = mock_handler(base.AuthHandler)
    handler.METHOD_ACCESS = {
        'GET': handler.UNAUTHENTICATED_ACCESS
    }
    handler.request.method = 'GET'

    IOLoop.instance().run_sync(handler.prepare)

    assert not verify_token.called


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_oauth_not_required(verify_token, options):
    options.use_oauth = False
    handler = mock_handler(base.AuthHandler)
    handler.request.method = 'GET'

    IOLoop.instance().run_sync(handler.prepare)

    assert not verify_token.called


@patch('koi.base.options')
@patch('koi.base.AuthHandler.verify_token')
def test_prepare_invalid_access(verify_token, options):
    handler = mock_handler(base.AuthHandler)
    handler.METHOD_ACCESS = {
        "HEAD": "r",
        "OPTIONS": "r",
        "POST": "w",
        "PATCH": "w",
        "PUT": "w",
        "DELETE": "w"
    }
    handler.request.method = 'GET'

    with pytest.raises(base.HTTPError) as exc:
        IOLoop.instance().run_sync(handler.prepare)

    assert exc.value.status_code == 500
    assert not verify_token.called


@patch('koi.base.logging')
def test_error_template_1error(logging_error):
    data = 'test'
    source = 'source'
    expected_body = {
        'status': 400,
        'errors': [
            {'message': data, 'source': source}
        ]
    }
    errors = base.JsonHandler._error_template(400, data, source=source)
    assert errors == expected_body
    assert logging_error.error.call_count == 1


@patch('koi.base.logging')
def test_error_template_2error(logging_error):
    source = 'source_example'
    data = ['test1', 'test2']
    expected_body = {
        'status': 401,
        'errors': [
            {'message': 'test1', 'source': source},
            {'message': 'test2', 'source': source}
        ]
    }
    errors = base.JsonHandler._error_template(401, data, source)
    assert errors == expected_body
    assert logging_error.error.call_count == 1


@patch('koi.base.logging')
def test_error_template_with_dict_with_source(logging_error):
    source = 'source_example'
    data = {
        'status': 402,
        'errors': [
            {'message': 'test1', 'source': source},
            {'message': 'test2', 'source': source}
        ]
    }
    errors = base.JsonHandler._error_template(402, data)
    assert errors == data
    assert logging_error.error.call_count == 1


@patch('koi.base.logging')
def test_error_template_with_dict_without_source(logging_error):
    data = {'errors': [{'message': 'test1'}, {'message': 'test2'}]}
    expected_body = {
        'status': 403,
        'errors': [
            {'message': 'test1', 'source': None},
            {'message': 'test2', 'source': None}
        ]
    }
    errors = base.JsonHandler._error_template(403, data)
    assert errors == expected_body
    assert logging_error.error.call_count == 1


@patch('koi.base.logging')
def test_error_template_with_tuple(logging_error):
    source = 'source_example'
    data = ('test1', 'test2')
    expected_body = {
        'status': 401,
        'errors': [
            {'message': 'test1', 'source': source},
            {'message': 'test2', 'source': source}
        ]
    }
    errors = base.JsonHandler._error_template(401, data, source)
    assert errors == expected_body
    assert logging_error.error.call_count == 1
