# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

"""Unit tests for utils"""
import re
from mock import patch, MagicMock

from tornado.web import RedirectHandler

from koi import utils
from koi.constants import PATH_PART


def test_tuplify():
    res = utils.tuplify("foo", *[1, 2, 3])
    expected = ("foo", 1, 2, 3)
    assert res == expected

    @utils.tuplify
    def do_numbers(num):
        for i in xrange(num):
            yield str(i)

    res = do_numbers(3)
    expected = ("0", "1", "2")
    assert res == expected


def test_listify():
    res = utils.listify("foo", *[1, 2, 3])
    expected = ["foo", 1, 2, 3]
    assert res == expected

    @utils.listify
    def do_numbers(num):
        for i in xrange(num):
            yield str(i)

    res = do_numbers(3)
    expected = ["0", "1", "2"]
    assert res == expected


def test_stringify():
    res = utils.stringify("foo", *[1, 2, 3])
    expected = "foo123"
    assert res == expected

    @utils.stringify
    def do_numbers(num):
        for i in xrange(num):
            yield str(i)

    res = do_numbers(3)
    expected = "012"
    assert res == expected


def test_add_prefix():
    data = [
        ("/foo", "handler", {"some": "kwarg"}),
        ("/bar", "handler"),
        ("/baz", "handler", {"another": "kwarg"}, "name")]
    res = utils.add_prefix(data, "/prefix")
    res = list(res)
    expected = [
        ("/prefix/foo", "handler", {"some": "kwarg"}),
        ("/prefix/bar", "handler"),
        ("/prefix/baz", "handler", {"another": "kwarg"}, "name")]
    assert res == expected


def test_add_prefix_with_kwargs():
    data = [
        ("/foo", "handler", {"some": "kwarg"}),
        ("/bar", "handler"),
        ("/baz", "handler", {"another": "kwarg"}, "name")]
    res = utils.add_prefix(data, "/prefix", {"some": "value"})
    res = list(res)
    expected = [
        ("/prefix/foo", "handler", {"some": "kwarg"}),
        ("/prefix/bar", "handler", {"some": "value"}),
        ("/prefix/baz", "handler",
         {"another": "kwarg", "some": "value"}, "name")]
    assert res == expected


def test_add_path_part():
    data = "/foo/{bar}/baz"
    result = utils.add_path_part(data)
    assert re.match(result, '/foo/xyz/baz')
    assert re.match(result, '/foo/x-y-z/baz')


def test_make_endpoints():
    foo = lambda x: x
    endpoints = [
        (r"", foo),
        (r"/authenticate", foo),
        (r"/organisations/{org_id}/assets", foo),
    ]

    res = utils.make_endpoints("x.y", "bar", endpoints)
    expected = [
        ("/", RedirectHandler, {'url': "/vx/bar"}),
        ("/vx/bar", foo),
        ("/vx/bar/authenticate", foo),
        (r"/vx/bar/organisations/(?P<org_id>{})/assets".format(PATH_PART), foo)
    ]
    assert res == expected


def test_make_endpoints_with_kwargs():
    foo = lambda x: x
    endpoints = [
        (r"", foo),
        (r"/authenticate", foo),
        (r"/organisations/{org_id}/assets", foo),
    ]

    res = utils.make_endpoints("x.y", "bar", endpoints, kwargs={'foo': 'bar'})
    expected = [
        ("/", RedirectHandler, {'url': "/vx/bar"}),
        ("/vx/bar", foo, {'foo': 'bar'}),
        ("/vx/bar/authenticate", foo, {'foo': 'bar'}),
        (r"/vx/bar/organisations/(?P<org_id>{})/assets".format(PATH_PART), foo, {'foo': 'bar'})
    ]
    assert res == expected


@patch('koi.utils.options')
def test_sanitise_capabilites(options):
    options.service_id = 'service123'
    capabilities = {
        'foo': 'bar',
        'client_secret': 'secret123'
    }
    result = utils.sanitise_capabilities(capabilities)
    assert sorted(result.keys()) == ['foo', 'service_id']


@patch('koi.utils.options')
def test_sanitise_capabilites_no_secret(options):
    options.service_id = 'service123'
    capabilities = {
        'foo': 'bar',
    }
    result = utils.sanitise_capabilities(capabilities)
    assert sorted(result.keys()) == ['foo', 'service_id']


@patch('koi.utils.options')
def test_sanitise_capabilites_empty(options):
    options.service_id = 'service123'
    capabilities = {}
    result = utils.sanitise_capabilities(capabilities)
    assert result.keys() == ['service_id']
