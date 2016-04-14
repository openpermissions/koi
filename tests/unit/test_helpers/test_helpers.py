# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

from mock import Mock,patch
from tornado.ioloop import IOLoop

from koi import test_helpers


def test_make_future():
    future = test_helpers.make_future('test')
    assert future.result() == 'test'


def test_make_future_in_ioloop():
    mock = Mock()
    mock.func.return_value = test_helpers.make_future('test')
    result = IOLoop.instance().run_sync(mock.func)

    assert result == 'test'


def test_gen_test_respect_exec_yields():
    yield_passed = {}
    yield_passed['value'] = False

    @patch('koi.keygen.os')
    @test_helpers.gen_test
    def fake_test(patch):
        yield test_helpers.make_future('test')
        yield_passed['value'] = True
        assert(patch.listdir.call_count == 0)

    fake_test()

    assert yield_passed['value']



