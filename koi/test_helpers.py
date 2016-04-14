# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 


import functools

from tornado.ioloop import IOLoop
from tornado.gen import coroutine
from tornado.concurrent import Future


def gen_test(func):
    """
    Helper for running async tests, based on the tornado.testing.gen_test
    decorator.
    It wraps the test function with tornado.gen.coroutine and initialises an
    IOLoop to run the async code using IOLoop.run_sync
    NOTE: if using this with the mock.patch decorator apply gen_test first,
    otherwise the patches won't work.
    ANOTHER NOTE: if you don't yield when calling coroutines in your test you
    can get false positives, just like any other place where you don't call
    coroutines correctly. It's always a good idea to see your test fail so
    you know it's testing something.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        cofunc = coroutine(func)
        io_loop = IOLoop.current()

        try:
            result = io_loop.run_sync(functools.partial(cofunc, *args, **kwargs))
            return result

        finally:
            io_loop.clear_current()
            if not IOLoop.initialized() or io_loop is not IOLoop.instance():
                io_loop.close(all_fds=True)


    return wrapper

def make_future(result):
    """Create a `tornado.concurrent.Future` that returns `result`

    Useful for adding a return value to a mocked coroutine, for example::

        mock = Mock()
        mock.func.return_value = test_helpers.make_future('test')
        result = IOLoop.instance().run_sync(mock.func)

        assert result == 'test'

    :param result: the Future's result
    :returns: tornado.concurrent.Future
    """
    f = Future()
    f.set_result(result)

    return f
