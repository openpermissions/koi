# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

from tornado.options import options
from tornado.web import HTTPError as _HTTPError


class HTTPError(_HTTPError):
    """Subclass of tornado.web.HTTPError.

    Raise a HTTPError to respond to a request with an error. The
    base.BaseHandler will use the information in the exception to form a
    JSON response in our standard error format.

    :param status_code: The status code that should be used in the HTTP response
    :param errors: Error messages
    :param kwargs: optionally include a source of the error (defaults to the
        service's name)
    """
    def __init__(self, status_code, errors, **kwargs):

        super(HTTPError, self).__init__(status_code)
        self.source = kwargs.get('source', getattr(options, 'name', None))
        self.errors = errors
