# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

"""Useful utils."""
from functools import wraps
import string

from tornado.web import RedirectHandler
from tornado.options import options
from koi.constants import PATH_PART


def tuplify(*args):
    """
    Convert args to a tuple, unless there's one arg and it's a
    function, then acts a decorator.
    """
    if (len(args) == 1) and callable(args[0]):
        func = args[0]

        @wraps(func)
        def _inner(*args, **kwargs):
            return tuple(func(*args, **kwargs))
        return _inner
    else:
        return tuple(args)


def listify(*args):
    """
    Convert args to a list, unless there's one arg and it's a
    function, then acts a decorator.
    """
    if (len(args) == 1) and callable(args[0]):
        func = args[0]

        @wraps(func)
        def _inner(*args, **kwargs):
            return list(func(*args, **kwargs))
        return _inner
    else:
        return list(args)


def stringify(*args):
    """
    Joins args to build a string, unless there's one arg and it's a
    function, then acts a decorator.
    """
    if (len(args) == 1) and callable(args[0]):
        func = args[0]

        @wraps(func)
        def _inner(*args, **kwargs):
            return "".join([str(i) for i in func(*args, **kwargs)])
        return _inner
    else:
        return "".join([str(i) for i in args])


def add_prefix(endpoints, prefix, kwargs=None):
    for endpoint in endpoints:
        url = endpoint[0]
        url = add_path_part(url)
        if kwargs:
            k = kwargs.copy()
            if len(endpoint) >= 3:
                # assume that the kwargs in the endpoint should over-ride
                # the kwargs passed in as an argument
                k.update(endpoint[2])

            yield tuplify(prefix+url, endpoint[1], k, *endpoint[3:])
        else:
            yield tuplify(prefix+url, *endpoint[1:])


@stringify
def add_path_part(url, regex=PATH_PART):
    """
    replace the variables in a url template with regex named groups
    :param url: string of a url template
    :param regex: regex of the named group
    :returns: regex
    """
    formatter = string.Formatter()
    url_var_template = "(?P<{var_name}>{regex})"

    for part in formatter.parse(url):
        string_part, var_name, _, _ = part
        if string_part:
            yield string_part
        if var_name:
            yield url_var_template.format(var_name=var_name, regex=regex)


@listify
def make_endpoints(version, name, endpoints, kwargs=None):
    """
    Returns a redirect handler and all endpoints with a version prefix added.

    :param version: the application version
    :param name: the application name
    :param endpoints: a list of application endpoints
    :param kwargs: an optional dictionary to populate placeholders in endpoints
    :returns:list of endpoints
    """
    if kwargs is None:
        kwargs = {}

    version_url_prefix = '/v{}/{}'.format(version.split('.')[0], name)
    yield (r"/", RedirectHandler, {"url": r"{}".format(version_url_prefix)})
    for endpoint in add_prefix(endpoints, version_url_prefix, kwargs):
        yield endpoint


REQUIRED_CAPABILITIES = ['service_id']
PROTECTED_CAPABILITIES = ['client_secret']


def sanitise_capabilities(capabilities):
    """
    Makes sure dictionary of capabilities includes required options, and does not include protected ones.
    :param capabilities:
    :return: dict
    """
    for c in REQUIRED_CAPABILITIES:
        capabilities[c] = options[c]

    for c in PROTECTED_CAPABILITIES:
        if c in capabilities:
            del capabilities['client_secret']

    return capabilities
