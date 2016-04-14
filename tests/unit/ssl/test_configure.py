# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
# 

import os
from textwrap import dedent
import logging
import ssl

from mock import Mock, patch

from koi.configure import (
    ssl_server_options, define_options, options,
    log_config, load_config, configure_syslog, SysLogHandler, make_server)


def test_ssl_options():
    server_opts = ssl_server_options()
    if hasattr(ssl, 'SSLContext'):
        assert isinstance(server_opts, ssl.SSLContext)
        assert server_opts.verify_mode == 0
    else:
        for name in ['ca_certs', 'keyfile', 'certfile']:
            assert os.path.isfile(server_opts[name])
        assert server_opts['cert_reqs'] == 0


@patch('koi.configure.open', create=True)
def test_define_options(mock_open):
    conf = """
    server = 'localhost'
    port = 8000
    version = '0.1.1'
    log_file_prefix = 'mylog'
    """
    file_handle = mock_open.return_value.__enter__.return_value
    file_handle.read = Mock(return_value=dedent(conf).strip())

    define_options(None)

    assert options.server == 'localhost'
    assert options.port == 8000
    assert options.version == '0.1.1'
    assert options.log_file_prefix == 'mylog'


@patch('koi.configure.logging')
@patch('koi.configure.options')
def test_log_config_logs_options(options, logging):
    options.as_dict.return_value = {"example_option": 'example_value'}

    # MUT
    log_config()

    assert options.as_dict.call_count == 1
    assert logging.info.call_count == 1


@patch('koi.configure.options')
def test_syslog_on(options):
    options.syslog_host = 'localhost'
    logger = logging.getLogger()
    logger.handlers = []
    configure_syslog()
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], SysLogHandler)


@patch('koi.configure.options')
def test_syslog_off(options):
    options.syslog_host = ''
    logger = logging.getLogger()
    logger.handlers = []
    configure_syslog()
    assert not logger.handlers


@patch('koi.configure.configure_syslog')
@patch('koi.configure.parse_command_line')
@patch('koi.configure.options')
@patch('koi.configure.define_options')
@patch('os.path.isfile')
def test_load_config_no_local_config(isfile,
                                     define_options,
                                     options,
                                     parse_command_line,
                                     configure_syslog):
    isfile.return_value = False

    # MUT
    load_config('.')
    assert define_options.call_count == 1
    assert options.run_parse_callbacks.call_count == 0
    options.parse_config_file.assert_not_called()
    parse_command_line.assert_called_once_with(final=True)


@patch('koi.configure.configure_syslog')
@patch('koi.configure.parse_command_line')
@patch('koi.configure.define_options')
@patch('koi.configure.options')
@patch('os.path.isfile')
def test_load_config_with_local_config(isfile, options, *args):
    isfile.return_value = True
    local_conf_file = './local.conf'

    # MUT
    load_config('.')
    options.parse_config_file.assert_called_once_with(local_conf_file,
                                                      final=False)


@patch('tornado.httpserver.HTTPServer')
@patch('koi.configure.options')
@patch('koi.configure.ssl_server_options')
@patch('koi.configure.load_config')
def test_make_server_use_ssl(load_config, ssl_server_options,
                             options, HTTPServer):
    ssl_server_options.return_value = {'': 'ssl'}
    options.use_ssl = True
    make_server(None, '.')
    assert load_config.call_count >= 1
    HTTPServer.assert_called_once_with(None, ssl_options={'': 'ssl'})


@patch('tornado.httpserver.HTTPServer')
@patch('koi.configure.options')
@patch('koi.configure.load_config')
def test_make_server_without_ssl(load_config, options, HTTPServer):
    options.use_ssl = False
    make_server(None, '.')
    assert load_config.call_count >= 1
    HTTPServer.assert_called_once_with(None)
