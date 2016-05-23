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
Configure ssl server and client
"""
from datetime import datetime
import hashlib
import logging
from logging.handlers import SysLogHandler
import os
import socket
import ssl
import time

import sys
import tornado.httpserver
from tornado.options import define, options, parse_command_line
from tornado.util import exec_in
from tornado.escape import native_str
from tornado.web import RequestHandler

from .keygen import DEFAULT_CERTS_DIR
from .utils import make_endpoints

general_logger = logging.getLogger('tornado.general')


def _default_certs_path(name):
    """
    prefix with the path to the certs directory
    """
    return os.path.join(DEFAULT_CERTS_DIR, name)


define('ssl_ca_cert', default=_default_certs_path('CA.crt'))
define('ssl_key', default=_default_certs_path('localhost.key'))
define('ssl_cert', default=_default_certs_path('localhost.crt'))
define('ssl_cert_reqs', default=0)
define('syslog_host', default='')
define('syslog_port', default=514)


def define_options(default_conf):
    """
    Define the options from default.conf dynamically
    """
    default = {}
    with open(default_conf, 'rb') as f:
        exec_in(native_str(f.read()), {}, default)

    for name, value in default.iteritems():
        # if the option is already defined by tornado
        # override the value
        # a list of options set by tornado:
        # log_file_num_backups, logging, help,
        # log_to_stderr, log_file_max_size, log_file_prefix
        if name in options:
            setattr(options, name, value)
        # otherwise define the option
        else:
            define(name, value)


def log_config():
    """Logs the config used to start the application"""
    conf = '\n'.join(
            ['{}="{}"'.format(k, v) for k, v
             in sorted(options.as_dict().iteritems())])
    logging.info('Service started with the following settings:\n' + conf)


def ssl_server_options():
    """
    ssl options for tornado https server
    these options are defined in each application's default.conf file
    if left empty, use the self generated keys and certificates included
    in this package.
    this function is backward compatible with python version lower than
    2.7.9 where ssl.SSLContext is not available.
    """
    cafile = options.ssl_ca_cert
    keyfile = options.ssl_key
    certfile = options.ssl_cert
    verify_mode = options.ssl_cert_reqs
    try:
        context = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH, cafile=cafile)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        context.verify_mode = verify_mode
        return context
    except AttributeError:
        ssl_options = {
            'ca_certs': cafile,
            'keyfile': keyfile,
            'certfile': certfile,
            'cert_reqs': verify_mode
        }
        return ssl_options


class RequestFilter(logging.Filter):
    def __init__(self, request):
        self.request = request
        self.request_id = hashlib.md5(datetime.now().isoformat() +
                                      request.remote_ip).hexdigest()[:10]

    def filter(self, record):
        record.remote_ip = self.request.remote_ip
        record.request_id = self.request_id
        return True


def log_formatter(request=None):
    """
    Log formatter used in our syslog

    :param request: a request object
    :returns: logging.Formatter
    """

    if request:
        format_str = ('%(asctime)s {ip} {name}:  ENV={env} '
                      'REMOTE_IP=%(remote_ip)s REQUEST_ID=%(request_id)s '
                      '%(message)s')
    else:
        format_str = '%(asctime)s {ip} {name}:  ENV={env} %(message)s'

    try:
        hostname = socket.gethostname()
    except socket.gaierror:
        hostname = 'localhost'

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip = '127.0.0.1'

    formatter = logging.Formatter(
            format_str.format(ip=ip, name=options.name, env=options.env),
            datefmt='%Y-%m-%dT%H:%M:%S')
    logging.Formatter.converter = time.gmtime

    return formatter


def configure_syslog(request=None, logger=None, exceptions=False):
    """
    Configure syslog logging channel.
    It is turned on by setting `syslog_host` in the config file.
    The port default to 514 can be overridden by setting `syslog_port`.

    :param request: tornado.httputil.HTTPServerRequest instance
    :param exceptions: boolean - This indicates if we should raise
        exceptions encountered in the logging system.
    """
    syslog_host = getattr(options, 'syslog_host', None)
    if not syslog_host:
        return

    sys.modules["logging"].raiseExceptions = exceptions
    handler = SysLogHandler(address=(syslog_host, options.syslog_port))
    formatter = log_formatter(request)
    handler.setFormatter(formatter)

    if request:
        handler.addFilter(RequestFilter(request))

    if logger:
        logger.addHandler(handler)
    else:
        logging.getLogger().addHandler(handler)


def load_config_file(conf_dir):
    default_conf = os.path.join(conf_dir, 'default.conf')
    define_options(default_conf)
    local_conf = os.path.join(conf_dir, 'local.conf')
    if os.path.isfile(local_conf):
        options.parse_config_file(local_conf, final=False)


def load_config(conf_dir):
    """
    Use default.conf as the definition of options with default values
    using tornado.options.define.
    Then overrides the values from: local.conf.
    This mapping allows to access the application configuration across the
    application.

    :param conf_dir: path to configuration directory
    """
    load_config_file(conf_dir)
    # NOTE:
    # logging before this line is not going to work
    parse_command_line(final=True)


class ErrorHandler(RequestHandler):
    def prepare(self):
        self.set_status(404)
        self.finish({'status': 404, 'errors': [{'message': 'Not Found'}]})


def make_application(version, app_name, app_urls, kwargs=None):
    """
    Loads the routes and starts the server

    :param version: the application version
    :param app_name: the application name
    :param app_urls: a list of application endpoints
    :param kwargs: dictionary of options
    :returns: tornado.web.Application instance
    """
    if kwargs is None:
        kwargs = {}

    urls = make_endpoints(version, app_name, app_urls, kwargs)
    application = tornado.web.Application(
            urls,
            default_handler_class=kwargs.get('default_handler_class', ErrorHandler))

    return application


def make_server(application, conf_dir=None):
    """
    Configure the server return the server instance
    """
    if conf_dir:
        load_config(conf_dir)
    configure_syslog()
    log_config()
    if options.use_ssl:
        ssl_options = ssl_server_options()
        server = tornado.httpserver.HTTPServer(
                application, ssl_options=ssl_options)
        general_logger.info(
                'start tornado https server at https://%s:%s'
                ' with ssl_options: %s', options.ip, options.port, ssl_options)
    else:

        server = tornado.httpserver.HTTPServer(application)
        general_logger.info('start tornado http server at http://{0}:{1}'.format(
                options.ip, options.port))

    server.bind(options.port, options.ip)
    return server
