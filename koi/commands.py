# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
#

import logging
import os
import socket
import sys

import click
from chub.api import API
from tornado import httpclient
from tornado.options import options

from . import configure, keygen


@click.group()
def defaults():
    pass


@defaults.command(help='Load fixture data')
def load_data():
    logging.warn('load_data is not implemented')


@defaults.command()
@click.argument('email')
@click.argument('password')
@click.argument('organisation_id')
@click.option('--name', help='The service\'s name')
@click.option('--service_type', help='The service type')
@click.option('--accounts_url', help='URL for the accounts service')
@click.option('--location', help='The url including protocol and port (if required) of service')
@click.option('--config', help='The configuration directory')
def register_service(email, password, organisation_id, name=None,
                     service_type=None, accounts_url=None,
                     location=None, config=None):
    """Register a service with the accounts service

    \b
    EMAIL: a user's email
    PASSWORD: a user's password
    ORGANISATION_ID: ID of the service's parent organisation
    """
    accounts_url = accounts_url or getattr(options, 'url_accounts', None)
    name = name or getattr(options, 'name', None)
    service_type = service_type or getattr(options, 'service_type', None)
    location = location or ('https://localhost:' + str(getattr(options, 'port')))
    config = config or 'config'

    if not accounts_url:
        raise click.ClickException(click.style('accounts_url not defined',
                                               fg='red'))

    if not name:
        raise click.ClickException(click.style('service name not defined',
                                               fg='red'))

    if not service_type:
        raise click.ClickException(click.style('service type not defined',
                                               fg='red'))

    client = API(accounts_url, async=False, validate_cert=False)
    try:
        response = client.accounts.login.post(email=email, password=password)
        client.default_headers['Authorization'] = response.data['token']

        try:
            response = client.accounts.organisations[organisation_id].services.post(
                name=name, location=location, service_type=service_type)
            service_id = response['data']['id']
        except httpclient.HTTPError:
            response = client.accounts.services.get(organisation_id=organisation_id)
            services = [s for s in response['data'] if s['name'] == name]

            if services:
                service_id = services[0]['id']
            else:
                msg = ('Organisation {} does not '
                       'have a service named {}').format(organisation_id, name)
                raise click.ClickException(click.style(msg, fg='red'))

        response = client.accounts.services[service_id].secrets.get()
        client_secrets = response['data']
    except httpclient.HTTPError as exc:
        try:
            msg = exc.response.body
        except AttributeError:
            msg = exc.message
        raise click.ClickException(click.style(msg, fg='red'))
    except socket.error as exc:
        raise click.ClickException(click.style(exc.strerror, fg='red'))

    try:
        with open(os.path.join(config, 'local.conf'), 'r') as f:
            lines = [line for line in f.readlines()
                     if not (line.startswith('service_id') or line.startswith('client_secret'))]
    except IOError:
        lines = []

    lines.append('\nservice_id = "{}"\n'.format(service_id))
    if client_secrets:
        lines.append('client_secret = "{}"\n'.format(client_secrets[0]))
    with open(os.path.join(config, 'local.conf'), 'w') as f:
        f.writelines(lines)

    click.echo(click.style('\n{} service registered\n'.format(name),
                           fg='green'))


def _options():
    """Collect all command line options"""
    opts = sys.argv[1:]
    return [click.Option((v.split('=')[0],)) for v in opts
            if v[0] == '-' and v != '--help']


def run(func):
    """Execute the provided function if there are no subcommands"""

    @defaults.command(help='Run the service')
    @click.pass_context
    def runserver(ctx, *args, **kwargs):
        if (ctx.parent.invoked_subcommand and
                ctx.command.name != ctx.parent.invoked_subcommand):
            return

        # work around the fact that tornado's parse_command_line can't
        # cope with having subcommands / positional arguments.
        sys.argv = [sys.argv[0]] + [a for a in sys.argv if a[0] == '-']

        sys.exit(func())

    return runserver


def _is_command_file(filename):
    return filename.endswith('.py') and filename[:-3] != '__init__'


class Command(click.MultiCommand):
    """A MultiCommand that extends the defaults click.Group with commands
    in a service.

    :param main: the main function to run the service. This function will
                 be called if the CLI is not provided with any subcommands
                 (e.g. `python accounts`).

    :param conf_dir: path to the service's tornado configuration directory

    :param commands_dir: path to the commands directory. Python modules within
                         the module will be attached to this CLI as a subcommand.
                         Each module needs to have a `cli` variable in it's
                         namespace which is a click.Command, click.Group or
                         click.MultiCommand instance.
    """

    def __init__(self, main, conf_dir=None, commands_dir=None, **kwargs):
        self._commands_dir = commands_dir
        if conf_dir:
            configure.load_config_file(conf_dir)

        # This is a bit of a hack, but need to register all parameters from
        # the command line because want to allow tornado to handle them and
        # click doesn't contain an equivalent of the `allow_extra_args`
        # keyword argument that works for options.
        # TODO: don't use tornado command line parsing
        params = _options()

        super(Command, self).__init__(self,
                                      params=params,
                                      callback=run(main),
                                      invoke_without_command=True,
                                      **kwargs)

    def list_commands(self, ctx):
        """List commands from the commands dir and default group"""
        rv = defaults.list_commands(ctx)
        if self._commands_dir:
            for filename in os.listdir(self._commands_dir):
                if _is_command_file(filename) and filename[:-3] not in rv:
                    rv.append(filename[:-3])
            rv.sort()
        return rv

    def get_command(self, ctx, name):
        """Get the command from either the commands dir or default group"""
        if not self._commands_dir:
            return defaults.get_command(ctx, name)

        ns = {}
        fn = os.path.join(self._commands_dir, name + '.py')

        try:
            with open(fn) as f:
                code = compile(f.read(), fn, 'exec')
        except IOError:
            return defaults.get_command(ctx, name)

        eval(code, ns, ns)

        CLI = 'cli'

        try:
            return ns[CLI]
        except KeyError:
            ctx.fail('`{}` not defined in "{}"'.format(CLI, name))


@defaults.command()
@click.argument('name')
@click.option('--dest', help='The directory to put the cert and key in', default='certs')
def create_dev_cert(name, dest):
    """
    A command to generate a self signed certificate for dev purposes.
    :param name: name ro be given to the cert and key
    :param dest: location on local filesystem to store the generated files
    :return:
    """
    if not os.path.exists(dest):
        os.makedirs(dest)
    keygen.gen_ca_cert(name, dest, 3650)


def cli(main, conf_dir=None, commands_dir=None):
    """Convenience function for initialising a Command CLI

    For parameter definitions see :class:`.Command`
    """
    return Command(main, conf_dir=conf_dir, commands_dir=commands_dir)()
