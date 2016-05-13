# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
#
import click
from click.testing import CliRunner

from mock import MagicMock, patch, mock_open, call
import pytest

from tornado.httpclient import HTTPError

from koi.commands import register_service, _get_client_secret, _update_local_conf,\
    _get_service, _create_service, _get_accounts_client, _get_existing_conf

class TestRegisterService:
    @patch('koi.commands.options')
    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret', return_value='secret')
    @patch('koi.commands._create_service', return_value='service-id')
    @patch('koi.commands._get_accounts_client', return_value='client')
    def test_register_service_params(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf, options):
        runner = CliRunner()
        options.port = '5000'


        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url'])

        assert result.exit_code == 0
        assert result.output == '\nservice-name service registered\n\n'

        _get_accounts_client.assert_called_once_with('accounts-url', 'test@example.com', 'password')
        _create_service.assert_called_once_with('client', 'organisation-id', 'service-name', 'https://localhost:5000', 'service-type')
        _get_client_secret.assert_called_once_with('client', 'service-id')
        _update_local_conf.assert_called_once_with('config', 'service-id', 'secret')


    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret', return_value='secret')
    @patch('koi.commands._create_service', return_value='service-id')
    @patch('koi.commands._get_accounts_client', return_value='client')
    def test_register_service_override_default_params(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com',
                                                 '--config', 'override-config'])

        assert result.exit_code == 0
        assert result.output == '\nservice-name service registered\n\n'

        _get_accounts_client.assert_called_once_with('accounts-url', 'test@example.com', 'password')
        _create_service.assert_called_once_with('client', 'organisation-id', 'service-name', 'https://example.com',
                                                'service-type')
        _get_client_secret.assert_called_once_with('client', 'service-id')
        _update_local_conf.assert_called_once_with('override-config', 'service-id', 'secret')


    @patch('koi.commands.options')
    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret', return_value='secret')
    @patch('koi.commands._create_service', return_value='service-id')
    @patch('koi.commands._get_accounts_client', return_value='client')
    def test_register_service_options(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf, options):
        runner = CliRunner()

        options.name = 'service-name'
        options.service_type = 'service-type'
        options.url_accounts = 'accounts-url'
        options.port = '5000'

        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id'])

        assert result.exit_code == 0
        assert result.output == '\nservice-name service registered\n\n'

        _get_accounts_client.assert_called_once_with('accounts-url', 'test@example.com', 'password')
        _create_service.assert_called_once_with('client', 'organisation-id', 'service-name', 'https://localhost:5000',
                                                'service-type')
        _get_client_secret.assert_called_once_with('client', 'service-id')
        _update_local_conf.assert_called_once_with('config', 'service-id', 'secret')


    def test_register_service_missing_required_param(self):
        runner = CliRunner()
        result = runner.invoke(register_service, ['password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--location', 'https://example.com'])
        assert result.exit_code == 2


    def test_register_service_no_accounts_url(self):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--location', 'https://example.com'])
        assert result.exit_code == 1
        assert result.output == 'Error: accounts_url not defined\n'


    def test_register_service_no_name(self):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com'])
        assert result.exit_code == 1
        assert result.output == 'Error: service name not defined\n'


    def test_register_service_no_service_type(self):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com'])
        assert result.exit_code == 1
        assert result.output == 'Error: service type not defined\n'


    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret')
    @patch('koi.commands._create_service')
    @patch('koi.commands._get_accounts_client', side_effect=HTTPError(400, message='Error Message'))
    def test_register_service_http_error_accounts(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com'])

        assert result.exit_code == 1
        assert result.output == 'Error: HTTP 400: Error Message\n'


    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret')
    @patch('koi.commands._create_service', side_effect=HTTPError(400, message='Error Message'))
    @patch('koi.commands._get_accounts_client')
    def test_register_service_http_error_create_service(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com'])

        assert result.exit_code == 1
        assert result.output == 'Error: HTTP 400: Error Message\n'


    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret', side_effect=HTTPError(400, message='Error Message'))
    @patch('koi.commands._create_service')
    @patch('koi.commands._get_accounts_client')
    def test_register_service_http_error_get_client_secret(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf):
        runner = CliRunner()
        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com'])

        assert result.exit_code == 1
        assert result.output == 'Error: HTTP 400: Error Message\n'



    @patch('koi.commands._update_local_conf')
    @patch('koi.commands._get_client_secret')
    @patch('koi.commands._create_service')
    @patch('koi.commands._get_accounts_client')
    def test_register_service_http_error_default_message(self, _get_accounts_client, _create_service, _get_client_secret, _update_local_conf):
        runner = CliRunner()

        _get_accounts_client.side_effect = HTTPError(400)

        result = runner.invoke(register_service, ['test@example.com', 'password', 'organisation-id',
                                                 '--name', 'service-name',
                                                 '--service_type', 'service-type',
                                                 '--accounts_url', 'accounts-url',
                                                 '--location', 'https://example.com'])

        assert result.exit_code == 1
        assert result.output == 'Error: HTTP 400: Bad Request\n'


class TestGetAccountsClient:
    @patch('koi.commands.API')
    def test_get_accounts_client(self, API):
        client = MagicMock(default_headers={})
        API.return_value = client
        client.accounts.login.post.return_value = {
            'status': 200,
            'data': {'token': 'token-1234'}
        }
        result = _get_accounts_client('accounts-url', 'email@example.com', 'password')

        API.assert_called_once_with('accounts-url', async=False, validate_cert=False)
        client.accounts.login.post.assert_called_once_with(email='email@example.com', password='password')
        assert client.default_headers['Authorization'] == 'token-1234'
        assert result == client


    @patch('koi.commands.API')
    def test_get_accounts_client_http_error(self, API):
        client = MagicMock(default_headers={})
        API.return_value = client
        client.accounts.login.post.side_effect = HTTPError(400, 'Error Message')

        with pytest.raises(HTTPError) as exc:
            _get_accounts_client('accounts-url', 'email@example.com', 'password')

        assert exc.value.message == 'HTTP 400: Error Message'


class TestCreateService:
    @patch('koi.commands._get_service')
    def test_create_service(self, _get_service):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'
        location = 'https://example.com'
        service_type = 'external'

        client.accounts.organisations = {'organisation-id': MagicMock()}
        client.accounts.organisations[organisation_id].services.post.return_value = {
            'status': 200,
            'data': {
                'id': 'service-id',
                'name': 'service-name'
            }
        }

        result = _create_service(client, organisation_id, name, location, service_type)

        client.accounts.organisations[organisation_id].services.post.assert_called_once_with(
            name='service-name', location='https://example.com', service_type='external')
        assert not _get_service.called
        assert result == 'service-id'

    @patch('koi.commands._get_service', return_value='service-id')
    def test_create_service_already_created(self, _get_service):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'
        location = 'https://example.com'
        service_type = 'external'

        client.accounts.organisations = {'organisation-id': MagicMock()}
        client.accounts.organisations[organisation_id].services.post.side_effect = HTTPError(400, 'Service already Created')

        result = _create_service(client, organisation_id, name, location, service_type)

        client.accounts.organisations[organisation_id].services.post.assert_called_once_with(
            name='service-name', location='https://example.com', service_type='external')
        _get_service.assert_called_once_with(client, 'organisation-id', 'service-name')
        assert result == 'service-id'


    @patch('koi.commands._get_service', side_effect=HTTPError(400, 'Error Message'))
    def test_create_service_http_error(self, _get_service):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'
        location = 'https://example.com'
        service_type = 'external'

        client.accounts.organisations = {'organisation-id': MagicMock()}
        client.accounts.organisations[organisation_id].services.post.side_effect = HTTPError(400, 'Service already Created')

        with pytest.raises(HTTPError) as exc:
            _create_service(client, organisation_id, name, location, service_type)

        assert exc.value.message == 'HTTP 400: Error Message'


class TestGetService:
    def test_get_service(self):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'

        client.accounts.services.get.return_value = {'status': 200, 'data': [
            {
                'id': 'service1',
                'name': 'service-name'
            }, {
                'id': 'service2',
                'name': 'other-service-name'
            }
        ]}

        result = _get_service(client, organisation_id, name)
        client.accounts.services.get.assert_called_once_with(organisation_id='organisation-id')
        assert result == 'service1'


    def test_get_service_multiple_names(self):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'

        client.accounts.services.get.return_value = {'status': 200, 'data': [
            {
                'id': 'service1',
                'name': 'service-name'
            }, {
                'id': 'service2',
                'name': 'service-name'
            }
        ]}

        result = _get_service(client, organisation_id, name)
        client.accounts.services.get.assert_called_once_with(organisation_id='organisation-id')
        assert result == 'service1'


    def test_get_service_no_names(self):
            client = MagicMock()
            organisation_id = 'organisation-id'
            name = 'service-name'

            client.accounts.services.get.return_value = {'status': 200, 'data': [
                {
                    'id': 'service1',
                    'name': 'a-service-name'
                }
            ]}

            with pytest.raises(click.ClickException):
                _get_service(client, organisation_id, name)
            client.accounts.services.get.assert_called_once_with(organisation_id='organisation-id')


    def test_get_service_no_results(self):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'

        client.accounts.services.get.return_value = {'status': 200, 'data': []}

        with pytest.raises(click.ClickException):
            _get_service(client, organisation_id, name)
        client.accounts.services.get.assert_called_once_with(organisation_id='organisation-id')


    def test_get_service_http_error(self):
        client = MagicMock()
        organisation_id = 'organisation-id'
        name = 'service-name'

        client.accounts.services.get.side_effect = HTTPError(400, message='Error Message')

        with pytest.raises(HTTPError) as exc:
            _get_service(client, organisation_id, name)

        assert exc.value.message == 'HTTP 400: Error Message'


class TestGetClientSecret:
    def test_get_client_secret(self):
        client = MagicMock()
        client.accounts.services = {'service-123': MagicMock()}
        service_id = 'service-123'

        client.accounts.services[service_id].secrets.get.return_value = {'status': 200, 'data': ['secret1', 'secret2']}

        result = _get_client_secret(client, service_id)

        assert result == 'secret1'


    def test_get_client_secret_no_value(self):
        client = MagicMock()
        client.accounts.services = {'service-123': MagicMock()}
        service_id = 'service-123'

        client.accounts.services[service_id].secrets.get.return_value = {'status': 200, 'data': []}

        result = _get_client_secret(client, service_id)

        assert result is None


    def test_get_client_secrets_http_error(self):
        client = MagicMock()
        client.accounts.services = {'service-123': MagicMock()}
        service_id = 'service-123'

        client.accounts.services[service_id].secrets.get.side_effect = HTTPError(400, message='Error Message')

        with pytest.raises(HTTPError) as exc:
            _get_client_secret(client, service_id)

        assert exc.value.message == 'HTTP 400: Error Message'


class TestUpdateLocalConf:
    @patch('koi.commands._get_existing_conf', return_value=[])
    def test_update_local_conf_no_existing_lines(self, _get_existing_conf):
        mocked_open = mock_open()

        with patch("__builtin__.open", mocked_open):
            _update_local_conf('config', 'service-id', 'client-secret')

        mocked_open.assert_called_once_with('config/local.conf', 'w')
        mocked_open().writelines.assert_called_once_with(
            ['\nservice_id = "service-id"\n', 'client_secret = "client-secret"\n'])

    @patch('koi.commands._get_existing_conf', return_value=['line1\n', 'line2\n'])
    def test_update_local_conf_existing_lines(self, _get_existing_conf):
        mocked_open = mock_open()

        with patch("__builtin__.open", mocked_open):
            _update_local_conf('config', 'service-id', 'client-secret')

        mocked_open.assert_called_once_with('config/local.conf', 'w')
        mocked_open().writelines.assert_called_once_with(
            ['line1\n','line2\n', '\nservice_id = "service-id"\n', 'client_secret = "client-secret"\n'])

    @patch('koi.commands._get_existing_conf', return_value=[])
    def test_update_local_conf_no_client_secret(self, _get_existing_conf):
        mocked_open = mock_open()

        with patch("__builtin__.open", mocked_open):
            _update_local_conf('config', 'service-id', None)

        mocked_open.assert_called_once_with('config/local.conf', 'w')
        mocked_open().writelines.assert_called_once_with(
            ['\nservice_id = "service-id"\n'])

class TestGetExistingConf:
    def test_get_existing_conf_no_content(self):
        mocked_open = mock_open()

        with patch("__builtin__.open", mocked_open):
            result = _get_existing_conf('config')

        mocked_open.assert_called_once_with('config/local.conf', 'r')
        assert result == []

    def test_get_existing_conf_no_service_info(self):
        file_text = "line1\nline2\nline3"
        mocked_open = mock_open(read_data=file_text)

        with patch("__builtin__.open", mocked_open):
            result = _get_existing_conf('config')

        mocked_open.assert_called_once_with('config/local.conf', 'r')
        assert result == ["line1\n", "line2\n", "line3"]

    def test_update_local_conf_has_service_info(self):
        file_text = 'line1\nline2\nline3\nservice_id = "old-service-id"\nclient_secret = "old-client-secret"\n'
        mocked_open = mock_open(read_data=file_text)

        with patch("__builtin__.open", mocked_open):
            result = _get_existing_conf('config')

        mocked_open.assert_called_once_with('config/local.conf', 'r')
        assert result == ["line1\n", "line2\n", "line3\n"]

    def test_update_local_conf_ioerror(self):
        mocked_open = mock_open()
        mocked_open.side_effect=IOError

        with patch("__builtin__.open", mocked_open):
            result = _get_existing_conf('config')

        mocked_open.assert_called_once_with('config/local.conf', 'r')
        assert result == []
