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
import tempfile
import subprocess

import pytest

from koi.keygen import (
    argument_parser, check_cert, check_key_cert_match, gen_non_ca_cert, main,
    DEFAULT_CERTS_DIR)


@pytest.mark.parametrize("args,is_ca,filename,dirname", [
    ('', False, 'localhost', 'certs'),
    ('--ca', True, 'localhost', 'certs'),
    ('--ca -f device', True, 'device', 'certs'),
    ('--ca -f device -d mydir', True, 'device', 'mydir'),
])
def test_argument_parser(args, is_ca, filename, dirname):
    parser = argument_parser()
    args = parser.parse_args(args.split())
    assert args.is_ca == is_ca
    assert args.filename == filename
    assert os.path.basename(args.dirname) == dirname


def test_check_cert_localhost():
    out = check_cert(os.path.join(DEFAULT_CERTS_DIR, 'localhost.crt'))
    assert 'localhost' in out

def test_check_cert_ip():
    out = check_cert(os.path.join(DEFAULT_CERTS_DIR, 'localhost.crt'))
    assert '127.0.0.1' in out

def test_key_cert_match():
    key = os.path.join(DEFAULT_CERTS_DIR, 'localhost.key')
    crt = os.path.join(DEFAULT_CERTS_DIR, 'localhost.crt')
    assert check_key_cert_match(key, crt)


def test_gen_ca_cert():
    tmp_dir = tempfile.mkdtemp()
    main(['--ca', '-f', 'PRIVATE_CA', '-d', tmp_dir])
    key = os.path.join(tmp_dir, 'PRIVATE_CA.key')
    crt = os.path.join(tmp_dir, 'PRIVATE_CA.crt')
    assert check_key_cert_match(key, crt)


def test_gen_non_ca_cert():
    tmp_dir = tempfile.mkdtemp()

    main(['--ca', '-f', 'CA', '-d', tmp_dir])
    ca_key = os.path.join(tmp_dir, 'CA.key')
    ca_crt = os.path.join(tmp_dir, 'CA.crt')
    assert check_key_cert_match(ca_key, ca_crt)

    gen_non_ca_cert('device', tmp_dir, 500, ['127.0.0.1'], [], ca_crt, ca_key)
    key = os.path.join(tmp_dir, 'device.key')
    crt = os.path.join(tmp_dir, 'device.crt')
    assert check_key_cert_match(key, crt)


def test_gen_non_ca_cert_shell():
    tmp_dir = tempfile.mkdtemp()

    key = os.path.join(tmp_dir, 'device.key')
    crt = os.path.join(tmp_dir, 'device.crt')
    main(['-f', 'device', '-d', tmp_dir])
    assert check_key_cert_match(key, crt)


def test_run_module_as_script():
    tmp_dir = tempfile.mkdtemp()

    key = os.path.join(tmp_dir, 'device.key')
    crt = os.path.join(tmp_dir, 'device.crt')

    subprocess.call(
        'python -m koi.keygen -d {} -f device'.format(tmp_dir),
        shell=True)
    assert check_key_cert_match(key, crt)
