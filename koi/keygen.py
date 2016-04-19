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
import subprocess
import argparse
import tempfile

DEFAULT_CERTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../certs'))

CA_CRT = os.path.join(DEFAULT_CERTS_DIR, 'CA.crt')
CA_KEY = os.path.join(DEFAULT_CERTS_DIR, 'CA.key')
MOZILLA_PEM = os.path.join(DEFAULT_CERTS_DIR, 'ca-bundle.crt')
LOCALHOST_CRT = os.path.join(DEFAULT_CERTS_DIR, 'localhost.crt')
LOCALHOST_KEY = os.path.join(DEFAULT_CERTS_DIR, 'localhost.key')
CLIENT_CRT = os.path.join(DEFAULT_CERTS_DIR, 'client.crt')
CLIENT_KEY = os.path.join(DEFAULT_CERTS_DIR, 'client.key')

SUBJECT = ('/C=GB/ST=London/L=London'
           '/O=Connected Digital Economy Catapult'
           '/OU=Dev Team'
           '/CN=Open Permissions Platform Coalition')

SUBJECT_ALT_NAME = '''\
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[req_distinguished_name]
# we get this from the command line through -subj

[alt_names]
'''


def call_openssl(cmd, message, silent=False):
    """
    call openssl
    :param cmd: a string of command send to openssl
    :param message: a string to print out if not silent
    :param silent: a boolean for whether to suppress output from openssl
    """
    if silent:
        with open(os.devnull, 'w') as devnull:
            return subprocess.check_call(cmd, shell=True, stdout=devnull,
                                         stderr=subprocess.STDOUT)
    else:
        print message
        return subprocess.check_call(cmd, shell=True)


def gen_private_key(filepath, silent=False):
    """
    generate ssl private key
    :param filepath: file path to the key file
    :param silent: whether to suppress output
    """
    cmd = 'openssl genrsa -out {} 2048'.format(filepath)
    message = 'generate private key {}'.format(filepath)
    call_openssl(cmd, message, silent)


def gen_self_signed_cert(filepath, keyfile, days, silent=False):
    """
    generate self signed ssl certificate, i.e. a private CA certificate
    :param filepath: file path to the key file
    :param keyfile: file path to the private key
    :param days: valid duration for the certificate
    :param silent: whether to suppress output
    """
    cmd = (
        'openssl req -x509 -new -nodes -key {} -days {} -out {} -subj "{}"'
    ).format(keyfile, days, filepath, SUBJECT)
    message = 'generate self signed certificate {} for {} days'.format(
        filepath, days)
    call_openssl(cmd, message, silent)


def gen_cert_request(filepath, keyfile, config, silent=False):
    """
    generate certificate request
    :param filepath: file path to the certificate request
    :param keyfile: file path to the private key
    :param silent: whether to suppress output
    """
    message = 'generate ssl certificate request'
    cmd = (
        'openssl req -new -key {} -out {} -subj "{}"'
        ' -extensions v3_req -config {}').format(
            keyfile, filepath, SUBJECT, config)
    call_openssl(cmd, message, silent)


def sign_cert_request(filepath, cert_req, ca_crt, ca_key, days, extfile,
                      silent=False):
    """
    generate self signed ssl certificate, i.e. a private CA certificate
    :param filepath: file path to the key file
    :param keyfile: file path to the private key
    :param days: valid duration for the certificate
    :param silent: whether to suppress output
    """
    message = 'sign certificate request'
    cmd = ('openssl x509 -req -in {} -CA {} -CAkey {} -CAcreateserial'
           ' -out {} -days {} -extfile {} -extensions v3_req').format(
               cert_req, ca_crt, ca_key, filepath, days, extfile)
    call_openssl(cmd, message, silent)


def gen_ca_cert(filename, dirname, days, silent=False):
    """
    generate a CA key and certificate key pair.
    :param filename: prefix for the key and cert file
    :param dirname: name of the directory
    :param days: days of the certificate being valid
    :param silent: whether to suppress output
    """
    keyfile = os.path.join(dirname, '{}.key'.format(filename))
    ca_crt = os.path.join(dirname, '{}.crt'.format(filename))
    gen_private_key(keyfile, silent)
    gen_self_signed_cert(ca_crt, keyfile, days, silent)


def gen_non_ca_cert(filename, dirname, days, ip_list, dns_list,
                    ca_crt, ca_key, silent=False):
    """
    generate a non CA key and certificate key pair signed by the private
    CA key and crt.
    :param filename: prefix for the key and cert file
    :param dirname: name of the directory
    :param days: days of the certificate being valid
    :ip_list: a list of ip address to be included in the certificate
    :dns_list: a list of dns names to be included in the certificate
    :ca_key: file path to the CA key
    :ca_crt: file path to the CA crt
    :param silent: whether to suppress output
    """
    key_file = os.path.join(dirname, '{}.key'.format(filename))
    req = os.path.join(dirname, '{}.csr'.format(filename))
    crt = os.path.join(dirname, '{}.crt'.format(filename))
    gen_private_key(key_file, silent)
    alt_names = []

    for ind, ip in enumerate(ip_list):
        alt_names.append('IP.{} = {}'.format(ind + 1, ip))
    for ind, dns in enumerate(dns_list):
        alt_names.append('DNS.{} = {}'.format(ind + 1, dns))

    conf = tempfile.mktemp()
    open(conf, 'w').write(SUBJECT_ALT_NAME + '\n'.join(alt_names))
    gen_cert_request(req, key_file, conf, silent)
    sign_cert_request(crt, req, ca_crt, ca_key, days, conf, silent)


def check_cert(certfile):
    """
    output the text format of the certificate
    :param filepath: file path to the ssl certificate
    :returns: string
    """
    cmd = 'openssl x509 -in {} -text -noout'.format(certfile)
    out = subprocess.check_output(cmd, shell=True)
    return out


def check_key_cert_match(keyfile, certfile):
    """
    check if the ssl key matches the certificate
    :param keyfile: file path to the ssl key
    :param certfile: file path to the ssl certificate
    :returns: true or false
    """
    key_modulus = subprocess.check_output(
        'openssl rsa -noout -modulus -in {}'.format(keyfile),
        shell=True)
    cert_modulus = subprocess.check_output(
        'openssl x509 -noout -modulus -in {}'.format(certfile),
        shell=True)
    return key_modulus == cert_modulus


def argument_parser():
    """
    process the command line arguments.
    :returns: an ArgumentParser object.
    """
    parser = argparse.ArgumentParser(
        description='openssl wrapper')
    parser.add_argument('--ca', action='store_true', default=False,
                        dest='is_ca',
                        help='Is it a Certificate Authority certificate?')
    parser.add_argument('-f', '--filename', type=str, default='localhost',
                        help='File name prefix of the key and certificate.')
    parser.add_argument('-d', '--dirname', type=str, default=DEFAULT_CERTS_DIR,
                        help='Destination directory name.')
    parser.add_argument('--days', type=int, default=500,
                        help='Duration of certificate.')
    parser.add_argument('--ip', nargs='*', default=['127.0.0.1'],
                        help='IP address.')
    parser.add_argument('--dns', nargs='*', default=['localhost'],
                        help='DNS')
    parser.add_argument('--silent', action='store_true',
                        help='should the output from the shell be silenced?')
    return parser


def main(argv=None):
    args = argument_parser().parse_args(argv)
    if args.is_ca:
        gen_ca_cert(args.filename, args.dirname, args.days, args.silent)
    else:
        ca_crt = os.path.join(DEFAULT_CERTS_DIR, 'CA.crt')
        ca_key = os.path.join(DEFAULT_CERTS_DIR, 'CA.key')
        gen_non_ca_cert(args.filename, args.dirname, args.days,
                        args.ip, args.dns, ca_crt, ca_key, args.silent)


if __name__ == '__main__':
    main()
