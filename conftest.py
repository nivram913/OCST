import re
import pytest
from argparse import ArgumentTypeError


def validate_ip_address(value):
    regex = re.compile('([0-9]+\.){3}[0-9]+')
    if not regex.fullmatch(value):
        raise ArgumentTypeError('Invalid IP address')

    numbers = value.split('.')
    if any([True if int(n) < 0 or int(n) > 255 else False for n in numbers]):
        raise ArgumentTypeError('Invalid IP address')

    return value


def validate_port(value):
    try:
        port = int(value)
    except ValueError:
        raise ArgumentTypeError('Port must be a number')

    if port <= 0 or port > 65535:
        raise ArgumentTypeError('Port must be between 1 and 65535')

    return port


def pytest_addoption(parser):
    parser.addoption('--target', required=True, type=validate_ip_address, action='store', help='Target IP address')
    parser.addoption('--port', default='80', type=validate_port, action='store', help='Target port number')

    parser.addoption('--adm-user', default='admin', action='store', help='ONVIF administrator account')
    parser.addoption('--adm-password', default='', action='store', help='ONVIF administrator password')
    parser.addoption('--op-user', default='', action='store', help='ONVIF operator account')
    parser.addoption('--op-password', default='', action='store', help='ONVIF operator password')
    parser.addoption('--usr-user', default='', action='store', help='ONVIF user account')
    parser.addoption('--usr-password', default='', action='store', help='ONVIF user password')

    parser.addoption('--default-creds', default='Authentication/default_credentials.txt', action='store',
                     help='Default credentials file')
    parser.addoption('--common-creds', default='', action='store', help='Common credentials file')
    parser.addoption('--dir-list', default='Configuration/directory-list-2.3-small.txt', action='store',
                     help='Known directories list file')


def _load_file(file):
    with open(file, 'r') as f:
        lines = f.readlines()

    return [(line.split('/')[0], line.split('/')[1][:-1]) for line in lines]


def _load_line_file(file):
    with open(file, 'r') as f:
        lines = f.readlines()

    return [line[:-1] for line in lines]


@pytest.fixture(scope="session")
def target(request):
    return request.config.getoption('--target')


@pytest.fixture(scope="session")
def port(request):
    return request.config.getoption('--port')


@pytest.fixture(scope="session")
def adm_user(request):
    return request.config.getoption('--adm-user')


@pytest.fixture(scope="session")
def adm_password(request):
    return request.config.getoption('--adm-password')


@pytest.fixture(scope="session")
def op_user(request):
    return request.config.getoption('--op-user')


@pytest.fixture(scope="session")
def op_password(request):
    return request.config.getoption('--op-password')


@pytest.fixture(scope="session")
def usr_user(request):
    return request.config.getoption('--usr-user')


@pytest.fixture(scope="session")
def usr_password(request):
    return request.config.getoption('--usr-password')


@pytest.fixture(scope="session")
def uri():
    return '/onvif/device_service'


@pytest.fixture(scope="session")
def default_creds(request):
    file = request.config.getoption('--default-creds')
    return _load_file(file)


@pytest.fixture(scope="session")
def common_creds(request):
    file = request.config.getoption('--common-creds')
    if file == '':
        return []
    return _load_file(file)


@pytest.fixture(scope="session")
def dir_list(request):
    file = request.config.getoption('--dir-list')
    return _load_line_file(file)
