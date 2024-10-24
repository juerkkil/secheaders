from unittest import mock, TestCase
from urllib.parse import ParseResult

from secheaders.securityheaders import SecurityHeaders

from .mock_classes import MockHTTPSConnection


@mock.patch("http.client.HTTPSConnection", MockHTTPSConnection)
class TestSecurityHeaders(TestCase):

    def test_init(self) -> None:
        secheaders = SecurityHeaders("https://www.example.com", 0)
        assert secheaders.target_url == ParseResult(
            scheme='https', netloc='www.example.com', path='', params='', query='', fragment='')

    def test_fetch_headers(self) -> None:
        secheaders = SecurityHeaders("https://www.example.com", 0)
        expected_value = {
            'server': 'nginx',
            'x-xss-protection': '1;',
        }
        secheaders.fetch_headers()
        assert secheaders.headers == expected_value

    def test_eval_headers(self) -> None:
        secheaders = SecurityHeaders("https://www.example.com", 0)
        expected_value = {
            'x-frame-options': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
            'strict-transport-security': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
            'content-security-policy': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
            'x-content-type-options': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
            'x-xss-protection': {'defined': True, 'warn': True, 'contents': '1;', 'notes': []},
            'referrer-policy': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
            'permissions-policy': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
            'server': {'defined': True, 'warn': False, 'contents': 'nginx', 'notes': []},
        }

        secheaders.fetch_headers()
        res = secheaders.check_headers()
        assert res == expected_value
