from unittest import mock, TestCase
from urllib.parse import ParseResult

from secheaders.webclient import WebClient

from .mock_classes import MockHTTPSConnection


@mock.patch("http.client.HTTPSConnection", MockHTTPSConnection)
class TestWebClient(TestCase):

    def test_init(self) -> None:
        webclient = WebClient("https://www.example.com", 0)
        assert webclient.target_url == ParseResult(
            scheme='https', netloc='www.example.com', path='', params='', query='', fragment='')

    def test_get_headers(self) -> None:
        webclient = WebClient("https://www.example.com", 0)
        expected_value = {
            'server': 'nginx',
            'x-xss-protection': '1;',
        }
        headers = webclient.get_headers()
        assert headers == expected_value
