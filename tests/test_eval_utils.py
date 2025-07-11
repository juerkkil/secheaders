from unittest import TestCase
import pytest

from secheaders.exceptions import SecurityHeadersException
from secheaders import eval_utils
from secheaders.constants import EVAL_OK, EVAL_WARN

from tests.constants import EXAMPLE_HEADERS


class TestUtils(TestCase):

    def test_csp_parser(self) -> None:
        example_csp = (
            "default-src 'none' *.example.com; script-src 'self' src.example.com 'unsafe-inline'; connect-src 'self';"
            "img-src *; style-src 'self'; base-uri 'self';form-action 'self'"
        )
        expected_value = {
            "default-src": ["'none'", "*.example.com"],
            "script-src": ["'self'", "src.example.com", "'unsafe-inline'"],
            "connect-src": ["'self'"],
            "img-src": ["*"],
            "style-src": ["'self'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
        }
        res = eval_utils.csp_parser(example_csp)
        assert res == expected_value

    def test_eval_csp(self) -> None:
        unsafe_csp = (
            "default-src 'none' *.example.com; script-src 'self' src.example.com 'unsafe-inline'; connect-src 'self';"
            "img-src *; style-src 'self'; base-uri 'self';form-action 'self'"
        )
        res = eval_utils.eval_csp(unsafe_csp)
        expected_value = (
            EVAL_WARN,
            ["Unsafe source 'unsafe-inline' in directive script-src"]
        )
        assert res == expected_value

        safe_csp = "default-src 'self'; img-src 'self' cdn.example.com;"
        expected_value = (EVAL_OK, [])
        res = eval_utils.eval_csp(safe_csp)
        assert res == expected_value

    def test_eval_version_info(self) -> None:
        nginx_banner_warn = 'nginx 1.17.10 (Ubuntu)'
        nginx_banner_ok = 'nginx'
        res = eval_utils.eval_version_info(nginx_banner_warn)
        assert res == (EVAL_WARN, [])
        res = eval_utils.eval_version_info(nginx_banner_ok)
        assert res == (EVAL_OK, [])

    def test_permissions_policy_parser(self) -> None:
        example_pp = (
            'geolocation=(src "https://a.example.com" "https://b.example.com"), picture-in-picture=(), camera=*;'
        )
        expected_value = {
            'geolocation': ['src', '"https://a.example.com"', '"https://b.example.com"'],
            'picture-in-picture': [],
            'camera': ['*'],
        }
        res = eval_utils.permissions_policy_parser(example_pp)
        assert expected_value == res

    def test_eval_permissions_policy(self) -> None:
        unsafe_pp = 'geolocation=(src "https://a.example.com"), picture-in-picture=(), camera=*;'
        expected_value = (EVAL_WARN, [
                "Privacy-sensitive feature 'camera' allowed from unsafe origin '*'",
                "Privacy-sensitive feature 'microphone' not defined in permission-policy, always allowed.",
                "Privacy-sensitive feature 'payment' not defined in permission-policy, always allowed.",
        ])
        res = eval_utils.eval_permissions_policy(unsafe_pp)
        assert res == expected_value
        safe_pp = "geolocation=(src), camera=(), microphone=(), payment=()"
        expected_value = EVAL_OK, []
        res = eval_utils.eval_permissions_policy(safe_pp)
        assert res == expected_value

    def test_eval_headers(self) -> None:
        fetched_headers = {
            'server': 'nginx',
            'x-xss-protection': '1;',
        }
        with pytest.raises(SecurityHeadersException, match=r"Headers not fetched successfully"):
            eval_utils.analyze_headers({})

        res = eval_utils.analyze_headers(fetched_headers)

        assert res == EXAMPLE_HEADERS
