from unittest import mock, TestCase
from secheaders import cmd_utils
from secheaders.constants import WARN_COLOR, OK_COLOR, END_COLOR
from .constants import EXAMPLE_HEADERS

from .mock_classes import MockHTTPSConnection


@mock.patch("http.client.HTTPSConnection", MockHTTPSConnection)
class TestCmdUtils(TestCase):

    def test_get_eval_output(self) -> None:
        assert cmd_utils.get_eval_output(True, True) == "[ WARN ]"
        assert cmd_utils.get_eval_output(True, False) == f"[ {WARN_COLOR}WARN{END_COLOR} ]"
        assert cmd_utils.get_eval_output(False, True) == "[ OK ]"
        assert cmd_utils.get_eval_output(False, False) == f"[ {OK_COLOR}OK{END_COLOR} ]"

    def test_cmd_output(self) -> None:
        example_https = {
            'supported': True,
            'certvalid': True,
            'redirect': False,
        }
        res = cmd_utils.output_text("example.com", EXAMPLE_HEADERS, example_https, verbose=True, no_color=False)
        assert "HTTPS supported" in res
        assert "Scanning target example.com ..." in res
        assert "Header 'x-frame-options' is missing" in res
        assert "x-xss-protection: 1;" in res
        assert "Header 'permissions-policy' is missing" in res
        assert "adsfdasfasdf " not in res
