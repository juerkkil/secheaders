import argparse
import http.client
import socket
import ssl
import sys
from urllib.parse import urlparse

import utils
from constants import EVAL_WARN, DEFAULT_URL_SCHEME


class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass


class SecurityHeaders():
    # Let's try to imitate a legit browser to avoid being blocked / flagged as web crawler
    REQUEST_HEADERS = {
        'Accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                   'application/signed-exchange;v=b3;q=0.9'),
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
                       'Chrome/106.0.0.0 Safari/537.36'),
    }

    HEADERS_DICT = {
        'x-frame-options': {
            'recommended': True,
            'eval_func': utils.eval_x_frame_options,
        },
        'strict-transport-security': {
            'recommended': True,
            'eval_func': utils.eval_sts,
        },
        'content-security-policy': {
            'recommended': True,
            'eval_func': utils.eval_csp,
        },
        'server': {
            'recommended': False,
            'eval_func': utils.eval_version_info,
        },
        'x-powered-by': {
            'recommended': False,
            'eval_func': utils.eval_version_info,
        },
        'x-content-type-options': {
            'recommended': True,
            'eval_func': utils.eval_content_type_options,
        },
        'x-xss-protection': {
            # X-XSS-Protection is deprecated; not supported anymore, and may be even dangerous in older browsers
            'recommended': False,
            'eval_func': utils.eval_x_xss_protection,
        },
        'referrer-policy': {
            'recommended': True,
            'eval_func': utils.eval_referrer_policy,
        },
        'permissions-policy': {
            'recommended': True,
            'eval_func': utils.eval_permissions_policy,
        }
    }

    def __init__(self, url, max_redirects=2, no_check_certificate=False):
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            url = "{}://{}".format(DEFAULT_URL_SCHEME, url)
            parsed = urlparse(url)
            if not parsed.scheme and not parsed.netloc:
                raise InvalidTargetURL("Unable to parse the URL")

        self.protocol_scheme = parsed.scheme
        self.hostname = parsed.netloc
        self.path = parsed.path
        self.max_redirects = max_redirects
        self.verify_ssl = False if no_check_certificate else True
        self.headers = None

    def test_https(self):
        conn = http.client.HTTPSConnection(self.hostname, context=ssl.create_default_context(), timeout=10)
        try:
            conn.request('GET', '/')
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return {'supported': False, 'certvalid': False}
        except ssl.SSLError:
            return {'supported': True, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def _follow_redirect_until_response(self, url, follow_redirects=5):
        temp_url = urlparse(url)
        while follow_redirects >= 0:
            if not temp_url.netloc:
                raise InvalidTargetURL("Invalid redirect URL")

            if temp_url.scheme == 'http':
                conn = http.client.HTTPConnection(temp_url.netloc, timeout=10)
            elif temp_url.scheme == 'https':
                if self.verify_ssl:
                    ctx = ssl.create_default_context()
                else:
                    ctx = ssl._create_stdlib_context()
                conn = http.client.HTTPSConnection(temp_url.netloc, context=ctx, timeout=10)
            else:
                raise InvalidTargetURL("Unsupported protocol scheme")

            try:
                conn.request('GET', temp_url.path, headers=self.REQUEST_HEADERS)
                res = conn.getresponse()
            except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
                raise UnableToConnect("Connection failed {}".format(temp_url.netloc)) from e
            except ssl.SSLError as e:
                raise UnableToConnect("SSL Error") from e

            if res.status >= 300 and res.status < 400:
                headers = res.getheaders()
                headers_dict = {x[0].lower(): x[1] for x in headers}
                if 'location' in headers_dict:
                    temp_url = urlparse(headers_dict['location'])
            else:
                return temp_url

            follow_redirects -= 1

        # More than x redirects, stop here
        return None

    def test_http_to_https(self, follow_redirects=5):
        url = "http://{}{}".format(self.hostname, self.path)
        target_url = self._follow_redirect_until_response(url)
        if target_url and target_url.scheme == 'https':
            return True

        return False

    def fetch_headers(self):
        """ Fetch headers from the target site and store them into the class instance """
        initial_url = "{}://{}{}".format(self.protocol_scheme, self.hostname, self.path)
        target_url = None
        if self.max_redirects:
            target_url = self._follow_redirect_until_response(initial_url, self.max_redirects)

        if not target_url:
            # If redirects lead to failing URL, fall back to the initial url
            target_url = urlparse(initial_url)

        if target_url.scheme == 'http':
            conn = http.client.HTTPConnection(target_url.hostname, timeout=10)
        elif target_url.scheme == 'https':
            if self.verify_ssl:
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_stdlib_context()
            conn = http.client.HTTPSConnection(target_url.hostname, context=ctx, timeout=10)
        else:
            raise InvalidTargetURL("Unsupported protocol scheme")

        try:
            conn.request('GET', target_url.path, headers=self.REQUEST_HEADERS)
            res = conn.getresponse()
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            raise UnableToConnect("Connection failed {}".format(target_url.hostname)) from e

        headers = res.getheaders()
        self.headers = {x[0].lower(): x[1] for x in headers}

    def check_headers(self):
        """ Default return array """
        retval = {}

        if not self.headers:
            raise SecurityHeadersException("Headers not fetched successfully")

        """ Loop through headers and evaluate the risk """
        for header in self.HEADERS_DICT:
            if header in self.headers:
                eval_func = self.HEADERS_DICT[header].get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException("No evaluation function found for header: {}".format(header))
                warn = eval_func(self.headers[header]) == EVAL_WARN
                retval[header] = {'defined': True, 'warn': warn, 'contents': self.headers[header]}
            else:
                warn = self.HEADERS_DICT[header].get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None}

        return retval


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    parser.add_argument('--no-check-certificate', dest='no_check_certificate', action='store_true',
                        help='Do not verify TLS certificate chain')
    args = parser.parse_args()
    header_check = SecurityHeaders(args.url, args.max_redirects, args.no_check_certificate)
    header_check.fetch_headers()
    headers = header_check.check_headers()
    if not headers:
        print("Failed to fetch headers, exiting...")
        sys.exit(1)

    ok_color = '\033[92m'
    warn_color = '\033[93m'
    end_color = '\033[0m'
    for header, value in headers.items():
        if value['warn']:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}WARN{} ]".format(header, warn_color, end_color))
            else:
                print("Header '{}' contains value '{}'... [ {}WARN{} ]".format(
                    header, value['contents'], warn_color, end_color,
                ))
        else:
            if not value['defined']:
                print("Header '{}' is missing ... [ {}OK{} ]".format(header, ok_color, end_color))
            else:
                print("Header '{}' contains value '{}'... [ {}OK{} ]".format(
                    header, value['contents'], ok_color, end_color,
                ))

    https = header_check.test_https()
    if https['supported']:
        print("HTTPS supported ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS supported ... [ {}FAIL{} ]".format(warn_color, end_color))

    if https['certvalid']:
        print("HTTPS valid certificate ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTPS valid certificate ... [ {}FAIL{} ]".format(warn_color, end_color))

    if header_check.test_http_to_https():
        print("HTTP -> HTTPS redirect ... [ {}OK{} ]".format(ok_color, end_color))
    else:
        print("HTTP -> HTTPS redirect ... [ {}FAIL{} ]".format(warn_color, end_color))
