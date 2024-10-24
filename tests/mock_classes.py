class MockHTTPResponse:
    def __init__(self, sock=None, debuglevel=0, method=None, url=None):
        pass

    def getheaders(self):
        return [
            ('x-xss-protection', '1;'),
            ('server', 'nginx')
        ]

    def getsomething(self):
        pass


class MockHTTPSConnection:
    def __init__(self, h, context, timeout):
        pass

    def request(self, method, url, headers):
        pass

    def headers(self):
        return "content-type", "accept"

    def getresponse(self):
        a = MockHTTPResponse()
        return a

    def close(self):
        pass
