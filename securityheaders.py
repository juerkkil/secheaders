import httplib
import argparse
import socket 
import ssl

from urlparse import urlparse

class SecurityHeaders():
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):
        """ Risk evaluation function.

        Set header warning flag (1/0) according to its contents.

        Args:
            header (str): HTTP header name in lower-case
            contents (str): Header contents (value)
        """
        warn = 1

        if header == 'x-frame-options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = 0
            else:
                warn = 1
    
        if header == 'strict-transport-security':
            warn = 0

        """ Evaluating the warn of CSP contents may be a bit more tricky.
            For now, just disable the warn if the header is defined
            """
        if header == 'content-security-policy':
            warn = 0

        """ Raise the warn flag, if cross domain requests are allowed from any 
            origin """
        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = 1
            else:
                warn = 0
    
        if header == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = 0
            else:
                warn = 1

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = 0
            else:
                warn =1

        """ Enable warning if backend version information is disclosed """
        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = 1
            else: 
                warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]

        conn = httplib.HTTPSConnection(hostname, timeout=5, context = ssl._create_unverified_context() )
        try:
            conn.request('GET', '/')
            res = conn.getresponse()
        except socket.gaierror:
            return False
        except:
            return False

        return True

    def test_http_to_https(self, url, follow_redirects = 5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        print str(url)

        if protocol == 'https' and follow_redirects != 5:
            return True
        elif protocol == 'https' and follow_redirects == 5:
            protocol = 'http'

        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print 'HTTP request failed'
            return False

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.test_http_to_https(header[1], follow_redirects - 1) 

        return False

    """ Make the HTTP HEAD request and check if any of the pre-defined 
        headers exists.
        If one does, evaluate the risk according to contents. """
    def check_headers(self, url, follow_redirects = 0):
        """ Make the HTTP request and check if any of the pre-defined
        headers exists.

        Args:
            url (str): Target URL in format: scheme://hostname/path/to/file
            follow_redirects (Optional[str]): How deep we follow the redirects, 
            value 0 disables redirects.
        """

        """ Default return array """
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''}, 
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''}
    
        }

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        elif (protocol == 'https'):
            conn = httplib.HTTPSConnection(hostname)
        else:
            """ Unknown protocol scheme """
            return {}
    
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print 'HTTP request failed'
            return {}

        """ Follow redirect """
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.check_headers(header[1], follow_redirects - 1) 
                
        """ Loop through headers and evaluate the risk """
        for header in headers:
            if (header[0] in retval):
                retval[header[0]] = self.evaluate_warn(header[0], header[1])

        return retval

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Check HTTP security headers', \
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int, help='Max redirects, set 0 to disable')
    args = parser.parse_args()
    url = args.url
    redirects = args.max_redirects

    foo = SecurityHeaders()

    headers = foo.check_headers(url, redirects)
    okColor = '\033[92m'
    warnColor = '\033[93m'
    endColor = '\033[0m'
    for header, value in headers.iteritems():
        if value['warn'] == 1:
            if value['defined'] == False:
                print 'Header \'' + header + '\' is missing ... [ ' + warnColor + 'WARN' + endColor + ' ]'
            else:
                print 'Header \'' + header + '\' contains value ' + value['contents'] + \
                    ' ... [ ' + warnColor + 'WARN' + endColor + ' ]'
        elif value['warn'] == 0:
            if value['defined'] == False:
                print 'Header \'' + header + '\' is missing ... [ ' + okColor + 'OK' + endColor +' ]'
            else:
                print 'Header \'' + header + '\' contains value ' + value['contents'] + \
                    ' ... [ ' + okColor + 'OK' + endColor + ' ]'

    if foo.test_https(url):
        print 'HTTPS supported ... [ ' + okColor + 'OK' + endColor + ' ]'
    else:
        print 'HTTPS supported ... [ ' + warnColor + 'FAIL' + endColor + ' ]'


    if foo.test_http_to_https(url, 5):
        print 'HTTP -> HTTPS redirect ... [ ' + okColor + 'OK' + endColor + ' ]'
    else:
        print 'HTTP -> HTTPS redirect ... [ ' + warnColor + 'FAIL' + endColor + ' ]'
    