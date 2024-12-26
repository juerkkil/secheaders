# Expected structure for parsed security headers when following headers are returned:
# X-XSS-Protection: 1;
# Server: nginx
EXAMPLE_HEADERS = {
    'x-frame-options': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
    'strict-transport-security': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
    'content-security-policy': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
    'x-content-type-options': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
    'x-xss-protection': {'defined': True, 'warn': True, 'contents': '1;', 'notes': []},
    'referrer-policy': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
    'permissions-policy': {'defined': False, 'warn': True, 'contents': None, 'notes': []},
    'server': {'defined': True, 'warn': False, 'contents': 'nginx', 'notes': []},
}
