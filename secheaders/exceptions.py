class SecurityHeadersException(Exception):
    pass


class InvalidTargetURL(SecurityHeadersException):
    pass


class UnableToConnect(SecurityHeadersException):
    pass


class FailedToFetchHeaders(SecurityHeadersException):
    pass
