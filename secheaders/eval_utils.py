import re
from typing import Tuple

from .constants import EVAL_WARN, EVAL_OK, UNSAFE_CSP_RULES, RESTRICTED_PERM_POLICY_FEATURES, SERVER_VERSION_HEADERS, \
    PREFLIGHT_HEADERS
from .exceptions import SecurityHeadersException


def eval_x_frame_options(contents: str) -> Tuple[int, list]:
    if contents.lower() in ['deny', 'sameorigin']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_content_type_options(contents: str) -> Tuple[int, list]:
    if contents.lower() == 'nosniff':
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_x_xss_protection(contents: str) -> Tuple[int, list]:
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    values = [v.strip() for v in contents.split(';')]
    if '0' in values or ('1' in values and 'mode=block' in values):
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_sts(contents: str) -> Tuple[int, list]:
    if re.match("^max-age=[0-9]+\\s*(;|$)\\s*", contents.lower()):
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_csp(contents: str) -> Tuple[int, list]:
    csp_unsafe = False
    csp_notes = []

    csp_parsed = csp_parser(contents)

    for rule, values in UNSAFE_CSP_RULES.items():
        rule_defined = rule in csp_parsed
        default_src_defined = 'default-src' in csp_parsed

        if rule_defined:
            for unsafe_src in values:
                if unsafe_src in csp_parsed[rule]:
                    csp_notes.append(f"Unsafe source {unsafe_src} in directive {rule}")
                    csp_unsafe = True
        elif '-src' in rule and default_src_defined:
            for unsafe_src in values:
                if unsafe_src in csp_parsed['default-src']:
                    csp_unsafe = True
                    csp_notes.append(
                        f"Directive {rule} not defined, and default-src contains unsafe source {unsafe_src}"
                    )
        else:
            if not default_src_defined:
                csp_notes.append(f"No directive {rule} nor default-src defined in the Content Security Policy")
                csp_unsafe = True

    if csp_unsafe:
        return EVAL_WARN, csp_notes

    return EVAL_OK, []


def eval_version_info(contents: str) -> Tuple[int, list]:
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 1 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN, []

    return EVAL_OK, []


def eval_permissions_policy(contents: str) -> Tuple[int, list]:
    pp_parsed = permissions_policy_parser(contents)
    notes = []
    pp_unsafe = False

    for feature in RESTRICTED_PERM_POLICY_FEATURES:
        feat_policy = pp_parsed.get(feature)
        if feat_policy is None:
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' not defined in permission-policy, always allowed.")
        elif '*' in feat_policy:
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' allowed from unsafe origin '*'")
    if pp_unsafe:
        return EVAL_WARN, notes

    return EVAL_OK, []


def eval_referrer_policy(contents: str) -> Tuple[int, list]:
    if contents.lower().strip() in [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
    ]:
        return EVAL_OK, []

    return EVAL_WARN, [f"Unsafe contents: {contents}"]


def csp_parser(contents: str) -> dict:
    csp = {}
    directives = contents.split(";")
    for directive in directives:
        directive = directive.strip().split()
        if directive:
            csp[directive[0]] = directive[1:] if len(directive) > 1 else []

    return csp


def permissions_policy_parser(contents: str) -> dict:
    policies = contents.split(",")
    retval = {}
    for policy in policies:
        match = re.match('^(\\w+(?:-\\w+)*)=(\\(([^\\)]*)\\)|\\*|self);?$', policy.strip())
        if match:
            feature = match.groups()[0]
            feature_policy = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


def eval_coep(contents: str) -> Tuple[int, list]:
    # Accept only recommended values as safe
    safe_values = ['require-corp', 'unsafe-none']
    notes = []

    value = contents.strip().lower()
    if value in safe_values:
        return EVAL_OK, []

    notes.append(f"Unrecognized or unsafe COEP value: {contents}")
    return EVAL_WARN, notes


def eval_coop(contents: str) -> Tuple[int, list]:
    # Accept only recommended values as safe
    safe_values = ['same-origin', 'same-origin-allow-popups', 'unsafe-none']
    notes = []

    value = contents.strip().lower()
    if value in safe_values:
        return EVAL_OK, []

    notes.append(f"Unrecognized or unsafe COOP value: {contents}")
    return EVAL_WARN, notes


def eval_cors(cors_headers: dict) -> Tuple[int, list]:
    contents = cors_headers.get('access-control-allow-origin')
    allow_credentials = cors_headers.get('access-control-allow-credentials', False)

    if not contents:
        return EVAL_OK, []

    notes = []
    # Check that the CORS value is not reflected from our preflight request (risky practice)
    if contents in PREFLIGHT_HEADERS.values():
        notes.append("CORS header value is reflected back from the Origin or other request headers.")
        if allow_credentials and allow_credentials.lower() == 'true':
            notes.append("Access-Control-Allow-Credentials is set to true, which is unsafe with reflected origins.")
        return EVAL_WARN, notes

    # Allow specific origins (not wildcard)
    # Match a valid http or https URL using regex
    if re.match(r'^https?://[^\s/$.?#].[^\s]*$', contents):
        return EVAL_OK, []

    if contents == '*':
        notes.append("Wildcard '*' allows cross-site requests from any origin.")
        if allow_credentials and allow_credentials.lower() == 'true':
            notes.append("Access-Control-Allow-Credentials is set to true, which is unsafe with wildcard origins.")
            return EVAL_WARN, notes
        return EVAL_OK, notes

    notes.append(f"Unrecognized or unsafe CORS value: {contents}")

    return EVAL_WARN, notes


def eval_corp(contents: str) -> Tuple[int, list]:
    # Accept only recommended values as safe
    safe_values = ['same-origin', 'same-site']
    valid_values = safe_values + ['cross-origin']

    notes = []

    value = contents.strip().lower()
    if value in valid_values:
        # Only 'same-origin' and 'same-site' are considered safe
        if value in safe_values:
            return EVAL_OK, []

        notes.append(
            f"Value '{contents}' is valid but less restrictive; consider using 'same-origin' or 'same-site'."
        )
        return EVAL_WARN, notes

    notes.append(f"Unrecognized value: {contents}")
    return EVAL_WARN, notes


def analyze_headers(headers: dict, cors_headers: dict = None) -> dict:
    """ Default return array """
    retval = {}

    security_headers = {
        'x-frame-options': {
            'recommended': True,
            'eval_func': eval_x_frame_options,
        },
        'strict-transport-security': {
            'recommended': True,
            'eval_func': eval_sts,
        },
        'content-security-policy': {
            'recommended': True,
            'eval_func': eval_csp,
        },
        'x-content-type-options': {
            'recommended': True,
            'eval_func': eval_content_type_options,
        },
        'x-xss-protection': {
            # X-XSS-Protection is deprecated; not supported anymore, and may be even dangerous in older browsers
            'recommended': False,
            'eval_func': eval_x_xss_protection,
        },
        'referrer-policy': {
            'recommended': True,
            'eval_func': eval_referrer_policy,
        },
        'permissions-policy': {
            'recommended': True,
            'eval_func': eval_permissions_policy,
        },
    }
    cors_headers_mapping = {
        'cross-origin-embedder-policy': {
            'recommended': True,
            'eval_func': eval_coep,
        },
        'cross-origin-opener-policy': {
            'recommended': True,
            'eval_func': eval_coop,
        },
        'cross-origin-resource-policy': {
            'recommended': True,
            'eval_func': eval_corp
        }
    }

    if not headers:
        raise SecurityHeadersException("Headers not fetched successfully")

    for header, settings in security_headers.items():
        if header in headers:
            eval_func = settings.get('eval_func')
            if not eval_func:
                raise SecurityHeadersException(f"No evaluation function found for header: {header}")
            res, notes = eval_func(headers[header])
            retval[header] = {
                'defined': True,
                'warn': res == EVAL_WARN,
                'contents': headers[header],
                'notes': notes,
            }
        else:
            warn = settings.get('recommended')
            retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

    if cors_headers:
        # cross-origin-allow-origin is a bit special as it depends on the presece of
        # the header cross-origin-allow-credentials
        res, notes = eval_cors(cors_headers)
        retval['access-control-allow-origin'] = {
            'defined': cors_headers.get('access-control-allow-origin') is not None,
            'warn': res == EVAL_WARN,
            'contents': cors_headers.get('access-control-allow-origin'),
            'notes': notes,
        }

        for header, settings in cors_headers_mapping.items():
            if header in cors_headers:
                eval_func = settings.get('eval_func')
                if not eval_func:
                    raise SecurityHeadersException(f"No evaluation function found for header: {header}")
                res, notes = eval_func(cors_headers[header])
                retval[header] = {
                    'defined': True,
                    'warn': res == EVAL_WARN,
                    'contents': cors_headers[header],
                    'notes': notes,
                }
            else:
                warn = settings.get('recommended')
                retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

    for header in SERVER_VERSION_HEADERS:
        if header in headers:
            res, notes = eval_version_info(headers[header])
            retval[header] = {
                'defined': True,
                'warn': res == EVAL_WARN,
                'contents': headers[header],
                'notes': notes,
            }

    return retval
