import argparse
import asyncio
import json
import sys


from . import cmd_utils
from .exceptions import SecurityHeadersException, FailedToFetchHeaders
from .securityheaders import SecurityHeaders


def main():
    parser = argparse.ArgumentParser(description='Scan HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', nargs='?', default=None, type=str, help='Target URL')
    parser.add_argument('--target-list', dest='target_list', metavar='FILE', default=None, type=str,
                        help='Input from list of target URLs')
    parser.add_argument('--max-redirects', dest='max_redirects', metavar='N', default=2, type=int,
                        help='Max redirects, set 0 to disable')
    parser.add_argument('--insecure', dest='insecure', action='store_true',
                        help='Do not verify TLS certificate chain')
    parser.add_argument('--json', dest='json', action='store_true', help='JSON output instead of text')
    parser.add_argument('--no-color', dest='no_color', action='store_true', help='Do not output colors in terminal')
    parser.add_argument('--verbose', '-v', dest='verbose', action='store_true',
                        help='Verbose output')
    args = parser.parse_args()

    if not args.url and not args.target_list:
        print("No target url provided.", file=sys.stderr)
        parser.print_usage(sys.stderr)
        sys.exit(1)

    target_list = []
    if args.target_list:
        with open(args.target_list, encoding='utf-8') as file:
            target_list = [line.rstrip() for line in file]
    if args.url:
        target_list.append(args.url)

    target_list = list(set(target_list))  # Remove possible duplicates

    if args.url:

        try:
            res = scan_target(args.url, args)
        except SecurityHeadersException as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        if args.json:
            print(json.dumps(res))
        else:
            print(cmd_utils.output_text(res['target'], res['headers'], res['https'], args.no_color, args.verbose))
    elif args.target_list:
        asyncio.run(scan_multiple_targets(args))


def async_scan_done(scan):
    try:
        res, args = scan.result()
        print(cmd_utils.output_text(res['target'], res['headers'], res['https'], args.no_color, args.verbose))
    except SecurityHeadersException as e:
        print(e, file=sys.stderr)


def scan_target(url, args):
    try:
        header_check = SecurityHeaders(url, args.max_redirects, args.insecure)
        header_check.fetch_headers()
        headers = header_check.check_headers()
    except SecurityHeadersException as e:
        raise e

    if not headers:
        raise FailedToFetchHeaders("Failed to fetch headers")

    https = header_check.test_https()
    return {'target': header_check.get_full_url(), 'headers': headers, 'https': https}


def scan_target_wrapper(url, args):
    # A bit of a dirty hack to pass args to the done callback
    return scan_target(url, args), args


async def scan_multiple_targets(args):
    with open(args.target_list, encoding='utf-8') as file:
        targets = [line.rstrip() for line in file]

    loop = asyncio.get_event_loop()
    tasks = []
    for target in targets:
        if args.json:
            task = loop.run_in_executor(None, scan_target, target, args)
        else:
            task = loop.run_in_executor(None, scan_target_wrapper, target, args)
            task.add_done_callback(async_scan_done)
        tasks.append(task)

    res = []
    for task in tasks:
        await task

    if args.json:
        for t in tasks:
            res.append(t.result())

        print(str(res))

if __name__ == "__main__":
    main()
