import argparse
import asyncio
import json
import sys


from . import cmd_utils
from .exceptions import SecurityHeadersException, FailedToFetchHeaders
from .utils import analyze_headers
from .webclient import WebClient


def main():
    parser = argparse.ArgumentParser(description='Scan HTTP security headers',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('url', metavar='URL', nargs='?', default=None, type=str, help='Target URL')
    parser.add_argument('--target-list', dest='target_list', metavar='FILE', default=None, type=str,
                        help='Read multiple target URLs from a file and scan them all')
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
    res, args = scan.result()
    if 'error' in res:
        print(f"Scanning target {res['target']}...")
        print(f"Error: {res['error']}\n")
    else:
        print(cmd_utils.output_text(res['target'], res['headers'], res['https'], args.no_color, args.verbose))


def scan_target(url, args):
    web_client = WebClient(url, args.max_redirects, args.insecure)
    headers = web_client.get_headers()
    if not headers:
        raise FailedToFetchHeaders("Failed to fetch headers")
    analysis_result = analyze_headers(headers)

    https = web_client.test_https()
    return {'target': web_client.get_full_url(), 'headers': analysis_result, 'https': https}


def scan_target_wrapper(url, args):
    try:
        # Return the args also for the callback function
        return scan_target(url, args), args
    except SecurityHeadersException as e:
        return {'target': url, 'error': str(e)}, args


async def scan_multiple_targets(args):
    with open(args.target_list, encoding='utf-8') as file:
        targets = [line.rstrip() for line in file]

    targets = list(set(targets))  # Remove possible duplicates
    loop = asyncio.get_event_loop()
    tasks = []
    for target in targets:
        task = loop.run_in_executor(None, scan_target_wrapper, target, args)
        if not args.json:
            # Output result of each scan immediately
            task.add_done_callback(async_scan_done)
        tasks.append(task)

    res = []
    for task in tasks:
        await task

    # When json output, aggregate the results and output the json dump at the end
    if args.json:
        for t in tasks:
            result, _args = t.result()
            res.append(result)

        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
