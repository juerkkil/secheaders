# secheaders
Python script to check HTTP security headers


Same functionality as securityheaders.io but as Python script. Also checks some server/version headers. Written and tested using Python 3.8.

With minor modifications could be used as a library for other projects.

**NOTE**: The project renamed (2024-10-19) from **securityheaders** to **secheaders** to avoid confusion with PyPI package with similar name.

## Installation

The following assumes you have Python  installed and command `python` refers to python version >= 3.8.

### Install

```
$ pip install secheaders
```

### Building and running locally

1. Clone into repository
2. `python -m build`
3. `pip install dist/secheaders-0.1.1-py3-none-any.whl`
4. Run `secheaders --help`


### Running from source without installation

1. Clone into repository
2. Run `python -m secheaders`


## Usage
```
$ secheaders --help
usage: secheaders [-h] [--max-redirects N] [--insecure] [--json] [--no-color]
                  [--verbose]
                  URL

Scan HTTP security headers

positional arguments:
  URL                Target URL

options:
  -h, --help         show this help message and exit
  --max-redirects N  Max redirects, set 0 to disable (default: 2)
  --insecure         Do not verify TLS certificate chain (default: False)
  --json             JSON output instead of text (default: False)
  --no-color         Do not output colors in terminal (default: False)
  --verbose, -v      Verbose output (default: False)
```


## Example output
```
$ secheaders example.com
Header 'x-frame-options' is missing                                   [ WARN ]
Header 'strict-transport-security' is missing                         [ WARN ]
Header 'content-security-policy' is missing                           [ WARN ]
Header 'x-content-type-options' is missing                            [ WARN ]
Header 'x-xss-protection' is missing                                   [ OK ]
Header 'referrer-policy' is missing                                   [ WARN ]
Header 'permissions-policy' is missing                                [ WARN ]
server: ECAcc (nyd/D147)                                              [ WARN ]
HTTPS supported                                                        [ OK ]
HTTPS valid certificate                                                [ OK ]
HTTP -> HTTPS automatic redirect                                      [ WARN ]
```

## Design principles

The following design principles have been considered:

* Simplicity of the codebase. 
	* The code should be easy to understand and follow without in-depth Python knowledge.
* Avoidance of external dependencies.
	* The Python Standard Libary provides enough tools and libraries for quite many use cases.
* Unix philosophy in general 
	* *"Do one thing and do it well"*

These are not rules set in stone, but should be revisited when doing big design choices.
