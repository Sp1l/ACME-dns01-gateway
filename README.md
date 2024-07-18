# ACME dns-01 gateway

Intentially naive "pip-less" web-service shim to add/remove
`_acme-challenge` TXT DNS resource records to your DNS service. Minimal
requirements, all part of a standard Python install.

Built to accompany Apache's `mod_md` and run in a FreeBSD jail (or your
container flavour-du-jour). Thus it uses "setup" and "teardown" for the action.
There's no reason this couldn't be made to work with any other client via
a curl script.

Uses a "bring-your-own" DNS modification python script. An example
implementation script (no pip requirements) can be found in this repo's
`providers/openprovider.py` file.

## Why?

I don't like to have credentials to my complete DNS zone in my web-server jail.
This setup separates the account credentials and will only add/remove
`_acme-challenge` records.

This setup also allows creating a single service/server that can manage the
dns-01 challenge creation and removal for many web-servers.

### Threat model

An attacker adding a spurious `_acme-challenge` notification, that's bad enough
but they'll have to do very fancy stuff to Man-in-the-Middle the connections to
your webserver, especially so if you're domain is DNSSEC protected.

An attacker with full control over your DNS records? That's **pants-on-fire**
bad! They'll have no issue MitM-ing all your traffic.

## Usage

1. Clone this repo.
1. Create DNS API implementation
1. Create configuration
1. Run `acmegw_server.py`, it will sit there and listen.

Use `daemon` on FreeBSD to run it in background from an `rc.d` script.
(A `systemd` unit on Linux?)

### Configuration

The webservice and the DNS API can be configured using (in decreasing
precedence):

1. Command-line arguments (long and short): unless long option listed in the
   table below, it is the lower-case of the variable.
2. Environment variables: only upper-case, verbatim (NOTE: watch out with
   quoting)
3. A `.env` file: format `variable = value`, variable will be converted to
   upper-case. Last entry in the file takes precedence.

| Variable | arg | env | .env | Default | Description |
| ---      |:---:|:---:|:---:| --- | --- |
| `DOTENV`   | -e  | ✓ | ✗ | `./.env`  | Path to .env file |
| `LISTEN`   | -l  | ✓ | ✓ | *:8000 | IP:port, port or IP to listen on |
| `LISTEN_PORT` | ✗ | ✓ | ✓ | 8000 | port to listen on |
| `LISTEN_IP` | ✗ | ✓ | ✓ | * | IP-address to listen on |
| `DNSAPI_USERNAME` | ✗ | ✓ | ✓ | | Username for DNS API |
| `DNSAPI_PASSWORD` | ✗ | ✓ | ✓ | | Password  DNS API |
| `DNSAPI_MODULE` | -m | ✓ | ✓ | Error | Python module to load for DNSAPI |
| `DNSAPI_CLASS` | -c | ✓ | ✓ | Error | Class in `DNSAPI_MODULE` to use as DNSAPI |
| `DNSAPI_DOMAINS`<sup>1</sup> | ✗ | ✓ | ✓ | Error | List of (Sub-)Domains manageable via API |
| `ALL_PROXY`<sup>2</sup> | ✗ | ✗ | ✓ | None | Forward proxy to use for providers |
| `SSL_CERT` | ✗ | ✓ | ✓ | cert.pem | Path to SSL certificate file |
| `SSL_KEY`  | ✗| ✓ | ✓ | key.pem | Path to SSL key file |
| `BASIC_AUTH`<sup>3</sup> | ✗ | ✓ | ✓ | None | Enable Basic authentication on API |
| `ALLOWED_HOSTS`<sup>1,3</sup> | ✗ | ✓ | ✓ | None | List of remote IP's/networks allowed to use API |
| `ALLOWED_PROXIES`<sup>1,4</sup> | ✗ | ✓ | ✓ | None | List of remote IP's/networks allowed to set XFF header |
| `PROXY_XFF`<sup>3</sup> | ✗ | ✓ | ✓ | X-Forwarded-For | XFF header to use |

Note <sup>1</sup>: Lists are comma-separated<br/>
Note <sup>2</sup>: Uses standard proxy environment variables (`ALL_PROXY`,
`HTTPS_PROXY`). If these are not set in environment, use `ALL_PROXY` from
`.env` as `HTTP_PROXY` and `HTTPS_PROXY` value.<br/>
Note <sup>3</sup>: One of `BASIC_AUTH` or `ALLOWED_HOSTS` must be set, both may
be set. See "API Authentication"<br/>
Note <sup>4</sup>: Only relevant if `ALLOWED_HOSTS` is set.

#### `.env` file parsing

1. Lines staring with "#", with optional leading whitespace, will be ignored.
2. Trailing comments are **not** ignored! `VAR = value # comment` will assign
   `value # comment` to `VAR`.
3. Whitespace around the "=" sign will be removed, as will leading and trailing
   whitespace of the variable and the value.
4. Either single- (') or double- (") quotes work.
5. Variables are case-insensitive (values are **not**!).

#### API Authentication

The `BASIC_AUTH` parameter and `ALLOWED_HOSTS` interact following setting of
`BASIC_AUTH`:

1. Not configured, empty, "none" or "disabled": Basic authentication disabled.
2. "sufficient": Either a matching username and password, or a matching host is sufficient for auth (if configured).
3. "required": A matching username and password is required, in addition to matching host (if configured).

### Apache `mod_md` configuration

See [mod_md documentation](https://httpd.apache.org/docs/2.4/mod/mod_md.htm)

```apache
MDChallengeDns01Version 2
MDChallengeDns01 /path/to/wrapper.sh
```

Example `/path/to/wrapper.sh`. Make sure it is executable!

```sh
!/bin/sh

printf '{"argument": "%s", "domain_name": "%s", "challenge_content": "%s"}' \
    "$1" "$2" "$3" \
    | curl http://dns01gw.example.org:8017/ -X POST --data @-
```

**NOTE**: Working with JSON in shell scripts is a real pain with quoting and
especially with spaces. This part of the reason this is implemented in Python.

## ACME DNS-01 API

Payload must be valid json and conform to the `mod_md` naming of the arguments.

```json
{
    "argument": "setup|add|teardown|remove",
    "domain_name": "fully.qualified.example.com",
    "challenge_content": "abcdef123456790" 
}
```

Nothing more, nothing less.

## DNS Provider script

The server will dynamically import your DNS API script as specified by the
`DNSAPI_MODULE` and `DNSAPI_CLASS` configuration.

Your `DNSAPI_CLASS **must** implement the following method: 

```python
class MyDNSProvider():
    def acme_challenge(self, action: str, fqdn: str, token: str):
        """Add or remove the _acme-challenge dns-01 validation token

        Args:
            action (str): 'setup' or 'teardown' 
            fqdn (str): The Fully Qualified Domain Name, includes `_acme-challenge` prefix 
            token (str): Content for the `_acme-challenge` TXT RR
        """
```

Check out the `providers\openprovider.py` example.

# Resources

Python examples for various DNS providers can be found in e.g.
[certbot's repo](https://github.com/certbot/certbot/), in the `certbot-dns-*`
directories.
Shell-script examples can be found in e.g. [acme.sh](https://acme.sh)'s repo
[dnsapi dir](https://github.com/acmesh-official/acme.sh/tree/master/dnsapi).
>>>>>>> 12583ee (First barely working alpha release)
