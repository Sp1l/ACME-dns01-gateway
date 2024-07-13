#!/usr/bin/env python3

"""
Naive web-service for mod_md, using only standard libraries

Required configuration, via arguments, environment, .env file (in that
order of precedence. Values from DOTENV do not override args or environment).
Long arguments are lower-case, prefixed with `--`. '(n.a.)' means that this
configration is (intentionally) not available via argument.

DOTENV (-e) = Path to .env file (default ./.env).
LISTEN (-l) = IP:port, port or IP to listen on.
LISTEN_PORT (n.a.) = port to listen on (default 8000).
LISTEN_IP (n.a.) = IP-address to listen on.
DNSAPI_USERNAME (n.a.) = Username to use for authenticating to your DNS API.
DNSAPI_PASSWORD (n.a.) = Password to use for authenticating to your DNS API.
DNSAPI_MODULE (-m) = Python module to load for DNS API. 
DNSAPI_CLASS (-c) = Class in DNSAPI_MODULE to use as DNS API.
SSL_CERT (n.a.) = x509 certificate chain file for SSL
SSL_KEY (n.a.) = private key file for SSL
ALLOWED_HOSTS (n.a.) = Hosts allowed to consume the API
ALLOWED_PROXIES (n.a.) = Proxies trusted by the API
PROXY_XFF (n.a.) = X-Forwarded-For header sent by proxy (default X-Forwarded-For)
BASIC_AUTH (n.a.) = Enable basic authentication. If "required", in addition to ALLOWED_HOSTS
                    If "sufficient" either Basic auth or Allowed hosts is OK. 

When running, it will accept POST/PUT/DELETE on for any path, the payload must
be valid json:

The DNSAPI_CLASS must implement the following:

def acme_challenge(self, action: str, fqdn: str, token: str)
    Add or remove the _acme-challenge dns-01 validation token

    Args:
        action (str): 'setup' or 'teardown' the _acme-challenge RR
        fqdn (str): The Fully Qualified Domain Name 
        token (str): Content for the _acme-challenge TXT RR

The DNS API must be instantiated with a call with username and password

def __init__(self, username: str, password: str):
    Args:
        username (str): Username for DNS API
        password (str): Password for DNS API
"""

from http.server import HTTPServer
import os
from pathlib import Path
import ssl
import sys
import logging

from acmedns01gw.config import Config
from acmedns01gw.request_handler import RequestHandler

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


# pylint: disable=bare-except
if __name__ == "__main__":
    os.chdir(Path(sys.argv[0]).parent)
    try:
        config = Config()
    except:

        logger.critical("FATAL: Configuration failed")
        sys.exit(1)
    logger.info("Starting SSL listener on %s:%s", config.listen_ip, config.listen_port)
    server_address = (config.listen_ip, int(config.listen_port))
    try:
        httpd = HTTPServer(server_address, RequestHandler)
    except OSError as e:
        logger.critical("FATAL: Can't start server: %s", e)
        sys.exit(1)
    try:
        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.check_hostname = False
        context.load_cert_chain(config.ssl_cert, config.ssl_key)
        context.set_ciphers("ECDHE+AESGCM:!AES128:ECDHE+CHACHA20-POLY1305")
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    except ssl.SSLError as e:
        logger.critical("FATAL: Can't start SSL server: %s", e)
    try:
        logger.info("Server running...")
        httpd.serve_forever()
    except:  # pylint: disable=bare-except
        logger.info("Server stopped")
