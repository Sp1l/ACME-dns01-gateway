"""Processor of inbound HTTP requests"""

from base64 import b64decode
from http.server import BaseHTTPRequestHandler
from ipaddress import ip_address, IPv4Address, IPv6Address, IPv4Network, IPv6Network
import json
import logging
import sys

from acmedns01gw.config import Config
from acmedns01gw.modmd_msg import ModMDMsg
from acmedns01gw.passwd import check_password

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

config = Config()

try:
    module = __import__(config.dnsapi_module, fromlist=[config.dnsapi_class])
    DNSAPI = getattr(module, config.dnsapi_class)
except:  # pylint: disable=bare-except
    logger.critical(
        "FATAL: Can't load class %s from %s",
        config.dnsapi_class,
        config.dnsapi_module,
    )
    sys.exit(1)

dns_api = DNSAPI(config.dnsapi_username, config.dnsapi_password)


class RequestHandler(BaseHTTPRequestHandler):
    """Naive request processor"""

    _user = ""
    _remote_ip = ""

    def check_remoteip(self):
        """Check if calling IP is allowed

        Returns:
            bool: Success or failure
            message: Descriptive message
        """

        def compare(remote, allow):
            return (isinstance(allow, (IPv4Address, IPv6Address)) and remote == allow) or (
                isinstance(allow, (IPv4Network, IPv6Network)) and remote in allow
            )

        message = ""
        if not config.allowed_hosts:
            return True, message
        if config.proxy_xff:
            forwarded_for = self.headers.get(config.proxy_xff)
        if config.allowed_proxies and forwarded_for:
            for proxy in config.allowed_proxies:
                if compare(self._remote_ip, proxy):
                    self._remote_ip = ip_address(forwarded_for)
                    message = " via " + config.proxy_xff
                    break
        for allowed_host in config.allowed_hosts:
            if compare(self._remote_ip, allowed_host):
                return True, f"{self._remote_ip} authorized{message}"
        return False, "Host not authorized"

    def check_basic_auth(self):
        if not config.basic_auth:
            return True, ""
        auth_header = self.headers.get("authorization")
        if not auth_header or auth_header[:6] != "Basic ":
            return False, '"Authorization: Basic" header missing'
        auth_header = b64decode(auth_header[6:])
        [self._user, password] = auth_header.decode().split(":")
        if check_password(self._user, password):
            return True, f'"{self._user}" password OK'
        else:
            return False, f'"{self._user}" password failed'

    def authorize(self) -> bool:
        host_allowed, host_message = self.check_remoteip()
        user_authorized, user_message = self.check_basic_auth()
        if config.basic_auth == "sufficient" and user_authorized:
            return True, user_message
        elif config.basic_auth == "sufficient" and not user_authorized and host_allowed:
            return True, f"{host_message} (password failed but host sufficient)"
        elif config.basic_auth == "required" and user_authorized and host_allowed:
            return True, f"{user_message}, {host_message}"
        elif not config.basic_auth and host_allowed:
            return True, host_message
        return False, f"{user_message}, {host_message}".strip(", ")

    def respond(self, code: int = 200, message: str = None):
        """Generate the response"""
        if code >= 400:
            self.send_error(code, explain=message)
            return
        self.send_response(code)
        if message:
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(bytes(message, "utf-8"))
            self.wfile.flush()
            self.wfile.close()
            logger.info("")

    def process_request(self, method: str):
        """Process the received request"""
        print(f"Here we {method}!")
        self._remote_ip = ip_address(self.client_address[0])
        authorized, message = self.authorize()
        if not authorized:
            logger.error("Authorization failed: %s", message)
            return self.respond(401, message)
        else:
            logger.info("Request authorized: %s", message)
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            logger.error("Missing request body from %s", self._remote_ip)
            return self.respond(400, "Missing request body")
        try:
            payload = json.loads(self.rfile.read(content_length))
        except json.JSONDecodeError as exc:
            logger.error("Request body JSON parse error: %s from %s", exc, self._remote_ip)
            return self.respond(400, f"JSON parse error: {exc}")
        try:
            dns_01 = ModMDMsg(payload)
        except KeyError as exc:
            return self.respond(400, f"Message missing required parameter {exc}, check docs")
        except ValueError as exc:
            return self.respond(400, str(exc))
        domain_match = False
        for domain in config.dnsapi_domains:
            if domain == dns_01.fqdn[-len(domain) :]:
                logger.info('"%s" matches "%s" from %s',
                    dns_01.fqdn, config.dnsapi_domains, self._remote_ip)
                domain_match = True
        if not domain_match:
            logger.error('"%s" does not match %s from %s',
                dns_01.fqdn, config.dnsapi_domains, self._remote_ip)
            return self.respond(403, f'"{dns_01.fqdn}" does not match {config.dnsapi_domains}')
        if method == "DELETE" and dns_01.action != "teardown":
            logger.error('"%s" action with DELETE method from %s', dns_01.action, self._remote_ip)
            return self.respond(400, "DELETE method only supports 'teardown' argument")
        logger.debug("dns-01 message: %s from %s", dns_01, self._remote_ip)

        status, message = dns_api.acme_challenge(dns_01.action, dns_01.fqdn, dns_01.token)
        return self.respond(status, message)

    # pylint: disable-next=invalid-name,missing-function-docstring
    def do_GET(self):
        return self.respond(405, "Only PUT and DELETE methods supported")

    # pylint: disable-next=invalid-name,missing-function-docstring
    def do_POST(self):
        return self.process_request("POST")

    # pylint: disable-next=invalid-name,missing-function-docstring
    def do_PUT(self):
        return self.process_request("PUT")

    # pylint: disable-next=invalid-name,missing-function-docstring
    def do_DELETE(self):
        return self.process_request("DELETE")
