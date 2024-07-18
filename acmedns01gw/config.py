"""Handle configuration and configuration checks for acmegw_server"""

import argparse
from ipaddress import ip_address, ip_network
import os
from pathlib import Path

import logging

logger = logging.getLogger("config")

DEFAULT_PORT = 8000


# pylint: disable-next=missing-class-docstring
class ArgParser(argparse.ArgumentParser):

    def __init__(self):
        super().__init__()
        self.description = """Naive ACME DNS-01 web-service. Uses only Python
            standard libraries. Configurable using command-line parameters,
            environment variables or .env file."""
        self.epilog = "Make sure you read the documentation!"

        # parser = argparse.ArgumentParser("Naive ACME DNS-01 web-service")
        self.add_argument(
            "-l",
            "--listen",
            type=str,
            help="""port or IP:port to listen on. Defaults to all interfaces,
                 ip-addresses and port 8000""",
        )
        self.add_argument(
            "-e",
            "--dotenv",
            type=Path,
            default=Path("./.env"),
            help="location of .env file. Default ./.env",
        )
        self.add_argument("-m", "--dnsapi_module", type=str, help="module name, e.g. dnsapi")
        self.add_argument("-c", "--dnsapi_class", type=str, help="class name, e.g. MyDNSAPI")
        self.add_argument(
            "--ssl_cert", type=Path, default=Path("./cert.pem"), help="SSL Certificate chain"
        )
        self.add_argument(
            "--ssl_key", type=Path, default=Path("./key.pem"), help="SSL Certificate chain"
        )


class Config:
    """Commandline args, then environment, then .env file"""

    _dotenv = {}
    dnsapi_username = None
    dnsapi_password = None
    dnsapi_module = None
    dnsapi_class = None
    dnsapi_domains = None
    listen_ip = None
    listen_port = None
    ssl_cert = None
    ssl_key = None
    allowed_hosts = None
    allowed_proxies = None
    proxy_xff = None
    basic_auth = None
    issues = []
    warnings = []

    def __init__(self):
        args = ArgParser().parse_args()

        # Configure using command-line arguments
        self.dnsapi_module = args.dnsapi_module
        self.dnsapi_class = args.dnsapi_class
        self.ssl_cert = args.ssl_cert
        self.ssl_key = args.ssl_key
        if args.listen:
            (self.listen_ip, self.listen_port) = self._split_listen(args.listen)

        # Configure using either environment or .env file
        if args.dotenv:
            env_file = args.dotenv
        elif os.environ.get("DOTENV"):
            env_file = os.environ.get("DOTENV")
        else:
            env_file = Path(__file__).resolve().parent / ".env"
        self._load_dotenv(env_file)
        self.dnsapi_username = self._get("dnsapi_username", False)
        self.dnsapi_password = self._get("dnsapi_password", False)
        if not self.dnsapi_module:
            self.dnsapi_module = self._get("dnsapi_module", True)
        if not self.dnsapi_class:
            self.dnsapi_class = self._get("dnsapi_class", True)
        self.dnsapi_domains = self._get_list("dnsapi_domains", True)
        if not self.listen_port:
            (self.listen_ip, self.listen_port) = self._split_listen(self._get("listen", None))
        if not self.listen_ip:
            self.listen_ip = self._get("listen_ip", "")
        if not self.listen_port:
            self.listen_port = self._get("listen_port", DEFAULT_PORT)
        if not self.ssl_key:
            self.ssl_key = self._get("ssl_key", True)
        if not self.ssl_cert:
            self.ssl_cert = self._get("ssl_cert", True)
        self.allowed_hosts = self._get_iplist("allowed_hosts")
        if self.allowed_hosts:
            self.allowed_proxies = self._get_iplist("allowed_proxies")
            if self.allowed_proxies:
                self.proxy_xff = self._get("proxy_xff", "X-Forwarded-For")
        self.basic_auth = self._get("basic_auth")
        if "ALL_PROXY" in os.environ and not "HTTP_PROXY" in os.environ:
            os.environ["HTTP_PROXY"] = os.environ["ALL_PROXY"]
        if "ALL_PROXY" in os.environ and not "HTTPS_PROXY" in os.environ:
            os.environ["HTTPS_PROXY"] = os.environ["ALL_PROXY"]
        if not "HTTPS_PROXY" in os.environ and "ALL_PROXY" in self._dotenv:
            os.environ["HTTP_PROXY"] = self._dotenv["ALL_PROXY"]
            os.environ["HTTPS_PROXY"] = self._dotenv["ALL_PROXY"]

        # Check configuration for completeness and issues
        if self.basic_auth and self.basic_auth.lower() in ["sufficient", "required"]:
            pass
        elif not self.basic_auth or self.basic_auth.lower() in ["none", "disabled"]:
            self.basic_auth = False
        else:
            self.issues.append("basic_auth")
            logger.error('FATAL: Invalid value "%s" for "basic_auth"', self.basic_auth)
        if not self.allowed_hosts and not self.basic_auth:
            self.issues.append("allowed_hosts")
            self.issues.append("basic_auth")
            logger.error('FATAL: Must configure one or both of "allowed_hosts", "basic_auth"')
        for issue in self.issues:
            logger.error("FATAL: Variable %s not set", issue)
        for warning in self.warnings:
            logger.warning("WARNING: Variable %s not set", warning)
        if self.issues:
            raise ValueError("Configuration failed")

    def _get(self, var: str, required=None) -> str:
        """Retrieve a variable from environment of .env file

        Args:
            var (str): Variable to retrieve.
            required (any):
                True (bool): empty value adds "fatal" entry.
                False (bool): empty value adds "warning" entry.
                None: ignore empty value.
                str|int: default value to assign.

        Returns:
            str: value retrieved from environment or .env file
        """
        var = var.upper()
        value = os.environ.get(var, self._dotenv.get(var))
        if value:
            # Found the variable, return the value
            return value
        if isinstance(required, (str, int)):
            # No value found for variable, return the default value
            return required
        elif required is None:
            pass  # None is also "falsey"
        elif not required:
            self.warnings.append(var)
        elif required:
            self.issues.append(var)
        return value

    def _get_list(self, var: str, required=None) -> list:
        value = self._get(var, required)
        if not value:
            return None
        result = []
        for item in value.split(","):
            result.append(item.strip())
        return result

    def _get_iplist(self, var: str) -> list:
        # Splits a csv list of ip-addresses or networks into list of network objects
        value = self._get_list(var)
        if not value:
            return None
        result = []
        for ip in value:
            try:
                if "/" in ip:
                    result.append(ip_network(ip, strict=False))
                else:
                    result.append(ip_address(ip))
            except ValueError:
                logger.warning('"%s" is not a valid IPv4 or IPv6 address or network, ignored', ip)
        return result

    def _split_listen(self, bind):
        if not bind:
            return None, None
        listen_ip = None
        listen_port = None
        listen = bind.split(":")
        if len(listen) == 1:
            try:
                listen_port = int(listen[0])
            except ValueError:
                listen_ip = listen[0]
        elif len(listen) >= 2:
            listen_ip = listen[:-1].join(":")
            try:
                ip_address(listen_ip)
            except ValueError:
                logger.error('listen_ip "%s" is not a valid IPv4 or IPv6 address')
            listen_port = int(listen[-1])
        return listen_ip, listen_port

    def _load_dotenv(self, env_file):
        if not env_file.is_file():
            return
        with env_file.open() as f:
            for line in f:
                line.strip(" \r\n")
                if line == "" or line.strip()[0] == "#":
                    continue  # skip empty and comment lines
                parts = line.split("=", maxsplit=1)
                if len(parts) != 2:
                    continue  # skip empty lines
                value = parts[1].strip()
                if value[0] in ["'", '"'] and value[0] == value[-1]:
                    value = value[1:-1]  # Remove outer quotes
                self._dotenv.update({parts[0].strip(): value})
