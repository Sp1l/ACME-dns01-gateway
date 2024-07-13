#!/usr/bin/env python3
"""Module to interact with OpenProvider DNS API using REST"""

# https://github.com/AntagonistHQ/openprovider.py for more detail

from datetime import datetime, timedelta, UTC
import json
from http.client import HTTPResponse
from typing import Tuple
from urllib import request
from urllib.parse import urlencode
from urllib.error import HTTPError

OPENPROVIDER_APIBASE = "https://api.openprovider.eu/v1beta"
OPENPROVIDER_LOGIN = "/auth/login"
OPENPROVIDER_TOKENTTL = 172000


class OpenProvider:
    """Add/remove DNS _acme-challenge records from OpenProvider"""

    _bearer_token = None
    _token_expires = None
    _conn = None
    _token_ttl = timedelta(seconds=OPENPROVIDER_TOKENTTL)

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def _req(
        self, api: str, method: str = None, data: dict = None, params: dict = None
    ) -> Tuple[int, dict | str]:
        """Abstract request call

        Args:
            api (str): The API to call (path after OPENPROVIDER_APIBASE)
            method (str, optional): HTTP method to use. Defaults to GET if data
                                    is None, to POST if data is not None
            data (dict, optional): Data. Defaults to None.
            params (dict, optional): Query-String parameters. Defaults to None.

        Returns:
            int : HTTP Status Code
            dict|str: Response body, dict if content-type is application/json
        """

        def get_encoding(content_type) -> str:
            if content_type:
                parts = content_type.split(";")
                if len(parts) == 1 and parts[0].lower() == "application/json":
                    return "ascii"
                for part in parts:
                    if part.strip().split["="][0].lower() == "charset":
                        return part.split["="][1].strip()
            return "utf-8"  # guess

        def process_resp(resp: HTTPResponse):
            resp_body = resp.read()
            content_type = resp.headers.get("content-type").lower()
            if content_type == "application/json":
                return resp.status, json.loads(resp_body)
            # Error returns are valid JSON, but have content-type text/plain
            return resp.status, resp_body.decode(get_encoding(content_type))

        # prepare query-string and data
        querystring = "?" + urlencode(params) if params else ""
        data = json.dumps(data).encode("ascii") if data else None

        req = request.Request(f"{OPENPROVIDER_APIBASE}{api}{querystring}", data=data, method=method)
        req.add_header("Accept", "application/json, text/plain")
        req.add_header("Content-Type", "application/json")
        if api != OPENPROVIDER_LOGIN:
            self._connect()
            req.add_header("Authorization", f"Bearer {self._bearer_token}")

        try:
            with request.urlopen(req) as resp:
                return process_resp(resp)
        except HTTPError as e:
            return process_resp(e.fp)

    def _connect(self):
        """Reuse or initialize authentication context (bearer token)"""
        timestamp = datetime.now(UTC)
        if self._bearer_token and self._token_expires > timestamp:
            return  # Re-use existing token

        # Retrieve a new bearer token
        _, response = self._req(
            OPENPROVIDER_LOGIN,
            data={"ip": "0.0.0.0", "username": self.username, "password": self.password},
        )

        if "data" in response and "token" in response["data"]:
            self._bearer_token = response["data"]["token"]
            self._token_expires = timestamp + self._token_ttl

    def _find_zone(self, fqdn: str):
        """Detect the DNS zone to modify"""
        labels = fqdn.split(".")
        while len(labels) >= 2:
            params = {"name_pattern": ".".join(labels)}
            status, response = self._req("/dns/zones", params=params)
            if "data" in response and "results" in response["data"]:
                results = response["data"]["results"]
                return status, results[0]["name"]
            labels = labels[1:]
        return 404, "Zone not found"

    def acme_challenge(self, action: str, fqdn: str, token: str):
        """Add or remove the _acme-challenge dns-01 validation token

        Args:
            action (str): 'setup'/'add' or 'teardown'/'remove' the _acme-challenge RR
            fqdn (str): The Fully Qualified Domain Name
            token (str): Content for the _acme-challenge TXT RR
        """
        action = {"setup": "add", "teardown": "remove"}.get(action, action)

        fqdn = fqdn.removeprefix("_acme-challenge.")
        status, zone_name = self._find_zone(fqdn)
        if status >= 300:
            return status, zone_name
        name = "_acme-challenge." + fqdn.removesuffix(f".{zone_name}")
        status, response = self._req(
            f"/dns/zones/{zone_name}",
            method="PUT",
            data={
                "name": zone_name,
                "records": {action: [{"name": name, "type": "TXT", "ttl": 900, "value": token}]},
            },
        )
        if "data" in response and "success" in response["data"] and response["data"]["success"]:
            print(response)
            return 201, "OK"
        else:
            return status, response


if __name__ == "__main__":
    # For testing purposes only
    import sys
    import os

    print("Use this ONLY for testing from command-line")
    dnsapi_username = os.environ["DNSAPI_USERNAME"]
    dnsapi_password = os.environ["DNSAPI_PASSWORD"]
    # action = sys.argv[1]
    # fqdn = sys.argv[2]
    # token = sys.argv[3]
    dns_api = OpenProvider(dnsapi_username, dnsapi_password)
    dns_api.acme_challenge(sys.argv[1], sys.argv[2], sys.argv[3])
