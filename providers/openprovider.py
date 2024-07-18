#!/usr/bin/env python3
"""Module to interact with OpenProvider DNS API using REST"""

# See https://github.com/AntagonistHQ/openprovider.py for more detail, esp.
# openprovider/data/exception_map.py for response code

from datetime import datetime, timedelta, UTC
import json
from http.client import HTTPResponse
from typing import Tuple
from urllib import request
import urllib.parse as urlparse
from urllib.error import HTTPError, URLError
import sys

import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)

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
        self._username = username
        self._password = password

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
                    if part.strip().split("=")[0].lower() == "charset":
                        return part.split("=")[1].strip()
            return "utf-8"  # guess

        def process_resp(resp: HTTPResponse):
            resp_body = resp.read()
            content_type = resp.headers.get("content-type").lower()
            if content_type == "application/json":
                return resp.status, json.loads(resp_body)
            # Error returns are valid JSON, but have content-type text/plain
            return resp.status, resp_body.decode(get_encoding(content_type))

        # Default methods
        if not method and not data:
            method = "GET"
        elif not method and data:
            method = "POST"

        # prepare query-string, uri and data
        params = "?" + urlparse.urlencode(params) if params else ""
        data = json.dumps(data).encode("ascii") if data else None
        uri = OPENPROVIDER_APIBASE + api + params

        req = request.Request(uri, data=data, method=method)
        req.add_header("User-Agent", "ACME-dns01-gateway/0.0.1-alpha")
        req.add_header("Accept", "application/json, text/plain")
        req.add_header("Content-Type", "application/json")
        if api != OPENPROVIDER_LOGIN:
            self._connect()
            req.add_header("Authorization", f"Bearer {self._bearer_token}")

        try:
            logger.debug('Calling %s "%s" %s %s', method, uri, data, req.header_items())
            with request.urlopen(req) as resp:
                return process_resp(resp)
        except HTTPError as e:
            return process_resp(e.fp)
        except URLError as e:
            logger.error("Calling %s failed: %s", f"{method} {uri}", e)

    def _connect(self):
        """Reuse or initialize authentication context (bearer token)"""
        timestamp = datetime.now(UTC)
        if self._bearer_token and self._token_expires > timestamp:
            return  # Re-use existing token

        logger.info("Getting new bearer token")
        # Retrieve a new bearer token
        _, response = self._req(
            OPENPROVIDER_LOGIN,
            data={"ip": "0.0.0.0", "username": self._username, "password": self._password},
        )

        if "data" in response and "token" in response["data"]:
            self._bearer_token = response["data"]["token"]
            self._token_expires = timestamp + self._token_ttl
            logger.info("Updated bearer token: valid thru %s", self._token_expires)
        else:
            logger.error("Failed to get new bearer token: response %s", response)
            sys.exit(1)

    def find_zone(self, fqdn: str):
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

    def find_record(self, zone: str, fqdn: str, rr_type: str, rr_value: str):
        status, response = self._req(
            f"/dns/zones/{zone}/records",
            params={
                "record_name_pattern": fqdn.removesuffix(zone).rstrip("."),
                "type": rr_type,
                "value_pattern": rr_value,
            },
        )
        try:
            if response["data"]["total"] == 1:
                record = response["data"]["results"].pop()
                record.pop("creation_date", None)
                record.pop("modification_date", None)
                record["name"] = record["name"].removesuffix(zone).rstrip(".")
                return 200, record
            elif response["data"]["total"] == 0:
                return 404, response
            return status, response["data"]
        except KeyError:
            return status, response

    def acme_challenge(self, action: str, fqdn: str, token: str):
        """Add or remove the _acme-challenge dns-01 validation token

        Args:
            action (str): 'setup'/'add' or 'teardown'/'remove' the _acme-challenge RR
            fqdn (str): The Fully Qualified Domain Name
            token (str): Content for the _acme-challenge TXT RR
        """
        action = {"setup": "add", "teardown": "remove"}.get(action, action)

        fqdn = fqdn.removeprefix("_acme-challenge.")
        status, zone_name = self.find_zone(fqdn)
        if status >= 300:
            return status, zone_name
        if fqdn == zone_name:
            name = "_acme-challenge"
        else:
            name = "_acme-challenge." + fqdn.removesuffix(f".{zone_name}")
        # OpenProvider quirk? TXT RR value must be double-quoted
        token = '"' + token.strip('"') + '"'
        if action == "remove":
            status, response = self.find_record(zone_name, fqdn, "TXT", token)
            if status == 200:
                record = response
            elif status == 404:
                return status, f'DNS "TXT" record for {fqdn} with value {token} not found'
            else:
                return status, response
        else:
            record = {"name": name, "type": "TXT", "ttl": 900, "value": token}
        status, response = self._req(
            f"/dns/zones/{zone_name}",
            method="PUT",
            data={"name": zone_name, "records": {action: [record]}},
        )
        if "code" in response and response["code"] in [0, 817]:
            # 0: Generic OK message
            # 817: Duplicate record, OK in our parlance
            print(response)
            return 201, "OK"
        else:
            return status, response
