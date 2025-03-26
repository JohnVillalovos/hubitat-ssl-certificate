#!/usr/bin/python3 -ttu
# vim: ai ts=4 sts=4 et sw=4

# Copyright (c) 2024 John L. Villalovos
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import argparse
import dataclasses
import http.client
import logging
import os
import pathlib
import pprint
import sys
from typing import Any
import urllib.parse

import requests
import urllib3


def main() -> int:
    args = parse_args()
    if args.debug:
        print(args)
        enable_debug()

    certificate = get_certificate(cert_dir=args.cert_dir)
    private_key = get_private_key(cert_dir=args.cert_dir)
    hubitat = Hubitat(
        fqdn=args.fqdn, username=args.username, password=args.password, debug=args.debug
    )
    hubitat.login()

    if not args.dry_run:
        if hubitat.update_certificate(certificate=certificate, private_key=private_key):
            hubitat.reboot()
    else:
        print("--dry-run specified. Will not update certificate")

    return 0


def get_certificate(*, cert_dir: pathlib.Path) -> str:
    assert cert_dir.is_dir()
    with open(cert_dir / "fullchain.pem", "r", encoding="utf-8") as in_file:
        content = in_file.read()
    return content


def get_private_key(*, cert_dir: pathlib.Path) -> str:
    assert cert_dir.is_dir()
    with open(cert_dir / "privkey.pem", "r", encoding="utf-8") as in_file:
        content = in_file.read()
    return content


@dataclasses.dataclass(kw_only=True)
class Hubitat:
    fqdn: str
    username: str
    password: str
    debug: bool = False
    _base_url: str = dataclasses.field(init=False)
    logged_in: bool = dataclasses.field(init=False, default=False)
    session: requests.Session = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        urllib3.disable_warnings()
        assert ":" not in self.fqdn, f"{self.fqdn!r} does not appear to be a FQDN"
        assert "/" not in self.fqdn, f"{self.fqdn!r} does not appear to be a FQDN"
        self._base_url = f"https://{self.fqdn}/"

    def login(self) -> None:
        login_url = os.path.join(self._base_url, "login")

        data = {"username": self.username, "password": self.password, "submit": "Login"}
        if self.debug:
            print()
            pprint.pprint(data)
        result = self.session.request(method="GET", url=login_url)
        if self.debug:
            print("GET:", result)
            pprint.pprint(result.cookies.get_dict())
            print()
            print("#" * 100)
        result = self.session.request(method="POST", url=login_url, data=data)
        if self.debug:
            print("POST:", result)
            print(result.content.decode())
            print()
            print("POST:", result)
            print(result.headers)
            print("URL:", result.url)
            print()
        parsed_url = urllib.parse.urlsplit(url=result.url)
        if self.debug:
            print(f"{parsed_url=}")
        if parsed_url.path != "/":
            raise ValueError(f"Failed to login to {login_url!r}")
        self.logged_in = True
        print(f"Logged into {login_url!r}")

    def update_certificate(self, *, certificate: str, private_key: str) -> bool:
        assert self.logged_in, "Must be logged in"
        cert_config_url = os.path.join(
            self._base_url, "hub", "advanced", "certificate", "save"
        )
        data = {
            "certificate": certificate.replace("\n", "\r\n"),
            "privateKey": private_key.replace("\n", "\r\n"),
            "toggleSSLEnableFlag": "on",
            "_action_update": "Save key pair",
        }
        if self.debug:
            pprint.pprint(data)
        result = self.session.request(method="POST", url=cert_config_url, data=data)
        if self.debug:
            print("POST:", result)
            print(result.text)
            print("POST:", result)
        if result.status_code == 200:
            print("Certificate updated successfully. Please reboot the Hubitat device")
            return True
        print("POST:", result)
        print(result.text)
        print("POST:", result)
        print()
        print("ERROR: Failed to update the certificate")
        return False

    def reboot(self) -> bool:
        assert self.logged_in, "Must be logged in"
        reboot_url = os.path.join(self._base_url, "hub", "reboot")
        data = {"rebuildDatabase": False, "purgeLogs": False}
        result = self.session.request(method="POST", url=reboot_url, data=data)
        if result.status_code == 200:
            print(f"{self.fqdn!r} has been rebooted")
            return True
        print("POST:", result)
        print(result.text)
        print(f"Failed to reboot {self.fqdn!r}")
        return False


def enable_debug() -> None:

    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    httpclient_log = logging.getLogger("http.client")
    httpclient_log.propagate = True
    httpclient_log.setLevel(logging.DEBUG)

    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

    # shadow http.client prints to log()
    # https://stackoverflow.com/a/16337639
    def print_as_log(*args: Any) -> None:
        httpclient_log.log(logging.DEBUG, " ".join(args))

    setattr(http.client, "print", print_as_log)


@dataclasses.dataclass(kw_only=True)
class ProgramArgs:
    cert_dir: pathlib.Path
    debug: bool
    dry_run: bool
    fqdn: str
    password: str
    username: str


def parse_args() -> ProgramArgs:
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-n", "--dry-run", action="store_true")
    parser.add_argument(
        "-u", "--username", help="Username to use to login", required=True
    )
    parser.add_argument(
        "-p", "--password", help="Password to use to login", required=True
    )
    parser.add_argument(
        "-f",
        "--fqdn",
        help=(
            "The FQDN (Fully Qualified Domain Name) of the Hubitat. "
            "For example: hubitat.example.com"
        ),
        required=True,
    )
    parser.add_argument("cert_dir")

    args = parser.parse_args()
    args.cert_dir = pathlib.Path(args.cert_dir).expanduser().resolve()
    assert args.cert_dir.is_dir(), f"{args.cert_dir} is not a directory"
    return ProgramArgs(**vars(args))


if "__main__" == __name__:
    sys.exit(main())
