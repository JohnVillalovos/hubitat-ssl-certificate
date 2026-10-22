#!/usr/bin/python3 -ttu
# vim: ai ts=4 sts=4 et sw=4

# Copyright (c) 2024, 2025, 2026 John L. Villalovos
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.


import argparse
import dataclasses
import http.client
import logging
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
            if not hubitat.enable_ssl(certificate=certificate, private_key=private_key):
                return 1
            if not hubitat.reboot(no_reboot=args.no_reboot):
                return 1
        else:
            print("An error occurred when attempting to update the certificate")
            return 1
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
    # Legacy save also enables SSL, so skip the separate enable request afterward.
    _legacy_save_enabled_ssl: bool = dataclasses.field(init=False, default=False)
    session: requests.Session = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        urllib3.disable_warnings()
        assert ":" not in self.fqdn, f"{self.fqdn!r} does not appear to be a FQDN"
        assert "/" not in self.fqdn, f"{self.fqdn!r} does not appear to be a FQDN"
        self._base_url = f"https://{self.fqdn}/"

    def login(self) -> None:
        login_url = urllib.parse.urljoin(base=self._base_url, url="login")

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
        self._legacy_save_enabled_ssl = False
        cert_config_url = urllib.parse.urljoin(
            base=self._base_url, url="hub/advanced/certificate/saveJson"
        )
        data = {
            "certificate": certificate.replace("\n", "\r\n"),
            "privateKey": private_key.replace("\n", "\r\n"),
        }
        if self.debug:
            pprint.pprint(data)
        result = self.session.request(method="POST", url=cert_config_url, data=data)
        if result.status_code in (404, 405):
            print("Certificate upload endpoint unavailable; trying legacy save.")
            return self._save_certificate_legacy(
                certificate=certificate, private_key=private_key
            )
        if self.debug:
            print("POST:", result)
            print(result.text)
            print("POST:", result)
        if result.status_code == 200:
            print("Certificate updated successfully.")
            return True
        print("POST:", result)
        print(result.text)
        print("POST:", result)
        print()
        print("ERROR: Failed to update the certificate")
        return False

    def _save_certificate_legacy(self, *, certificate: str, private_key: str) -> bool:
        assert self.logged_in, "Must be logged in"
        url = urllib.parse.urljoin(self._base_url, "hub/advanced/certificate/save")
        data = {
            "certificate": certificate.replace("\n", "\r\n"),
            "privateKey": private_key.replace("\n", "\r\n"),
            "toggleSSLEnableFlag": "on",
            "_action_update": "Save key pair",
        }
        result = self.session.request(method="POST", url=url, data=data)
        if self.debug or result.status_code != 200:
            print("POST:", result)
            print(result.text)
        self._legacy_save_enabled_ssl = result.status_code == 200
        if self._legacy_save_enabled_ssl:
            print("Certificate updated and SSL enabled using legacy save.")
            return True
        print("ERROR: Failed to save certificate and enable SSL using legacy save")
        return False

    def enable_ssl(self, *, certificate: str, private_key: str) -> bool:
        assert self.logged_in, "Must be logged in"
        if self._legacy_save_enabled_ssl:
            return True
        cert_config_url = urllib.parse.urljoin(
            base=self._base_url, url="hub/toggleUISSLEnabled"
        )
        payload = {"toggleSSLEnableFlag": True}
        result = self.session.request(method="POST", url=cert_config_url, json=payload)
        if result.status_code in (404, 405):
            print("SSL enablement endpoint unavailable; trying legacy save.")
            return self._save_certificate_legacy(
                certificate=certificate, private_key=private_key
            )
        if self.debug or result.status_code != 200:
            print("POST:", result)
            print(result.text)
        if result.status_code == 200:
            print("SSL enabled successfully.")
            return True
        print("ERROR: Failed to enable ssl")
        return False

    def reboot(self, *, no_reboot: bool) -> bool:
        assert self.logged_in, "Must be logged in"
        if no_reboot:
            print(
                "--no-reboot specified. The Hubitat device was not automatically "
                "rebooted."
            )
            print("Please reboot the Hubitat device")
            return True
        reboot_url = urllib.parse.urljoin(base=self._base_url, url="hub/reboot")
        payload = {"rebuildDatabase": False, "purgeLogs": False}
        result = self.session.request(method="POST", url=reboot_url, json=payload)
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
    no_reboot: bool
    password: str
    username: str


def parse_args() -> ProgramArgs:
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-n", "--dry-run", action="store_true")
    parser.add_argument(
        "--no-reboot",
        action="store_true",
        help="Don't reboot the Hubitat after installing the certificate",
    )
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
