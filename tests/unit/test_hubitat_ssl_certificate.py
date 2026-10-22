import pathlib
import sys
from unittest import mock

import pytest
import requests

from hubitat_ssl_certificate import hubitat_ssl_certificate


def test_main_returns_failure_when_ssl_enablement_fails(tmp_path: pathlib.Path) -> None:
    (tmp_path / "fullchain.pem").write_text("certificate", encoding="utf-8")
    (tmp_path / "privkey.pem").write_text("private key", encoding="utf-8")
    argv = [
        "hubitat-ssl-certificate",
        "-u",
        "user",
        "-p",
        "password",
        "-f",
        "hubitat.example.com",
        str(tmp_path),
    ]
    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(
            hubitat_ssl_certificate, "Hubitat", autospec=True
        ) as mock_hubitat,
    ):
        hubitat = mock_hubitat.return_value
        hubitat.update_certificate.return_value = True
        hubitat.enable_ssl.return_value = False

        assert hubitat_ssl_certificate.main() == 1

    hubitat.enable_ssl.assert_called_once_with(
        certificate="certificate", private_key="private key"
    )
    hubitat.reboot.assert_not_called()


def test_enable_ssl_with_debug() -> None:
    hubitat = hubitat_ssl_certificate.Hubitat(
        fqdn="hubitat.example.com", username="user", password="password", debug=True
    )
    hubitat.logged_in = True
    response = mock.Mock(spec=requests.Response, status_code=200, text="OK")

    with mock.patch.object(
        hubitat.session, "request", return_value=response
    ) as mock_request:
        assert hubitat.enable_ssl(certificate="certificate", private_key="private key")

    mock_request.assert_called_once_with(
        method="POST",
        url="https://hubitat.example.com/hub/toggleUISSLEnabled",
        json={"toggleSSLEnableFlag": True},
    )


@pytest.mark.parametrize("unsupported_status", [404, 405])
@pytest.mark.parametrize("legacy_status", [200, 500])
@pytest.mark.parametrize("unsupported_step", ["upload", "enable"])
def test_legacy_certificate_fallback(
    unsupported_status: int, legacy_status: int, unsupported_step: str
) -> None:
    hubitat = hubitat_ssl_certificate.Hubitat(
        fqdn="hubitat.example.com", username="user", password="password"
    )
    hubitat.logged_in = True
    statuses = [unsupported_status, legacy_status]
    if unsupported_step == "enable":
        statuses.insert(0, 200)
    responses = [
        mock.Mock(spec=requests.Response, status_code=status, text="response")
        for status in statuses
    ]
    certificate, private_key = "certificate\n", "private key\n"
    with mock.patch.object(
        hubitat.session, "request", side_effect=responses
    ) as request:
        updated = hubitat.update_certificate(
            certificate=certificate, private_key=private_key
        )
        if updated:
            enabled = hubitat.enable_ssl(
                certificate=certificate, private_key=private_key
            )
        else:
            enabled = False

    assert enabled == (legacy_status == 200)
    expected_calls = [
        mock.call(
            method="POST",
            url="https://hubitat.example.com/hub/advanced/certificate/saveJson",
            data={"certificate": "certificate\r\n", "privateKey": "private key\r\n"},
        )
    ]
    if unsupported_step == "enable":
        expected_calls.append(
            mock.call(
                method="POST",
                url="https://hubitat.example.com/hub/toggleUISSLEnabled",
                json={"toggleSSLEnableFlag": True},
            )
        )
    expected_calls.append(
        mock.call(
            method="POST",
            url="https://hubitat.example.com/hub/advanced/certificate/save",
            data={
                "certificate": "certificate\r\n",
                "privateKey": "private key\r\n",
                "toggleSSLEnableFlag": "on",
                "_action_update": "Save key pair",
            },
        )
    )
    assert request.call_args_list == expected_calls


@pytest.mark.parametrize("status", [200, 400, 401, 403, 500])
@pytest.mark.parametrize("method", ["update_certificate", "enable_ssl"])
def test_no_legacy_fallback_for_supported_endpoints(status: int, method: str) -> None:
    hubitat = hubitat_ssl_certificate.Hubitat(
        fqdn="hubitat.example.com", username="user", password="password"
    )
    hubitat.logged_in = True
    response = mock.Mock(spec=requests.Response, status_code=status, text="response")
    with mock.patch.object(
        hubitat.session, "request", return_value=response
    ) as request:
        result = getattr(hubitat, method)(
            certificate="certificate", private_key="private key"
        )
    assert result == (status == 200)
    request.assert_called_once()


def test_reboot_sends_json_payload() -> None:
    hubitat = hubitat_ssl_certificate.Hubitat(
        fqdn="hubitat.example.com", username="user", password="password"
    )
    hubitat.logged_in = True
    response = requests.Response()
    response.status_code = 200

    with mock.patch.object(
        hubitat.session, "request", return_value=response
    ) as mock_request:
        assert hubitat.reboot(no_reboot=False)

    mock_request.assert_called_once_with(
        method="POST",
        url="https://hubitat.example.com/hub/reboot",
        json={"rebuildDatabase": False, "purgeLogs": False},
    )


def test_reboot_with_no_reboot() -> None:
    hubitat = hubitat_ssl_certificate.Hubitat(
        fqdn="hubitat.example.com", username="user", password="password"
    )
    hubitat.logged_in = True

    with mock.patch.object(hubitat.session, "request") as mock_request:
        assert hubitat.reboot(no_reboot=True)

    mock_request.assert_not_called()
