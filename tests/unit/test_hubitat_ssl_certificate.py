from unittest import mock

import requests

from hubitat_ssl_certificate import hubitat_ssl_certificate


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
