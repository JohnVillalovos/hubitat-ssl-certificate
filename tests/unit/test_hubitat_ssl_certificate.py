import pathlib
import sys
from unittest import mock

import pytest
import requests

from hubitat_ssl_certificate import hubitat_ssl_certificate


@pytest.mark.parametrize("explicit_files", [False, True])
def test_parse_args_certificate_modes(
    tmp_path: pathlib.Path, explicit_files: bool
) -> None:
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("certificate", encoding="utf-8")
    key.write_text("private key", encoding="utf-8")
    options = (
        ["--cert", str(cert), "--key", str(key)] if explicit_files else [str(tmp_path)]
    )
    args = hubitat_ssl_certificate.parse_args(
        ["-u", "user", "-p", "password", "-f", "hub.example.com", *options]
    )

    assert args.cert_dir == (None if explicit_files else tmp_path)
    assert args.cert == (cert if explicit_files else None)
    assert args.key == (key if explicit_files else None)


@pytest.mark.parametrize(
    "options, message",
    [
        ([], "specify cert_dir or both --cert and --key"),
        (["--cert", "cert.pem"], "must be specified together"),
        (["--key", "key.pem"], "must be specified together"),
        (["directory", "--cert", "cert.pem", "--key", "key.pem"], "cannot be combined"),
        (["directory", "--cert", "cert.pem"], "cannot be combined"),
        (["directory", "--key", "key.pem"], "cannot be combined"),
        (["--cert"], "expected one argument"),
        (["--key"], "expected one argument"),
    ],
)
def test_parse_args_rejects_invalid_certificate_modes(
    options: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        hubitat_ssl_certificate.parse_args(
            ["-u", "user", "-p", "password", "-f", "hub.example.com", *options]
        )

    assert exc.value.code == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("argument", ["cert_dir", "--cert", "--key"])
@pytest.mark.parametrize("missing", [False, True])
def test_parse_args_rejects_invalid_paths(
    tmp_path: pathlib.Path,
    argument: str,
    missing: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid_file = tmp_path / "valid.pem"
    valid_file.write_text("content", encoding="utf-8")
    invalid_path = (
        tmp_path / "missing"
        if missing
        else (valid_file if argument == "cert_dir" else tmp_path)
    )
    if argument == "cert_dir":
        options = [str(invalid_path)]
        expected_type = "directory"
    else:
        options = [
            "--cert",
            str(invalid_path if argument == "--cert" else valid_file),
            "--key",
            str(invalid_path if argument == "--key" else valid_file),
        ]
        expected_type = "file"

    with pytest.raises(SystemExit) as exc:
        hubitat_ssl_certificate.parse_args(
            ["-u", "user", "-p", "password", "-f", "hub.example.com", *options]
        )

    assert exc.value.code == 2
    assert (
        f"{argument}: {invalid_path} is not a {expected_type}"
        in capsys.readouterr().err
    )


def test_get_private_key_from_directory(tmp_path: pathlib.Path) -> None:
    (tmp_path / "fullchain.pem").write_text("certificate content", encoding="utf-8")
    private_key = "private key content\n"
    (tmp_path / "privkey.pem").write_text(private_key, encoding="utf-8")

    assert hubitat_ssl_certificate.get_private_key(cert_dir=tmp_path) == private_key


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
