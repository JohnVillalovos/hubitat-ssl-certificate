# hubitat-ssl-certificate

## Warning

After updating the certificate the Hubitat will be rebooted. This is because
the certificate doesn't become activated until after a reboot. This can be
disabled with the `--no-reboot` argument.

## Usage

This assumes in the specified certificate directory there are `fullchain.pem`
and `privkey.pem` files.

Usage:

```
$ hubitat-ssl-certificate --help
usage: hubitat-ssl-certificate [-h] [-d] [-n] [--no-reboot] -u USERNAME -p PASSWORD -f FQDN cert_dir

positional arguments:
  cert_dir

options:
  -h, --help            show this help message and exit
  -d, --debug
  -n, --dry-run
  --no-reboot           Don't reboot the Hubitat after installing the certificate
  -u, --username USERNAME
                        Username to use to login
  -p, --password PASSWORD
                        Password to use to login
  -f, --fqdn FQDN       The FQDN (Fully Qualified Domain Name) of the Hubitat. For example: hubitat.example.com

$ hubitat-ssl-certificate --username "${USERNAME}" --password "${PASSWORD}" --fqdn "${FQDN}" "${CERT_DIR}"
```

## License

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
