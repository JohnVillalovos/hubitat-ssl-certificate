# hubitat-ssl-certificate

This assumes in the specified certificate directory there are `fullchain.pem`
and `privkey.pem` files.

Usage:

```
$ hubitat-ssl-certificate --help
usage: hubitat-ssl-certificate [-h] [-d] [-n] -u USERNAME -p PASSWORD -f FQDN cert_dir

positional arguments:
  cert_dir

options:
  -h, --help            show this help message and exit
  -d, --debug
  -n, --dry-run
  -u, --username USERNAME
                        Username to use to login
  -p, --password PASSWORD
                        Password to use to login
  -f, --fqdn FQDN       The FQDN (Fully Qualified Domain Name) of the Hubitat. For example: hubitat.example.com

$ hubitat-ssl-certificate --username "${USERNAME}" --password "${PASSWORD}" --fqdn "${FQDN}" "${CERT_DIR}"
```


