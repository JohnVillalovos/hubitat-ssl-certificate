# hubitat-ssl-certificate

This assumes in the specified certificate directory there are `fullchain.pem`
and `privkey.pem` files.

Usage:

hubitat-ssl-certificate --username "${USERNAME}" --password "${PASSWORD}" --fqdn "${FQDN}" "${CERT_DIR}"
