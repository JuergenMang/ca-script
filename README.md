# CA-Script

This is a simple script to create a self signed CA and create/sign certificates. It uses the OpenSSL command line tool.

You can use following environment variables to set some defaults:

```sh
#CA settings
export CA_PATH="default-ca"          # CA path
export CA_DAYS="3650"                # The CA certificate lifetime in days
export CA_KEY_ALG="ec:secp384r1"     # Alg for the CA key: rsa:2048, rsa:4096, ec:prime256v1, ec:secp384r1
export CA_KEY_ENC="1"                # Set to 0 to not encrypt CA private keys

# Certificate settings
export CERT_DAYS="365"               # The certificate lifetime in days
export CERT_EXPIRE_DAYS="14"         # Remaining lifetime in days for autorenew
export CERT_KEY_ALG="ec:prime256v1"  # Alg for the certificate keys: rsa:2048, rsa:4096, ec:prime256v1, ec:secp384r1
export CERT_KEY_ENC="1"              # Set to 0 to not encrypt certificate private keys
```

The script also tries to read the `.ca-script.cnf` file in the current folter to get defaults.

```sh
# Example .ca-script.cnf that uses defaults
# CA default config
[ -n "${CA_PATH+x}" ] || CA_PATH="default-ca"
[ -n "${CA_DAYS+x}" ] || CA_DAYS=3650
[ -n "${CA_KEY_ALG+x}" ] || CA_KEY_ALG="ec:secp384r1"
[ -n "${CA_KEY_ENC+x}" ] || CA_KEY_ENC="1"

# Certificate default config
[ -n "${CERT_DAYS+x}" ] || CERT_DAYS=365
[ -n "${CERT_EXPIRE_DAYS+x}" ] || CERT_EXPIRE_DAYS=14
[ -n "${CERT_KEY_ALG+x}" ] || CERT_KEY_ALG="ec:prime256v1"
[ -n "${CERT_KEY_ENC+x}" ] || CERT_KEY_ENC="1"
```

## Multiple CA's

Simply use a different `CA_PATH` to manage multiple CA's with this script.

## Key encryption

In the default config the private keys are encrypted. If you do not want to type passwords while you managing the certificates, you can set environment variables for the passwords.

```sh
export CA_KEY_PASS="<password>"
export CERT_KEY_PASS="<password>"
```

## Usage

### Create a CA

```sh
# Create the CA with default values.
# It asks for the CA name and organization.
./ca-script.sh ca create

# Show the CA certificate
./ca-script.sh ca show
```

You can find the CA certificate in the folder `$CA_PATH/ca/ca.crt` and import this files in the CA trust stores to trust issued certificates.

### Create a Certificate

```sh
# Create a certificate with default values.
# It asks for the Subject Alternative Names and for Extended Key Usage.
./ca-script.sh cert create

# Show the certificate
./ca-script.sh cert show <fqdn>

# Renew the certificate
./ca-script.sh cert renew <fqdn>
```

You can find the certificate and private key in the folder `$CA_PATH/certs/<fqdn>.{crt,key}`.

### Manage Certificates

```sh
# Show all certificates issued by the CA
./ca-script.sh cert list

# Renew all certificates that expire within two weeks
./ca-script.sh cert autorenew

# Revoke a certificate
./ca-script.sh cert revoke <fqdn>
```

### Certificate Revocation List

The CRL can be found in `$CA_PATH/crl/ca.crl`.

```sh
# Create the CRL
./ca-script.sh crl create

# Show the CRL
./ca-script.sh crl show
```
