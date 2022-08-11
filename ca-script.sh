#!/bin/bash

# This script:
#  - creates ca self signed certificate
#  - creates signed server certificates

# Author: Juergen Mang <juergen.mang@axians.de>
# Date: 2021-12-08

# strict checking
set -u

if [ -z "${CAPATH+x}" ]
then
    CAPATH=$(pwd)
fi

create_ca() {
    mkdir -p "$CAPATH/ca"
    mkdir "$CAPATH/certs"
    cd "$CAPATH/ca" || exit 1

    echo '01' > serial
    touch index.txt
    touch index.txt.attr

    echo "Creating ca"

    cat > ca.cnf << EOL
[req]
distinguished_name = root_ca_distinguished_name
x509_extensions = root_ca_extensions
prompt = no
[root_ca_distinguished_name]
O = Self Signed CA
CN = Self Signed CA

[root_ca_extensions]
basicConstraints = CA:true

[ ca ]
default_ca = self_signed_ca

[self_signed_ca]
dir = $CAPATH/ca
database = $CAPATH/ca/index.txt
new_certs_dir = $CAPATH/certs/
serial = $CAPATH/ca/serial
copy_extensions = copy
policy = local_ca_policy
x509_extensions = local_ca_extensions
default_md = sha256

[ local_ca_policy ]
commonName = supplied
organizationName = supplied

[ local_ca_extensions ]
basicConstraints = CA:false
EOL

    openssl req -new -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -config ca.cnf \
        -keyout ca.key -out ca.pem
}

create_cert() {
    cd "$CAPATH/certs" || exit 1
    #first get sans interactively
    rm -f alt_names.cnf
    #dns names
    CN=""
    I=0
    while :
    do
        read -r -p "Enter hostname: " NAME
        [ -z "$NAME" ] && break
        ((I++))
        echo "DNS.$I = $NAME" >> alt_names.cnf
        #first name is CN
        [ "$I" = "1" ] && CN="$NAME"
    done
    #ips
    I=0
    while :
    do
        read -r -p "Enter IP: " IP
        [ -z "$IP" ] && break
        ((I++))
        echo "IP.$I = $IP" >> alt_names.cnf
    done

    if [ -z "$CN" ]
    then
        echo "Minimum one name is required"
        exit 1
    fi

    cat > "$CN.cnf" << EOL
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
O = Custom Cert
CN = $CN
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
EOL
    cat alt_names.cnf >> "$CN.cnf"
    rm alt_names.cnf

    openssl req -new -sha256 -newkey rsa:2048 -nodes -config "$CN.cnf" \
        -keyout "$CN.key" -out "$CN.csr" -extensions v3_req

    echo "Sign cert with ca"
    openssl ca -in "$CN.csr" -cert "$CAPATH/ca/ca.pem" -keyfile "$CAPATH/ca/ca.key" \
        -config "$CAPATH/ca/ca.cnf" -out "$CN.pem" -days 365 -batch
}

print_usage() {
    echo "Creates a self signed ca and signed certificates"
    echo "Usage: createcert.sh (ca|cert)"
}

if [ -z "${1+x}" ]
then
    print_usage
    exit 1
else
    ACTION="$1"
fi

case "$ACTION" in
    ca)
        create_ca
        ;;
    cert)
        create_cert
        ;;
    clean)  
        rm -rf ca
        rm -rf certs
        ;;
    *)
        print_usage
        exit 1
        ;;
esac

exit 0
