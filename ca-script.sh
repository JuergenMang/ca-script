#!/bin/bash

# Author: Juergen Mang <juergen.mang@axians.de>
# Date: 2024-07-26

# Shortdesc: Simple script to create a self signed ca and create/sign certificates.
# Desc:
#  - Creates ca self signed certificate
#  - Creates signed server certificates

# Strict error handling
set -eEu -o pipefail

[ -z "${CAPATH+x}" ] && CAPATH="default-ca"
[ -z "${CADAYS+x}" ] && CADAYS=3650
[ -z "${KEYALG+x}" ] && KEYALG="rsa:2048"
[ -z "${CERTDAYS+x}" ] && CERTDAYS=365

KEY_TYPE=${KEYALG%%:*}
KEY_SIZE=${KEYALG#*:}

if [ -z "$KEY_TYPE" ] || [ -z "$KEY_SIZE" ]
then
    echo "Invalid KEYALG environment"
    exit 1
fi

if [ -d "$CAPATH" ]
then
    CAPATH=$(realpath "$CAPATH")
fi

echo "--"
echo "CAPATH: $CAPATH"
echo "CADAYS $CADAYS"
echo "KEYALG: $KEYALG"
echo "CERTDAYS: $CERTDAYS"
echo "--"

create_ca() {
    mkdir -p "$CAPATH/ca"
    mkdir -p "$CAPATH/certs"
    CAPATH=$(realpath "$CAPATH")

    echo '01' > "$CAPATH/ca/serial"
    touch "$CAPATH/ca/index.txt"
    cat > "$CAPATH/ca/index.txt.attr" << EOL
unique_subject = no

EOL

    echo "Creating ca"

    cat > "$CAPATH/ca/ca.cnf" << EOL
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

    if [ "$KEY_TYPE" = "rsa" ]
    then
        openssl req -new -x509 -newkey "$KEYALG" -sha256 -days "$CADAYS" -nodes \
            -config "$CAPATH/ca/ca.cnf" -keyout "$CAPATH/ca/ca.key" \
            -out "$CAPATH/ca/ca.pem"
    elif [ "$KEY_TYPE" = "ec" ]
    then
        openssl req -new -x509 -newkey "$KEY_TYPE" -pkeyopt "ec_paramgen_curve:$KEY_SIZE" \
            -sha256 -days "$CADAYS" -nodes -config "$CAPATH/ca/ca.cnf" \
            -keyout "$CAPATH/ca/ca.key" -out "$CAPATH/ca/ca.pem"
    else
        echo "Unsupported key type"
        return 1
    fi
    return 0
}

create_cert() {
    #first get sans interactively
    rm -f "$CAPATH/certs/alt_names.cnf"
    #dns names
    local CN=""
    local I=0
    while :
    do
        read -r -p "Enter hostname: " NAME
        [ -z "$NAME" ] && break
        I=$((I+1))
        echo "DNS.$I = $NAME" >> "$CAPATH/certs/alt_names.cnf"
        #first name is CN
        [ "$I" = "1" ] && CN="$NAME"
    done
    #ips
    I=0
    while :
    do
        read -r -p "Enter IP: " IP
        [ -z "$IP" ] && break
        I=$((I+1))
        echo "IP.$I = $IP" >> "$CAPATH/certs/alt_names.cnf"
    done

    if [ -z "$CN" ]
    then
        echo "Minimum one name is required"
        exit 1
    fi

    cat > "$CAPATH/certs/$CN.cnf" << EOL
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
    cat "$CAPATH/certs/alt_names.cnf" >> "$CAPATH/certs/$CN.cnf"
    rm -f "$CAPATH/certs/alt_names.cnf"

    if [ "$KEY_TYPE" = "rsa" ]
    then
        openssl req -new -sha256 -newkey "$KEYALG" -nodes -config "$CAPATH/certs/$CN.cnf" \
            -keyout "$CAPATH/certs/$CN.key" -out "$CAPATH/certs/$CN.csr" -extensions v3_req
    elif [ "$KEY_TYPE" = "ec" ]
    then
        openssl req -new -sha256 -newkey "$KEY_TYPE" -pkeyopt "ec_paramgen_curve:$KEY_SIZE" \
            -nodes -config "$CAPATH/certs/$CN.cnf" -keyout "$CAPATH/certs/$CN.key" \
            -out "$CAPATH/certs/$CN.csr" -extensions v3_req
    else
        echo "Unsupported key type"
        return 1
    fi

    echo "Sign cert with ca"
    openssl ca -in "$CAPATH/certs/$CN.csr" -cert "$CAPATH/ca/ca.pem" -keyfile "$CAPATH/ca/ca.key" \
        -config "$CAPATH/ca/ca.cnf" -out "$CAPATH/certs/$CN.pem" -days "$CERTDAYS" -batch

    return 0
}

print_usage() {
    exec 1>&2
    echo "Creates a self signed ca and signed certificates"
    echo "Usage: createcert.sh (ca|cert)"
    echo "Environment:"
    echo -e "\tCAPATH     CA path, default: current dir"
    echo -e "\tCADAYS     Lifetime of the CA certificate in days, default: 3650"
    echo -e "\tKEYALG     Alg for key: rsa:2048 (default), ec:prime256v1, ec:secp384r1"
    echo -e "\tCERTDAYS   Lifetime of the certificate in days, default: 365"
}

if [ -z "${1+x}" ]
then
    print_usage
    exit 2
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
        rm -rf "$CAPATH"
        ;;
    *)
        print_usage
        exit 2
        ;;
esac

exit 0
