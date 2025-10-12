#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-3.0-or-later
# (c) 2025 Juergen Mang <mail@juergenmang.de>
# https://github.com/JuergenMang/ca-script

# Strict error handling
set -eEu -o pipefail

if [ -s .ca-script.cnf ]
then
    . .ca-script.cnf
fi

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

CA_KEY_TYPE=${CA_KEY_ALG%%:*}
CA_KEY_SIZE=${CA_KEY_ALG#*:}
CERT_KEY_TYPE=${CERT_KEY_ALG%%:*}
CERT_KEY_SIZE=${CERT_KEY_ALG#*:}

if [ -z "$CA_KEY_TYPE" ] || [ -z "$CA_KEY_SIZE" ]
then
    echo "Invalid CA_KEY_ALG environment"
    exit 1
fi

if [ -z "$CERT_KEY_TYPE" ] || [ -z "$CERT_KEY_SIZE" ]
then
    echo "Invalid CERT_KEY_ALG environment"
    exit 1
fi

if [ -d "$CA_PATH" ]
then
    CA_PATH=$(realpath "$CA_PATH")
fi

echo "--"
echo "CA_PATH: $CA_PATH"
echo "CA_DAYS $CA_DAYS"
echo "CA_KEY_ALG: $CA_KEY_ALG"
echo "CA_KEY_ENC $CA_KEY_ENC"
echo "CERT_DAYS: $CERT_DAYS"
echo "CERT_EXPIRE_DAYS: $CERT_EXPIRE_DAYS"
echo "CERT_KEY_ALG: $CERT_KEY_ALG"
echo "CERT_KEY_ENC: $CERT_KEY_ENC"
echo "--"

ca.create() {
    local CA_NAME
    read -r -p "Enter CA Name: " CA_NAME
    if [ -z "$CA_NAME" ]
    then
        echo "No CA Name entered, exiting"
        exit 1
    fi
    local CA_ORG
    read -r -p "Enter CA Organization: " CA_ORG
    if [ -z "$CA_ORG" ]
    then
        echo "No CA Name entered, exiting"
        exit 1
    fi
    mkdir -p "$CA_PATH/ca"
    mkdir -p "$CA_PATH/certs"
    mkdir -p "$CA_PATH/crl"
    CA_PATH=$(realpath "$CA_PATH")

    echo '01' > "$CA_PATH/ca/serial"
    echo '1000' > "$CA_PATH/ca/crlnumber"
    touch "$CA_PATH/ca/index.txt"
    cat > "$CA_PATH/ca/index.txt.attr" << EOL
unique_subject = no

EOL

    echo "Creating ca in folder $CA_PATH"

    cat > "$CA_PATH/ca/ca.cnf" << EOL
[req]
distinguished_name     = root_ca_distinguished_name
x509_extensions        = root_ca_extensions
prompt                 = no

[root_ca_distinguished_name]
O                      = $CA_ORG
CN                     = $CA_NAME

[root_ca_extensions]
basicConstraints       = CA:true

[ ca ]
default_ca             = self_signed_ca

[self_signed_ca]
dir                    = $CA_PATH/ca
database               = $CA_PATH/ca/index.txt
new_certs_dir          = $CA_PATH/certs/
certificate            = $CA_PATH/ca/ca.crt
serial                 = $CA_PATH/ca/serial
crlnumber              = $CA_PATH/ca/crlnumber
private_key            = $CA_PATH/ca/ca.key
copy_extensions        = copy
policy                 = local_ca_policy
x509_extensions        = local_ca_extensions
default_md             = sha256
default_crl_days       = 30
crl_extensions         = crl_ext

[ local_ca_policy ]
commonName             = supplied

[ local_ca_extensions ]
basicConstraints       = CA:false

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOL

    local OPTS=()
    if [ "$CA_KEY_ENC" -eq 0 ]
    then
        OPTS+=("-nodes")
    fi

    if [ "$CA_KEY_TYPE" = "rsa" ]
    then
        if ! openssl req -new -x509 -newkey "$CA_KEY_ALG" -sha256 -days "$CA_DAYS" \
            -config "$CA_PATH/ca/ca.cnf" -keyout "$CA_PATH/ca/ca.key" \
            -out "$CA_PATH/ca/ca.crt" "${OPTS[@]}"
        then
            rm -rf "$CA_PATH"
            return 1
        fi
    elif [ "$CA_KEY_TYPE" = "ec" ]
    then
        if ! openssl req -new -x509 -newkey "$CA_KEY_TYPE" -pkeyopt "ec_paramgen_curve:$CA_KEY_SIZE" \
            -sha256 -days "$CA_DAYS" -config "$CA_PATH/ca/ca.cnf" -keyout "$CA_PATH/ca/ca.key" \
            -out "$CA_PATH/ca/ca.crt" "${OPTS[@]}"
        then
            rm -rf "$CA_PATH"
            return 1
        fi
    else
        echo "Unsupported key type"
        return 1
    fi
    return 0
}

ca.delete() {
    read -r -N1 -p "Really delete $CA_PATH? (y|N)" ANSWER
    echo ""
    if [ "$ANSWER" = "y" ]
    then
        rm -rf "$CA_PATH"
        return 0
    fi
    return 1
}

ca.index() {
    cat "$CA_PATH/ca/index.txt"
}

ca.show() {
    openssl x509 -in "$CA_PATH/ca/ca.crt" -noout -subject -dates -fingerprint
}

crl.create() {
    openssl ca -config "$CA_PATH/ca/ca.cnf" -gencrl -out "$CA_PATH/crl/ca.crl"
}

crl.show() {
     openssl crl -in "$CA_PATH/crl/ca.crl" -noout -text
}

cert.create() {
    #first get sans interactively
    rm -f "$CA_PATH/certs/alt_names.cnf"
    #dns names
    local CN=""
    local I=0
    while :
    do
        read -r -p "Enter hostname: " NAME
        [ -z "$NAME" ] && break
        I=$((I+1))
        echo "DNS.$I = $NAME" >> "$CA_PATH/certs/alt_names.cnf"
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
        echo "IP.$I = $IP" >> "$CA_PATH/certs/alt_names.cnf"
    done

    if [ -z "$CN" ]
    then
        echo "Minimum one name is required"
        exit 1
    fi

    local EXT_KEY_USAGE
    echo "1) serverAuth"
    echo "2) clientAuth"
    read -r -N 1 -p "Extended Key Usage: " EXT_KEY_USAGE
    case "$EXT_KEY_USAGE" in
        2) EXT_KEY_USAGE="clientAuth" ;;
        *) EXT_KEY_USAGE="serverAuth" ;;
    esac
    echo ""

    cat > "$CA_PATH/certs/$CN.cnf" << EOL
[req]
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[req_distinguished_name]
CN                 = $CN

[v3_req]
basicConstraints   = CA:FALSE
keyUsage           = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage   = $EXT_KEY_USAGE
subjectAltName     = @alt_names

[alt_names]
EOL
    cat "$CA_PATH/certs/alt_names.cnf" >> "$CA_PATH/certs/$CN.cnf"
    rm -f "$CA_PATH/certs/alt_names.cnf"

    local OPTS=()
    if [ "$CERT_KEY_ENC" -eq 0 ]
    then
        OPTS+=("-nodes")
    fi

    if [ "$CERT_KEY_TYPE" = "rsa" ]
    then
        if ! openssl req -new -sha256 -newkey "$CERT_KEY_ALG" -config "$CA_PATH/certs/$CN.cnf" \
            -keyout "$CA_PATH/certs/$CN.key" -out "$CA_PATH/certs/$CN.csr" -extensions v3_req \
            "${OPTS[@]}"
        then
            return 1
        fi
    elif [ "$CERT_KEY_TYPE" = "ec" ]
    then
        if ! openssl req -new -sha256 -newkey "$CERT_KEY_TYPE" -pkeyopt "ec_paramgen_curve:$CERT_KEY_SIZE" \
            -config "$CA_PATH/certs/$CN.cnf" -keyout "$CA_PATH/certs/$CN.key" \
            -out "$CA_PATH/certs/$CN.csr" -extensions v3_req "${OPTS[@]}"
        then
            return 1
        fi
    else
        echo "Unsupported key type"
        return 1
    fi

    echo "Sign cert with ca"
    if ! openssl ca -in "$CA_PATH/certs/$CN.csr" -cert "$CA_PATH/ca/ca.crt" -keyfile "$CA_PATH/ca/ca.key" \
        -config "$CA_PATH/ca/ca.cnf" -out "$CA_PATH/certs/$CN.crt" -days "$CERT_DAYS" -batch
    then
        return 1
    fi

    return 0
}

cert.revoke() {
    if [ -z "${1+x}" ]
    then
        print_usage
        return 2
    elif [ ! -f "$CA_PATH/certs/$1.crt" ]
    then
        echo "Certificate for $1 not found"
        return 1
    fi
    openssl ca -config "$CA_PATH/ca/ca.cnf" -revoke "$CA_PATH/certs/$1.crt"
}

cert.list() {
    local CERT FILENAME SUBJECT SAN END
    {
        while read -r CERT
        do
            FILENAME=$(basename "$CERT" .crt)
            SUBJECT=$(openssl x509 -in "$CERT" -noout -subject | sed 's/^subject=//')
            SAN=$(openssl x509 -in "$CERT" -noout -ext subjectAltName | tail -1 | sed -E 's/^\s+//')
            END=$(openssl x509 -in "$CERT" -noout -enddate | sed 's/notAfter=//')
            printf "%s\t%s\t%s\t%s\n" "$FILENAME" "$SUBJECT" "$SAN" "$END"
        done < <(find "$CA_PATH/certs/" -name \*.crt)
    } | column -t -s $'\t' -N "Cert,Subject,SAN,End"
}

cert.show() {
    if [ -z "${1+x}" ]
    then
        print_usage
        return 2
    elif [ ! -f "$CA_PATH/certs/$1.crt" ]
    then
        echo "Certificate for $1 not found"
        return 1
    fi
    openssl x509 -in "$CA_PATH/certs/$1.crt" -noout -subject -dates -fingerprint -ext subjectAltName
}

cert.renew() {
    if [ -z "${1+x}" ]
    then
        print_usage
        return 2
    elif [ ! -f "$CA_PATH/certs/$1.csr" ]
    then
        echo "Certificate signing request for $1 not found"
        return 1
    fi
    echo "Renewing cert $1"
    if ! openssl ca -in "$CA_PATH/certs/$1.csr" -cert "$CA_PATH/ca/ca.crt" -keyfile "$CA_PATH/ca/ca.key" \
        -config "$CA_PATH/ca/ca.cnf" -out "$CA_PATH/certs/$1.crt" -days "$CERT_DAYS" -batch
    then
        return 1
    fi

    return 0
}

cert.autorenew() {
    local EXPIRE=$((CERT_EXPIRE_DAYS*24*60*60))
    while read -r CSR
    do
        local FQDN
        FQDN=$(basename "$CSR" .csr)
        echo -n "Checking $FQDN: "
        if ! openssl x509 --checkend "$EXPIRE" -in "$CA_PATH/certs/$FQDN.crt"
        then
            renew_cert "$FQDN"
        fi
    done < <(find "$CA_PATH/certs" -type f -name \*.csr -printf "%f\n")
}

print_usage() {
    exec 1>&2
    echo "Creates a self signed ca and signed certificates"
    echo "Usage:"
    echo "    ca-script.sh ca <create|delete|show|index>"
    echo "    ca-script.sh cert <autorenew|create|list>"
    echo "    ca-script.sh cert <renew|revoke|show> <fqdn>"
    echo "    ca-script.sh crl <create|show>"
    echo ""
    echo "Environment:"
    echo "    CA_PATH           CA path, default: default-ca"
    echo "    CA_DAYS           The CA certificate lifetime in days, default: 3650"
    echo "    CA_KEY_ALG        Alg. for CA key: rsa:2048, rsa:4096, ec:prime256v1, ec:secp384r1 (default)"
    echo "    CA_KEY_ENC        Encrypt CA private key, default: 1"
    echo ""
    echo "    CERT_DAYS         The certificate lifetime in days, default: 365"
    echo "    CERT_KEY_ALG      Alg. for certificate keys: rsa:2048, rsa:4096, ec:prime256v1 (default), ec:secp384r1"
    echo "    CERT_KEY_ENC      Encrypt certificate private keys, default: 1"
    echo "    CERT_EXPIRE_DAYS  Remaining lifetime in days for autorenew, default 14"
}

if [ $# -lt 2 ]
then
    print_usage
    exit 2
fi

CATEGORY="$1"
ACTION="$2"
shift 2

case "$CATEGORY" in
    ca)
        case "$ACTION" in
            create)
                ca.create
                ;;
            delete)
                ca.delete
                ;;
            index)
                ca.index
                ;;
            show)
                ca.show
                ;;
            *)
                print_usage
                exit 2
                ;;
        esac
        ;;
    cert)
        case "$ACTION" in
            autorenew)
                cert.autorenew
                ;;
            create)
                cert.create
                ;;
            list)
                cert.list
                ;;
            renew)
                cert.renew "$@"
                ;;
            revoke)
                cert.revoke "$@"
                ;;
            show)
                cert.show "$@"
                ;;
            *)
                print_usage
                exit 2
                ;;
        esac
        ;;
    crl)
        case "$ACTION" in
            create)
                crl.create
                ;;
            show)
                crl.show
                ;;
            *)
                print_usage
                exit 2
                ;;
        esac
        ;;
    *)
        print_usage
        exit 2
        ;;
esac

exit 0
