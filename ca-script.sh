#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-3.0-or-later
# (c) 2025 Juergen Mang <mail@juergenmang.de>
# https://github.com/JuergenMang/ca-script

# Strict error handling
set -eEu -o pipefail

# Keep created files private
umask 0077

# Get configuration
if [ -s .ca-script.cnf ]
then
    # shellcheck disable=SC1091
    . .ca-script.cnf
fi

# Root CA default config
[ -n "${CA_ROOT_PATH+x}" ] || CA_ROOT_PATH="default-root-ca"
[ -n "${CA_ROOT_DAYS+x}" ] || CA_ROOT_DAYS=7300

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
echo "CA_KEY_ENC: $CA_KEY_ENC"
echo "CERT_DAYS: $CERT_DAYS"
echo "CERT_EXPIRE_DAYS: $CERT_EXPIRE_DAYS"
echo "CERT_KEY_ALG: $CERT_KEY_ALG"
echo "CERT_KEY_ENC: $CERT_KEY_ENC"
echo "--"

###############################################################################
# Functions

ca.create() {
    local SELF_SIGNED
    local DAYS=$CA_DAYS
    read -r -p "Self signed (Y/n): " SELF_SIGNED
    if [ -z "$SELF_SIGNED" ] || [ "$SELF_SIGNED" = "y" ] || [ "$SELF_SIGNED" = "Y" ]
    then
        DAYS=$CA_ROOT_DAYS
        SELF_SIGNED=1
    else
        SELF_SIGNED=0
    fi
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
    mkdir -p "$CA_PATH/certs/archive"
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
[ ca ]
default_ca             = self_signed_ca

[ self_signed_ca ]
dir                    = $CA_PATH/ca
database               = $CA_PATH/ca/index.txt
new_certs_dir          = $CA_PATH/certs/archive
certificate            = $CA_PATH/ca/ca.crt
serial                 = $CA_PATH/ca/serial
crlnumber              = $CA_PATH/ca/crlnumber
private_key            = $CA_PATH/ca/ca.key
copy_extensions        = copy
policy                 = local_ca_policy
default_md             = sha256
default_crl_days       = 30
crl_extensions         = crl_ext

[ local_ca_policy ]
commonName             = supplied

[ req ]
distinguished_name     = req_distinguished_name
x509_extensions        = root_ca_extensions
prompt                 = no

[ req_distinguished_name ]
O                      = $CA_ORG
CN                     = $CA_NAME

[ root_ca_extensions ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign  

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ intermediate_ca_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
EOL

    local OPTS=()
    if [ "$CA_KEY_ENC" -eq 0 ]
    then
        OPTS+=("-nodes")
    elif [ -n "${CA_KEY_PASS+x}" ]
    then
        OPTS+=("-passout" "env:CA_KEY_PASS")
    fi

    if [ "$SELF_SIGNED" -eq 1 ]
    then
        OPTS+=("-x509")
    fi

    if [ "$CA_KEY_TYPE" = "rsa" ]
    then
        if ! openssl req -new -newkey "$CA_KEY_ALG" -sha256 -days "$CA_DAYS" \
            -config "$CA_PATH/ca/ca.cnf" -keyout "$CA_PATH/ca/ca.key" \
            -out "$CA_PATH/ca/ca.crt" "${OPTS[@]}"
        then
            rm -rf "$CA_PATH"
            return 1
        fi
    elif [ "$CA_KEY_TYPE" = "ec" ]
    then
        if ! openssl req -new -newkey "$CA_KEY_TYPE" -pkeyopt "ec_paramgen_curve:$CA_KEY_SIZE" \
            -sha256 -days "$DAYS" -config "$CA_PATH/ca/ca.cnf" -keyout "$CA_PATH/ca/ca.key" \
            -out "$CA_PATH/ca/ca.crt" "${OPTS[@]}"
        then
            rm -rf "$CA_PATH"
            return 1
        fi
    else
        echo "Unsupported key type"
        return 1
    fi

    if [ "$SELF_SIGNED" -eq 0 ]
    then
        if [ -d "$CA_ROOT_PATH" ]
        then
            if ! ca.sign "$CA_PATH/ca/ca.csr" "$CA_PATH/ca/ca.crt"
            then
                return 1
            fi
        else
            echo "Root CA not found"
            return 1
        fi
    fi
    return 0
}

ca.sign() {
    if [ $# -ne 2 ]
    then
        print_usage
        return 2
    fi
    local IN=$1
    local OUT=$2
    echo "Signing intermediate ca certificate with root ca certificate"
    OPTS=()
    if [ "$CA_KEY_ENC" -eq 1 ] && [ -n "${CA_KEY_PASS+x}" ]
    then
        OPTS+=("-passin" "env:CA_KEY_PASS")
    fi
    if ! openssl ca -in "$IN" -cert "$CA_ROOT_PATH/ca/ca.crt" -keyfile "$CA_ROOT_PATH/ca/ca.key" \
        -config "$CA_ROOT_PATH/ca/ca.cnf" -out "$OUT" -days "$CA_DAYS" -batch \
        -extensions intermediate_ca_ext "${OPTS[@]}"
    then
        return 1
    fi
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
    local ALT_NAMES
    ALT_NAMES=$(mktemp)
    #dns names
    local CN=""
    local I=0
    while :
    do
        read -r -p "Enter hostname: " NAME
        [ -z "$NAME" ] && break
        I=$((I+1))
        echo "DNS.$I = $NAME" >> "$ALT_NAMES"
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
        echo "IP.$I = $IP" >> "$ALT_NAMES"
    done

    if [ -z "$CN" ]
    then
        echo "Minimum one name is required"
        return 1
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
keyUsage           = critical, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage   = $EXT_KEY_USAGE
subjectAltName     = @alt_names

[alt_names]
EOL
    cat "$ALT_NAMES" >> "$CA_PATH/certs/$CN.cnf"
    rm -f "$ALT_NAMES"

    local OPTS=()
    if [ "$CERT_KEY_ENC" -eq 0 ]
    then
        OPTS+=("-nodes")
    elif [ -n "${CERT_KEY_PASS+x}" ]
    then
        OPTS+=("-passout" "env:CERT_KEY_PASS")
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

    if ! cert.sign "$CA_PATH/certs/$CN.csr" "$CA_PATH/certs/$CN.crt"
    then
        return 1
    fi
    return 0
}

cert.sign() {
    if [ $# -ne 2 ]
    then
        print_usage
        return 2
    fi
    local IN=$1
    local OUT=$2
    echo "Sign cert with ca"
    OPTS=()
    if [ "$CA_KEY_ENC" -eq 1 ] && [ -n "${CA_KEY_PASS+x}" ]
    then
        OPTS+=("-passin" "env:CA_KEY_PASS")
    fi
    if ! openssl ca -in "$IN" -cert "$CA_PATH/ca/ca.crt" -keyfile "$CA_PATH/ca/ca.key" \
        -config "$CA_PATH/ca/ca.cnf" -out "$OUT" -days "$CERT_DAYS" -batch "${OPTS[@]}"
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
    OPTS=()
    if [ "$CA_KEY_ENC" -eq 1 ] && [ -n "${CA_KEY_PASS+x}" ]
    then
        OPTS+=("-passin" "env:CA_KEY_PASS")
    fi
    if ! openssl ca -config "$CA_PATH/ca/ca.cnf" -revoke "$CA_PATH/certs/$1.crt" "${OPTS[@]}"
    then
        return 1
    fi
    return 0
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
    local OPTS=()
    if [ "$CA_KEY_ENC" -eq 1 ] && [ -n "${CA_KEY_PASS+x}" ]
    then
        OPTS+=("-passin" "env:CA_KEY_PASS")
    fi
    echo "Renewing cert $1"
    if ! openssl ca -in "$CA_PATH/certs/$1.csr" -cert "$CA_PATH/ca/ca.crt" -keyfile "$CA_PATH/ca/ca.key" \
        -config "$CA_PATH/ca/ca.cnf" -out "$CA_PATH/certs/$1.crt" -days "$CERT_DAYS" -batch "${OPTS[@]}"
    then
        return 1
    fi
    if [ -x "$CA_PATH/hooks/$1.sh" ]
    then
        echo "Executing post renew script"
        eval "$CA_PATH/hooks/$1.sh" || true
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
            cert.renew "$FQDN"
        fi
    done < <(find "$CA_PATH/certs" -type f -name \*.csr -printf "%f\n")
}

p12.create() {
    if [ $# -ne 2 ]
    then
        print_usage
        return 2
    elif [ ! -f "$CA_PATH/certs/$1.crt" ]
    then
        echo "Certificate for $1 not found"
        return 1
    fi
    local OPTS=()
    if [ "$CERT_KEY_ENC" -eq 1 ] && [ -n "${CERT_KEY_PASS+x}" ]
    then
        OPTS+=("-passin" "env:CERT_KEY_PASS")
    fi
    if [ -n "${P12_PASS+x}" ]
    then
        OPTS+=("-passout" "env:P12_PASS")
    fi
    if ! openssl pkcs12 -export -out "$2" -in "$CA_PATH/certs/$1.crt" -inkey "$CA_PATH/certs/$1.key" \
            -certfile "$CA_PATH/ca/ca.crt" "${OPTS[@]}"
    then
        return 1
    fi
    return 0
}

print_usage() {
    exec 1>&2
    echo "Creates a Self Signed Root CA, Intermediate CA's and creates/signes server and client certificates."
    echo "Usage:"
    echo "    ca-script.sh ca <create|delete|show|index>"
    echo "    ca-script.sh ca sign <in csr> <out crt>"
    echo "    ca-script.sh cert <autorenew|create|list>"
    echo "    ca-script.sh cert <renew|revoke|show> <fqdn>"
    echo "    ca-script.sh cert sign <in csr> <out crt>"
    echo "    ca-script.sh crl <create|show>"
    echo "    ca-script.sh p12 create <fqdn> <output file>"
    echo ""
    echo "Environment:"
    echo "    CA_ROOT_PATH      Root CA path, default: default-ca"
    echo "    CA_ROOT_DAYS      The Root CA certificate lifetime in days, default: 7300"
    echo ""
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

###############################################################################
# Main

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
            sign)
                ca.sign "$@"
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
            sign)
                cert.sign "$@"
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
    p12)
        case "$ACTION" in
            create)
                p12.create "$@"
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
