#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-3.0-or-later
# (c) 2025-2026 Juergen Mang <mail@juergenmang.de>
# https://github.com/JuergenMang/ca-script

# Generates:
# 1. Self signed Root CA: default-root-ca
# 2. Intermediate CA signed by the default-root-ca: default-ca
# 3. Singing CA signed by the default-ca: signing-ca

# Go to the script's directory
cd "$(dirname "$(realpath "$0")")" || exit 1

# Cleanup
rm -rf default-root-ca/
rm -rf default-ca/
rm -rf signing-ca/
rm -f .ca-script.cnf
rm -f chain.crt

# Generate random password
# They are stored in the .ca-script.cnf configuration file
export CA_KEY_PASS="$(tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c "24" || true)"
export CERT_KEY_PASS="$(tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c "12" || true)"
export P12_PASS="$(tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c "12" || true)"

# Create self signed Root CA
CA_PATH=default-root-ca ./ca-script.sh ca create -s1 -n default-root-ca -o default-root-org

# Create intermediate CA
CA_ROOT_PATH=default-root-ca CA_PATH=default-ca ./ca-script.sh ca create -s0 -n default-ca -o default-org

# Create signing CA
CA_ROOT_PATH=default-ca CA_PATH=signing-ca ./ca-script.sh ca create -s0 -n signing-ca -o signing-org

# Create chain file
cat signing-ca/ca/ca.crt default-ca/ca/ca.crt default-root-ca/ca/ca.crt > chain.crt

# Create config for certificate creation
cat > .ca-script.cnf <<EOL
[ -n "\${CA_KEY_PASS+x}" ] || export CA_KEY_PASS="$CA_KEY_PASS"
[ -n "\${CERT_KEY_PASS+x}" ] || export CERT_KEY_PASS="$CERT_KEY_PASS"
[ -n "\${P12_PASS+x}" ] || export P12_PASS="$P12_PASS"
[ -n "\${CA_PATH+x}" ] || export CA_PATH="signing-ca"

EOL
