#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-3.0-or-later
# (c) 2025-2026 Juergen Mang <mail@juergenmang.de>
# https://github.com/JuergenMang/ca-script

# Generates:
# 1. Self signed Root CA: default-root-ca
# 2. Intermediate CA: default-ca
# 3. Singing CA: signing-ca

# Go to the script's directory
cd "$(dirname "$(realpath "$0")")" || exit 1

# Cleanup
rm -rf default-root-ca/
rm -rf default-ca/
rm -rf signing-ca/

# Create self signed Root CA
CA_PATH=default-root-ca ./ca-script.sh ca create

# Create intermediate CA
CA_ROOT_PATH=default-root-ca CA_PATH=default-ca ./ca-script.sh ca create

# Create signing CA
CA_ROOT_PATH=default-ca CA_PATH=signing-ca ./ca-script.sh ca create

# Create chain file
cat signing-ca/ca/ca.crt default-ca/ca/ca.crt default-root-ca/ca/ca.crt > chain.crt

# Create config for certificate creation
cat > .ca-script.cnf <<EOL
[ -n "${CA_PATH+x}" ] || CA_PATH="signing-ca"
EOL
