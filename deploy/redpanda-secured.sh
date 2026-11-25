#!/usr/bin/env bash
# Starts the backbone the integration suite holds the platform's grants against:
# one TLS listener on which every client authenticates by SCRAM and is held to its
# ACLs, as production runs it. The broker mints its own authority and discards its
# key, so no key exists outside the container; the suite trusts authority.pem.
set -euo pipefail
tls=/tmp/tls
mkdir -p "$tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj "/CN=Seagull secured test backbone" -keyout "$tls/authority.key" -out "$tls/authority.pem" 2> /dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=redpanda-secured" \
  -keyout "$tls/broker.key" -out "$tls/broker.csr" 2> /dev/null
printf 'subjectAltName=DNS:redpanda-secured,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$tls/extensions"
openssl x509 -req -in "$tls/broker.csr" -CA "$tls/authority.pem" -CAkey "$tls/authority.key" -CAcreateserial \
  -days 2 -extfile "$tls/extensions" -out "$tls/broker.pem" 2> /dev/null
rm -f "$tls/authority.key" "$tls/broker.csr" "$tls/extensions"

cat > /etc/redpanda/.bootstrap.yaml << YAML
superusers: [backbone-migrator]
kafka_enable_authorization: true
YAML
cat > /etc/redpanda/redpanda.yaml << YAML
redpanda:
  data_directory: /var/lib/redpanda/data
  seed_servers: []
  rpc_server: {address: 0.0.0.0, port: 33145}
  advertised_rpc_api: {address: 127.0.0.1, port: 33145}
  kafka_api:
    - {name: secured, address: 0.0.0.0, port: 9093, authentication_method: sasl}
  advertised_kafka_api:
    - {name: secured, address: 127.0.0.1, port: ${SEAGULL_SECURED_ADVERTISED_PORT}}
  kafka_api_tls:
    - {name: secured, enabled: true, cert_file: $tls/broker.pem, key_file: $tls/broker.key, require_client_auth: false}
  admin:
    - {address: 0.0.0.0, port: 9644}
  developer_mode: true
YAML
exec rpk redpanda start --node-id=0 --smp=1 --memory=1G --reserve-memory=0M --overprovisioned --check=false
