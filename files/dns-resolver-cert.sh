#!/usr/bin/env bash
# Get, install and check the TLS certificate that Hickory serves.
#
#   dns-resolver-cert install   First issuance on a new host. Gets a certificate
#                               if there is none, stages it, checks it, and
#                               points "current" at it. Does not touch Hickory.
#   dns-resolver-cert renew     Renew with lego if due, and nothing else. The
#                               next "sync" installs the result.
#   dns-resolver-cert sync      From the timer. Renews if due (a failed renewal
#                               is reported, and the run goes on), installs a
#                               changed certificate with a rollback, then probes
#                               every listener and writes metrics.
#
# Settings come from /etc/dns-resolver/cert.env (written by the role) and the
# ACME provider's secrets from /etc/dns-resolver/acme.env (mode 0600).
#
# Layout: $TLS_DIR/releases/<sha256 of chain>/{fullchain,privkey}.pem, with
# "current" and "previous" links. lego writes .crt and .key files; Hickory needs
# a .pem certificate name and reads a .key file as DER, so both are restaged as
# .pem.
set -euo pipefail

# shellcheck source=/dev/null
. /etc/dns-resolver/cert.env
if [ -f /etc/dns-resolver/acme.env ]; then
  set -a
  # shellcheck source=/dev/null
  . /etc/dns-resolver/acme.env
  set +a
fi

: "${TLS_DIR:?}" "${LEGO_PATH:?}" "${HOSTNAMES:?}" "${SERVICE_USER:?}" "${CA_BUNDLE:?}"
METRICS_DIR=${METRICS_DIR:--}
read -r -a names <<< "$HOSTNAMES"
read -r -a listen <<< "${LISTEN_ADDRESSES:-}"

log() { echo "dns-resolver-cert: $*"; }

lego_cmd() {
  local args=(--path "$LEGO_PATH" --email "$ACME_EMAIL" --accept-tos --key-type "$ACME_KEY_TYPE"
              --dns "$ACME_PROVIDER" --server "$ACME_SERVER")
  local name
  for name in "${names[@]}"; do args+=(--domains "$name"); done
  if [ "${ACME_DISABLE_CP:-false}" = true ]; then args+=(--dns.disable-cp); fi
  if [ -n "${ACME_DNS_RESOLVERS:-}" ]; then
    local resolver
    for resolver in $ACME_DNS_RESOLVERS; do args+=(--dns.resolvers "$resolver"); done
  fi
  lego "${args[@]}" "$@"
}

issued_paths() {
  issued_crt="$LEGO_PATH/certificates/${names[0]}.crt"
  issued_key="$LEGO_PATH/certificates/${names[0]}.key"
}

# Check a chain and key as the service user: readable, matching, all names
# present, not about to expire, and trusted by the CA bundle.
verify_pair() {
  local chain=$1 key=$2 leaf name sans
  runuser -u "$SERVICE_USER" -- test -r "$chain" || { log "$chain is not readable by $SERVICE_USER"; return 1; }
  runuser -u "$SERVICE_USER" -- test -r "$key" || { log "$key is not readable by $SERVICE_USER"; return 1; }
  if [ "$(openssl x509 -in "$chain" -noout -pubkey | sha256sum)" != "$(openssl pkey -in "$key" -pubout | sha256sum)" ]; then
    log "the key does not belong to the certificate"; return 1
  fi
  sans=$(openssl x509 -in "$chain" -noout -ext subjectAltName)
  for name in "${names[@]}"; do
    grep -q "DNS:${name}\(,\|$\)" <<< "$sans" || { log "the certificate does not cover $name"; return 1; }
  done
  openssl x509 -in "$chain" -noout -checkend $((7 * 86400)) >/dev/null || { log "the certificate expires within 7 days"; return 1; }
  leaf=$(mktemp)
  openssl x509 -in "$chain" -out "$leaf"
  if ! openssl verify -CAfile "$CA_BUNDLE" -untrusted "$chain" "$leaf" >/dev/null; then
    rm -f "$leaf"; log "the chain does not verify against $CA_BUNDLE"; return 1
  fi
  rm -f "$leaf"
}

# Copy the issued pair into a new release directory and print its path.
stage() {
  local release dir
  release=$(sha256sum "$issued_crt" | cut -c1-64)
  dir="$TLS_DIR/releases/$release"
  if [ ! -d "$dir" ]; then
    install -d -m 0750 -o root -g "$SERVICE_USER" "$dir.tmp"
    install -m 0640 -o root -g "$SERVICE_USER" "$issued_crt" "$dir.tmp/fullchain.pem"
    install -m 0640 -o root -g "$SERVICE_USER" "$issued_key" "$dir.tmp/privkey.pem"
    mv -T "$dir.tmp" "$dir"
  fi
  echo "$dir"
}

point() {  # point <link name> <release dir>
  ln -sfn "releases/$(basename "$2")" "$TLS_DIR/.$1.tmp"
  mv -T "$TLS_DIR/.$1.tmp" "$TLS_DIR/$1"
}

leaf_fingerprint() {  # leaf_fingerprint <file>
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2
}

# Probe one listener and print the SHA-256 fingerprint of the leaf it serves.
# A probe is tried three times before it counts as unanswered.
probe() {  # probe <dot|doh|doq> <address> <hostname>
  local kind=$1 address=$2 name=$3 port flags target got attempt
  case $kind in
    dot) port=$DOT_PORT; flags=(-alpn dot) ;;
    doh) port=$DOH_PORT; flags=(-alpn h2) ;;
    doq) port=$DOQ_PORT; flags=(-quic -alpn doq) ;;
  esac
  if [[ $address == *:* ]]; then target="[$address]:$port"; else target="$address:$port"; fi
  for attempt in 1 2 3; do
    got=$(timeout 10 openssl s_client "${flags[@]}" -connect "$target" -servername "$name" </dev/null 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    if [ -n "$got" ]; then echo "$got"; return 0; fi
    [ "$attempt" = 3 ] || sleep 2
  done
}

restart_hickory() {
  systemctl restart hickory-dns.service
  local _
  for _ in $(seq 1 30); do
    if timeout 2 openssl s_client -connect "127.0.0.1:$DOT_PORT" -servername "${names[0]}" </dev/null >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Check that every listener, on every address, serves the expected leaf for
# every host name. Sets the global "mismatch" to 1 if a probe succeeded but
# served another leaf, and "probe_failed" to 1 if a probe got nothing.
metrics_lines=()
check_listeners() {  # check_listeners <expected fingerprint>
  local expected=$1 kind address name got
  mismatch=0; probe_failed=0; metrics_lines=()
  for kind in dot doh doq; do
    for address in "${listen[@]}"; do
      for name in "${names[@]}"; do
        got=$(probe "$kind" "$address" "$name" || true)
        local labels="listener=\"$kind\",address=\"$address\",hostname=\"$name\""
        if [ -z "$got" ]; then
          probe_failed=1
          metrics_lines+=("dns_resolver_tls_probe_success{$labels} 0")
          continue
        fi
        metrics_lines+=("dns_resolver_tls_probe_success{$labels} 1")
        if [ "$got" = "$expected" ]; then
          metrics_lines+=("dns_resolver_tls_leaf_match{$labels} 1")
        else
          mismatch=1
          metrics_lines+=("dns_resolver_tls_leaf_match{$labels} 0")
        fi
      done
    done
  done
  if [ "${DNS_RESOLVER_TEST_FAIL_POSTCHECK:-0}" = 1 ]; then mismatch=1; fi
}

write_metrics() {  # write_metrics <name value>...
  [ "$METRICS_DIR" != "-" ] && [ -d "$METRICS_DIR" ] || return 0
  local file="$METRICS_DIR/dns_resolver_tls.prom" expiry=0
  if [ -e "$TLS_DIR/current/fullchain.pem" ]; then
    expiry=$(date -d "$(openssl x509 -in "$TLS_DIR/current/fullchain.pem" -noout -enddate | cut -d= -f2)" +%s)
  fi
  {
    echo "# HELP dns_resolver_tls_leaf_match 1 if a listener serves the installed certificate."
    echo "# TYPE dns_resolver_tls_leaf_match gauge"
    echo "# HELP dns_resolver_tls_probe_success 1 if a listener answered the TLS probe."
    echo "# TYPE dns_resolver_tls_probe_success gauge"
    echo "dns_resolver_tls_cert_expiry_timestamp_seconds $expiry"
    echo "dns_resolver_tls_sync_timestamp_seconds $(date +%s)"
    local line
    for line in "${metrics_lines[@]}" "$@"; do echo "$line"; done
  } > "$file.tmp"
  chmod 0644 "$file.tmp"
  mv "$file.tmp" "$file"
}

cmd_install() {
  issued_paths
  if [ ! -s "$issued_crt" ]; then
    log "getting a certificate for ${names[*]}"
    lego_cmd run
  fi
  local dir
  dir=$(stage)
  verify_pair "$dir/fullchain.pem" "$dir/privkey.pem"
  point current "$dir"
  log "installed $(basename "$dir")"
}

cmd_sync() {
  local renew_ok=1 activation_failed=0
  issued_paths
  if ! lego_cmd renew --days "${RENEW_DAYS:-30}" --no-random-sleep; then
    renew_ok=0
    log "renewal failed; going on with the certificate lego already has"
  fi

  local current_dir new_dir expected
  current_dir=$(readlink -f "$TLS_DIR/current")
  if [ -s "$issued_crt" ] && ! cmp -s "$issued_crt" "$current_dir/fullchain.pem"; then
    new_dir=$(stage)
    if verify_pair "$new_dir/fullchain.pem" "$new_dir/privkey.pem"; then
      log "activating $(basename "$new_dir")"
      point previous "$current_dir"
      point current "$new_dir"
      if restart_hickory; then
        check_listeners "$(leaf_fingerprint "$new_dir/fullchain.pem")"
      else
        mismatch=1; probe_failed=1
      fi
      # Activation needs every listener to answer with the new certificate.
      if [ "$mismatch" = 1 ] || [ "${probe_failed:-1}" = 1 ]; then
        log "the new certificate is not served correctly; going back to $(basename "$current_dir")"
        point current "$current_dir"
        restart_hickory || true
        activation_failed=1
      fi
    else
      log "the issued certificate failed its checks; keeping $(basename "$current_dir")"
      activation_failed=1
    fi
  fi

  # Check what is actually served. Restart only when a listener answered with
  # the wrong certificate; a failed probe never restarts a working service.
  expected=$(leaf_fingerprint "$TLS_DIR/current/fullchain.pem")
  check_listeners "$expected"
  if [ "$mismatch" = 1 ] && [ "${DNS_RESOLVER_TEST_FAIL_POSTCHECK:-0}" != 1 ]; then
    log "a listener serves another certificate; restarting Hickory"
    restart_hickory || true
    check_listeners "$expected"
  fi

  write_metrics \
    "dns_resolver_tls_acme_renew_success $renew_ok" \
    "dns_resolver_tls_activation_failed $activation_failed"
  [ "$activation_failed" = 0 ] && [ "$mismatch" = 0 ]
}

case ${1:-} in
  install) cmd_install ;;
  renew) lego_cmd renew --days "${RENEW_DAYS:-30}" --no-random-sleep ;;
  sync) cmd_sync ;;
  *) echo "usage: $0 install|renew|sync" >&2; exit 2 ;;
esac
