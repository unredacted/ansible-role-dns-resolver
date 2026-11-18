# Test image for molecule: Debian 13 with systemd as PID 1.
# Dependabot keeps the digest current.
FROM debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus python3 python3-apt sudo ca-certificates iproute2 \
 && rm -f /lib/systemd/system/multi-user.target.wants/getty.target
# The apt lists are kept on purpose. Without them, apt's cache looks fresh to
# Ansible (cache_valid_time) but holds no packages.

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
