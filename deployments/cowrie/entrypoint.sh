#!/bin/sh

set -eu

mkdir -p /opt/cowrie-src/var/log/cowrie \
    /opt/cowrie-src/var/lib/cowrie/downloads \
    /opt/cowrie-src/var/lib/cowrie/tty

exec /opt/cowrie-src/bin/cowrie start -n
