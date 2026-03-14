#!/bin/sh
set -eu

cleanup() {
    ovs-appctl -t ovs-vswitchd exit >/dev/null 2>&1 || true
    ovs-appctl -t ovsdb-server exit >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch

if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

if ! pgrep -x ovsdb-server >/dev/null 2>&1; then
    ovsdb-server \
        --remote=punix:/var/run/openvswitch/db.sock \
        --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
        --pidfile \
        --detach \
        --log-file
fi

ovs-vsctl --no-wait init

if ! pgrep -x ovs-vswitchd >/dev/null 2>&1; then
    ovs-vswitchd unix:/var/run/openvswitch/db.sock \
        --pidfile \
        --detach \
        --log-file
fi

exec "$@"
