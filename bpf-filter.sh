#!/bin/bash

set -x

iface=${VETH_NAME:-veth1}
veth_id=${VETH_ID}
vpeer_mac=${VPEER_MAC}

BPF_PROG=${3:-./bin/bpf/drop.o}

BPF_USER="./bin/bpf-filter-user"

#run user prog for programming maps
CMD=${BPF_USER}" --mode add --idx "${veth_id}" --mac "${vpeer_mac}
${CMD}
if [ $? -eq 1 ]
then
    echo ${CMD}" failed error code "$?
    exit 1
fi

echo "Attaching bpf-filter to tc hookpoint"
tc qdisc add dev ${iface} clsact
tc filter add dev ${iface} ingress bpf da obj ${BPF_PROG} sec classifier_ingress_drop
tc filter add dev ${iface} egress bpf da obj ${BPF_PROG} sec classifier_egress_drop

set +x