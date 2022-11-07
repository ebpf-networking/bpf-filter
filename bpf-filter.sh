#!/bin/bash

set -x

VETH_IFACE=${VETH_NAME:-veth1}
VETH_IFACE_IDX=${VETH_ID}

BPF_PROG=${3:-./bin/bpf/drop.o}

BPF_USER="./bin/main"

#run user prog for programming maps
CMD=${user}" --mode add --idx "${iface_idx}
${CMD}
if [ $? -eq 1 ]
then
    echo ${CMD}" failed error code "$?
    exit 1
fi

echo "Attaching bpf-filter to tc hookpoint"
tc qdisc add dev ${iface} clsact
tc filter add dev ${iface} ingress bpf da obj ${prog} sec classifier_ingress_drop
tc filter add dev ${iface} egress bpf da obj ${prog} sec classifier_egress_drop

set +x