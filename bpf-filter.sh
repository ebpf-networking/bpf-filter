#!/bin/bash

iface=${VETH_NAME}
iface_id=${VETH_ID}
namespace=${NAMESPACE}
iface_mac=${VPEER_MAC}

BPF_PROG=${3:-./bin/bpf/drop.o}

TC='/sbin/tc'
BPF_USER="./bin/main"

#run user prog for programming maps
CMD=${BPF_USER}" --mode add --idx "${iface_id}" --mac "${iface_mac}

echo "${CMD}"
${CMD}
if [ $? -eq 1 ]
then
    echo ${CMD}" failed error code "$?
    exit 1
fi

echo "Attaching bpf-filter to tc hookpoint"
set -x
    ${TC} qdisc add dev ${iface} clsact
    ${TC} filter add dev ${iface} egress bpf da obj ${BPF_PROG} sec classifier_ingress_drop
    ${TC} filter add dev ${iface} ingress bpf da obj ${BPF_PROG} sec classifier_egress_drop
set +x