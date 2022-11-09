#!/bin/bash

iface=${VPEER_NAME}
iface_id=${VPEER_ID}
namespace=${NAMESPACE}
mac_arg="INVALID"

BPF_PROG=${3:-./bin/bpf/drop.o}

BPF_USER="./bin/bpf-filter-user"

#run user prog for programming maps
CMD=${BPF_USER}" --mode add --idx "${iface_id}" --mac "${mac_arg}

ip netns exec ${namespace} ${CMD}
if [ $? -eq 1 ]
then
    echo ${CMD}" failed error code "$?
    exit 1
fi

echo "Attaching bpf-filter to tc hookpoint"
ip netns exec ${namespace} tc qdisc add dev ${iface} clsact
ip netns exec ${namespace} tc filter add dev ${iface} ingress bpf da obj ${BPF_PROG} sec classifier_ingress_drop
ip netns exec ${namespace} tc filter add dev ${iface} egress bpf da obj ${BPF_PROG} sec classifier_egress_drop