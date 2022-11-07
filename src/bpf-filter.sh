#!/bin/bash

iface=${1:-veth1}
iface_idx=${2}
prog=${3:-./bin/bpf/drop.o}
user="./bin/main"
cmd=${user}" --mode add --idx "${iface_idx}
echo ${cmd}
#run user prog for programming maps
${cmd}
echo $?
echo "GOing to Attach"
tc qdisc add dev ${iface} clsact
tc filter add dev ${iface} ingress bpf da obj ${prog} sec classifier_ingress_drop
tc filter add dev ${iface} egress bpf da obj ${prog} sec classifier_egress_drop

