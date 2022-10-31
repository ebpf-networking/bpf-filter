#!/bin/bash

iface=${1:-veth1}
prog=${2:-./bin/drop.o}
user="main"

#run user prog for programming maps
exec ${user}

tc qdisc add dev ${iface} clsact
tc filter add dev ${iface} ingress bpf da obj ${prog} sec classifier_ingress_drop
tc filter add dev ${iface} egress bpf da obj ${prog} sec classifier_egress_drop

