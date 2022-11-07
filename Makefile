BINDIR=bin
EXEC=main

BPFDIR=ebpf
BPFBIN=${BINDIR}/bpf
BPFEXEC=drop

.PHONY: all
.default: ${EXEC}

${EXEC}: ${BINDIR} drop
	go build -o ${BINDIR}/${EXEC} ${EXEC}.go

drop: ${BPFBIN}
	clang -O2 -g -Wall -emit-llvm -c ${BPFDIR}/drop.c -o ${BPFBIN}/drop.bc
	llc -march=bpf -mcpu=probe -filetype=obj ${BPFBIN}/drop.bc -o ${BPFBIN}/drop.o

drop-install: drop
	tc qdisc add dev eth0 clsact
	tc filter add dev eth0 ingress bpf da obj ${BPFBIN}/drop.o sec classifier_ingress_drop
	tc filter add dev eth0 egress bpf da obj ${BPFBIN}/drop.o sec classifier_egress_drop

drop-uninstall:
	tc qdisc del dev eth0 clsact

show:
	tc filter show dev eth0 ingress
	tc filter show dev eth0 egress

${BINDIR}:
	mkdir -p ${BINDIR}

${BPFBIN}:
	mkdir -p ${BPFBIN}

clean:
	rm -r ${BINDIR}

clean-maps:
	rm -r /sys/fs/bpf/tc/globals/*
