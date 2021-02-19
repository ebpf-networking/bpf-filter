BUILD=build

.PHONY: all
.default: drop

${BUILD}:
	mkdir -p ${BUILD}	

drop: ${BUILD}
	clang -O2 -g -Wall -Werror -emit-llvm -c drop.c -o ${BUILD}/drop.bc
	llc -march=bpf -mcpu=probe -filetype=obj ${BUILD}/drop.bc -o ${BUILD}/drop.o

tc: ${BUILD}
	clang -O2 -g -Wall -Werror -emit-llvm -c tc-example.c -o ${BUILD}/tc-example.bc
	llc -march=bpf -mcpu=probe -filetype=obj ${BUILD}/tc-example.bc -o ${BUILD}/tc-example.o

drop-install: drop
	tc filter add dev eth0 ingress bpf da obj drop.o sec classifier_ingress_drop 
	tc filter add dev eth0 egress bpf da obj drop.o sec classifier_egress_drop

tc-install: tc
	tc filter add dev eth0 ingress bpf da obj tc-example.o sec ingress
	tc filter add dev eth0 egress bpf da obj tc-example.o sec egress

show:
	tc filter show dev eth0 ingress
	tc filter show dev eth0 egress

clean:
	-$(RM) -r ${BUILD}
