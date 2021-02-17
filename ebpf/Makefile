clean:
	-$(RM) drop tc-example

drop:
	clang -O2 -g -Wall -Werror -emit-llvm -c drop.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o drop

tc:	
	clang -O2 -g -Wall -Werror -emit-llvm -c tc-example.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o tc-example.o

tc-install:
	tc filter add dev eth0 ingress bpf da obj tc-example.o sec ingress
	tc filter add dev eth0 egress bpf da obj tc-example.o sec egress

show:
	tc filter show dev eth0 ingress
	tc filter show dev eth0 egress

drop-install:
	tc filter add dev eth0 ingress bpf da obj drop sec classifier_ingress_drop 
	tc filter add dev eth0 egress bpf da obj drop sec classifier_egress_drop
