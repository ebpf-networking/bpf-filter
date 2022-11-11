#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "parsing_helpers.h"


#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
	inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
	((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
	(*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

//#define bpf_htonl __builtin_bswap32
#define bpf_memcpy __builtin_memcpy

#define EGRESS_MODE 0
#define INGRESS_MODE 1
#define MAXELEM 2000



typedef struct cnt_pkt {
	uint32_t drop;
	uint32_t pass;
} pkt_count;

typedef struct iface_desc {
  __u8 mac[ETH_ALEN];
  __u32 ip;
} iface_desc;

#define IP_LEN 4

struct bpf_elf_map iface_map __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(uint32_t),
	.size_value     = ETH_ALEN,
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAXELEM,
};


struct bpf_elf_map iface_ip_map __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(__be32),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAXELEM,
};


struct bpf_elf_map egress_iface_stat_map  __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(pkt_count),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAXELEM,
};

struct bpf_elf_map ingress_iface_stat_map  __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(pkt_count),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAXELEM,
};


/* helper functions called from eBPF programs */
//static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
//	        (void *) BPF_FUNC_trace_printk;

static __inline int match_mac( struct __sk_buff *skb, uint32_t mode) {

	char pkt_fmt[]	 = "MAC_FILTER: pkt skb: %x %x %x\n";
	char src_fmt[] 	 = "MAC_FILTER: source mac: %x %x %x\n";
	char matched[] 	 = "MAC_FILTER: MAC MATCHED\n";
	char unmatched[] = "MAC_FILTER: MAC DID NOT MATCH\n";
	char ip_matched[] 	 = "IP_FILTER: IP MATCHED\n";
	char ip_unmatched[] = "IP_FILTER: IP DID NOT MATCH\n";


	
	uint32_t *bytes;
	pkt_count *inf;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr  *eth  = data;
	struct iphdr *ip;
	struct hdr_cursor nh;
	int nh_type;


	uint32_t idx = skb->ifindex;	

	if(data_end < (void*)eth + sizeof(struct ethhdr))
		return TC_ACT_SHOT;

	nh.pos = data;
	nh_type = parse_iphdr(&nh, data_end, &ip);
	if (nh_type == -1)
	  return TC_ACT_SHOT;
	


	if(mode == EGRESS_MODE){
	 	inf = bpf_map_lookup_elem(&egress_iface_stat_map, &(idx));
	} else{
	  	inf = bpf_map_lookup_elem(&ingress_iface_stat_map, &(idx));
	}
	
	if (!inf){
		//haven't found the stat-entry, unexpected behavior, let packet go through.
		return TC_ACT_OK;
	}

	bytes = bpf_map_lookup_elem(&iface_map, &(idx));
	if (bytes) {
		__u8 iface_mac[ETH_ALEN];
		__u8 pkt_mac[ETH_ALEN];

		bpf_memcpy(iface_mac, bytes, ETH_ALEN);

		if (mode == EGRESS_MODE) {
			bpf_memcpy(pkt_mac, eth->h_source, ETH_ALEN);
		} else {
			bpf_memcpy(pkt_mac, eth->h_dest, ETH_ALEN);
		}

		bpf_trace_printk(src_fmt, sizeof(src_fmt), 
			iface_mac[0],iface_mac[1],iface_mac[2]);
		bpf_trace_printk(src_fmt, sizeof(src_fmt), 
			iface_mac[3],iface_mac[4],iface_mac[5]);
		bpf_trace_printk(pkt_fmt, sizeof(pkt_fmt), 
			pkt_mac[0],pkt_mac[1],pkt_mac[2]);
		bpf_trace_printk(pkt_fmt, sizeof(pkt_fmt), 
			pkt_mac[3],pkt_mac[4],pkt_mac[5]);

		//check if the MAC matches and return TC_ACT_OK
	       	if(iface_mac[0] == pkt_mac[0] &&
	       	   iface_mac[1] == pkt_mac[1] &&
	       	   iface_mac[2] == pkt_mac[2] &&
	       	   iface_mac[3] == pkt_mac[3] &&
	       	   iface_mac[4] == pkt_mac[4] &&
	       	   iface_mac[5] == pkt_mac[5]){
			bpf_trace_printk(matched, sizeof(matched));
			if(idx < MAXELEM){
				lock_xadd(&(inf->pass), 1);
			}
			return TC_ACT_OK;	
		}

		if(idx < MAXELEM){
			lock_xadd(&(inf->drop), 1);
		}

		bpf_trace_printk(unmatched, sizeof(unmatched));
		return TC_ACT_SHOT;
	} else {
		/* Unable to get iface MAC. Let the packet through */
		return TC_ACT_OK;
	}

	// IP addresss match
	bytes = bpf_map_lookup_elem(&iface_ip_map, &(idx));
	if (bytes) {
	  __be32 pkt_ip;
		if (mode == EGRESS_MODE) {
		  pkt_ip=ip->saddr;
		} else {
		  pkt_ip = ip->daddr;

		}
		__be32 iface_ip;
		bpf_memcpy(&iface_ip, bytes, sizeof(__be32));
		if(iface_ip == pkt_ip){
		  bpf_trace_printk(ip_matched, sizeof(ip_matched));
		  lock_xadd(&(inf->pass), 1);
		  return TC_ACT_OK;	

		} else{
		  lock_xadd(&(inf->drop), 1);
		  bpf_trace_printk(ip_unmatched, sizeof(ip_unmatched));
		  return TC_ACT_SHOT;
		}

		
	} else {
		/* Unable to get iface IP. Let the packet through */
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

__section("classifier_egress_drop") int egress_drop(struct __sk_buff *skb) {
	return match_mac(skb, EGRESS_MODE);
}

__section("classifier_ingress_drop") int ingress_drop(struct __sk_buff *skb) {
	return match_mac(skb, INGRESS_MODE);
}
