//+build ignore
#include <stddef.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <asm/types.h>
#include <linux/udp.h>
#include <linux/random.h>
#include <linux/net.h>
/* #include <netinet/in.h> */

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef _Bool bool;
#define MATCH_ALL 0

// These macros represent the direction of traffic in a packet and in a filter rule(to check when to evaluate it).
// Direction will be represented by u8
#define Ingress 0
#define Egress 1


// These offsets are defined as per the __sk_buf struct of a particular version. Might break??
#define OFFSET_PROTOCOL 4
#define OFFSET_REMOTE_IP 19
#define OFFSET_LOCAL_IP 20
#define OFFSET_REMOTE_PORT 23
#define OFFSET_LOCAL_PORT 24




extern int LINUX_KERNEL_VERSION __kconfig;
/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};
struct packet {
  u32 source_ip;
  u32 dest_ip;
  u32 size;
  u16 source_port;
  u16 dest_port;
  u8 protocol;
  bool is_dropped;
  u8 direction;
};

struct filter_rule {
  u32 source_ip;
  u16 source_port;
  u16 dest_port;
  u8 protocol;
  u8 direction;
};

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16777216 or 2^24 entries
} events SEC(".maps");

#define NO_OF_RULES 1 << 8

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct filter_rule);
  __uint(max_entries, NO_OF_RULES); // 256 or 2^8 filter rules
} filter_rules SEC(".maps");

// The same lookup_ctx will be used for both XDP and tc related filtering. Different fields will be set depending on filter_rule->direction.
struct lookup_ctx {
  struct packet *pk;
  struct filter_rule *fr;
  int xdp_output;
  int tc_output;
};

static void push_log(struct packet *pk) {
  struct packet *packet =
      bpf_ringbuf_reserve(&events, sizeof(struct packet), 0);
  if (!packet) {
    return;
  }

  packet->source_ip = pk->source_ip;
  packet->source_port = pk->source_port;
  packet->dest_ip = pk->dest_ip;
  packet->dest_port = pk->dest_port;
  packet->protocol = pk->protocol;
  packet->size = pk->size;
  packet->is_dropped = pk->is_dropped;

  bpf_ringbuf_submit(packet, 0);
}

static u64 filter_packet(struct bpf_map *map, u32 *key,
                         struct filter_rule *value, struct lookup_ctx *ctx) {
  struct packet *pk = ctx->pk;

  // DEBUGGING
  /*bpf_printk("Rule %u: %u %u %u %u. Packet %u %u %u %u", key,
     value->source_ip, value->source_port, value->dest_port, value->protocol,
       pk->source_ip, pk->source_port, pk->dest_port, pk->protocol);
  */

  if((value->direction == Ingress) && // Use XDP filtering on Ingress 
     (value->source_ip == MATCH_ALL || value->source_ip == pk->source_ip) && // match source IP 
     (value->source_port == MATCH_ALL || value->source_port == pk->source_port) && //match source port
     (value->dest_port == MATCH_ALL || value->dest_port == pk->dest_port) && // match destination port
     (value->protocol == MATCH_ALL || value->protocol == pk->protocol)){ // match protocol
          ctx->xdp_output = XDP_DROP;
          ctx->fr = value;
          return 1;
  }

  if((value->direction == Egress) && // Use tc filtering on Egress
     (value->source_ip == MATCH_ALL || value->source_ip == pk->source_ip) && // match source IP 
     (value->source_port == MATCH_ALL || value->source_port == pk->source_port) && //match source port
     (value->dest_port == MATCH_ALL || value->dest_port == pk->dest_port) && // match destination port
     (value->protocol == MATCH_ALL || value->protocol == pk->protocol)){ // match protocol
          ctx->tc_output = TC_ACT_SHOT;
          ctx->fr = value;
          return 1;
  }
  return 0;
}


SEC("tc")
int intercept_packets_tc_egress(struct __sk_buff *ctx){
  //Parse skbuff to create the packet struct and pass that to filter_packets
  struct packet pk;
  pk.direction = Egress;
  // We mark the start and end of our ethernet frame
  void *ethernet_start = (void *)(long)ctx->data;
  void *ethernet_end = (void *)(long)ctx->data_end;

  struct ethhdr *ethernet_frame = ethernet_start;
  // Check if we have the entire ethernet frame
  if ((void *)ethernet_frame + sizeof(*ethernet_frame) <= ethernet_end) {
    struct iphdr *ip_packet = ethernet_start + sizeof(*ethernet_frame);

    // Check if the IP packet is within the bounds of ethernet frame
    if ((void *)ip_packet + sizeof(*ip_packet) <= ethernet_end) {
          // extract info from the IP packet
      struct packet pk;
      pk.source_ip = ip_packet->saddr;
      pk.dest_ip = ip_packet->daddr;
      pk.protocol = ip_packet->protocol;
      pk.size = (ethernet_end - ethernet_start);
      pk.dest_port = pk.source_port = 0;
      pk.is_dropped = 0;
    }
          // check the protocol and get port
      if (pk.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip_packet + sizeof(*ip_packet);
        if ((void *)tcp + sizeof(*tcp) <= ethernet_end) {
          // Checking if the destination port matches with the specified port
          pk.source_port = tcp->source;
          pk.dest_port = tcp->dest;
        }
      }

      if (pk.protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip_packet + sizeof(*ip_packet);
        if ((void *)udp + sizeof(*udp) <= ethernet_end) {
          // Checking if the destination port matches with the specified port
          pk.source_port = udp->source;
          pk.dest_port = udp->dest;
        }
      }
      struct lookup_ctx data = {
          .pk = &pk,
          .tc_output = 0,
      };
      bpf_for_each_map_elem(&filter_rules, filter_packet, &data, 0);
        push_log(&pk);
      if(data.tc_output == TC_ACT_SHOT){
        return TC_ACT_SHOT;
      }
      return TC_ACT_OK;
  }
//------
  //First Try
  //create a copy of skbuff locally
  // currently failing verification
  // struct __sk_buff localskb;
  // int status = bpf_skb_load_bytes(skb,0,&localskb,sizeof(struct __sk_buff));
  // if (!status){
  //     return TC_ACT_SHOT; //for testing
  // }

  // pk.dest_ip = localskb.remote_ip4;
  // pk.dest_port = localskb.remote_port;
  // pk.source_ip = localskb.local_ip4;
  // pk.source_port = localskb.local_port;
  // pk.protocol = localskb.protocol;


  //Second Try
  //individually filling
  // bpf_skb_load_bytes(skb,sizeof(__u32)*OFFSET_REMOTE_IP,&pk.dest_ip,sizeof(__u32));
  // bpf_skb_load_bytes(skb,sizeof(__u32)*OFFSET_LOCAL_IP,&pk.source_ip,sizeof(__u32));
  // bpf_skb_load_bytes(skb,sizeof(__u32)*OFFSET_LOCAL_PORT,&pk.source_port,sizeof(__u32));
  // bpf_skb_load_bytes(skb,sizeof(__u32)*OFFSET_REMOTE_PORT,&pk.dest_port,sizeof(__u32));
  // bpf_skb_load_bytes(skb,sizeof(__u32)*OFFSET_PROTOCOL,&pk.protocol,sizeof(__u32));

  //Third Try
  //Direct packet access doesn't work with socket filter programs smh :(
  // pk.dest_ip = skb->remote_ip4;
  // pk.dest_port = skb->remote_port>>16;
  // pk.source_ip = skb->local_ip4;
  // pk.source_port = skb->local_port>>16;
  // pk.protocol = skb->protocol;

  // void *pktdata = (void* )(long)skb->data;
  // struct eth_hdr* eth = pktdata;
  // void *pktdata_end = (void*)(long)skb->data_end;
  // int key = 0,*ifindex;
  // int ret;

  // if (pktdata+sizeof(*eth)>pktdata_end){
  // push_log(&pk);
  // return TC_ACT_SHOT;
  // }
  //   struct iphdr *iph = pktdata+sizeof(*eth);
  //   pk.protocol = iph->protocol;
  //   pk.source_ip = iph->saddr;
  //   pk.dest_ip = iph->daddr;

  //testing 


  //------------

  // struct lookup_ctx data = {
  //   .pk = &pk,
  //   .tc_output = 0,
  // };
  // bpf_for_each_map_elem(&filter_rules, filter_packet, &data, 0);
  
//   if(data.tc_output == TC_ACT_SHOT){
//         pk.is_dropped = 1;
//         struct filter_rule *fr = data.fr;
//         // network security event logs only work on kernel 5.16
// #if LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 16, 0)
//         bpf_printk("Rule: %u %u %u %u. Packet %u %u %u %u", fr->source_ip,
//                    fr->source_port, fr->dest_port, fr->protocol, pk.source_ip,
//                    pk.source_port, pk.dest_port, pk.protocol);
// #endif
//         push_log(&pk);
//         return TC_ACT_SHOT;

//   }
  pk.source_ip = 100;
  push_log(&pk);
  return TC_ACT_SHOT;
}


SEC("xdp")
int intercept_packets_xdp_ingress(struct xdp_md *ctx) {
  // We mark the start and end of our ethernet frame
  void *ethernet_start = (void *)(long)ctx->data;
  void *ethernet_end = (void *)(long)ctx->data_end;

  struct ethhdr *ethernet_frame = ethernet_start;

  // Check if we have the entire ethernet frame
  if ((void *)ethernet_frame + sizeof(*ethernet_frame) <= ethernet_end) {
    struct iphdr *ip_packet = ethernet_start + sizeof(*ethernet_frame);

    // Check if the IP packet is within the bounds of ethernet frame
    if ((void *)ip_packet + sizeof(*ip_packet) <= ethernet_end) {

      // extract info from the IP packet
      struct packet pk;
      pk.source_ip = ip_packet->saddr;
      pk.dest_ip = ip_packet->daddr;
      pk.protocol = ip_packet->protocol;
      pk.size = (ethernet_end - ethernet_start);
      pk.dest_port = pk.source_port = 0;
      pk.is_dropped = 0;
      pk.direction = Ingress;
      // check the protocol and get port
      if (pk.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip_packet + sizeof(*ip_packet);
        if ((void *)tcp + sizeof(*tcp) <= ethernet_end) {
          // Checking if the destination port matches with the specified port
          pk.source_port = tcp->source;
          pk.dest_port = tcp->dest;
        }
      }

      if (pk.protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip_packet + sizeof(*ip_packet);
        if ((void *)udp + sizeof(*udp) <= ethernet_end) {
          // Checking if the destination port matches with the specified port
          pk.source_port = udp->source;
          pk.dest_port = udp->dest;
        }
      }

      struct lookup_ctx data = {
          .pk = &pk,
          .xdp_output = 0,
      };

      bpf_for_each_map_elem(&filter_rules, filter_packet, &data, 0);

      if (data.xdp_output == XDP_DROP) {
        pk.is_dropped = 1;
        struct filter_rule *fr = data.fr;
        // network security event logs only work on kernel 5.16
#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 16, 0)
        bpf_printk("Rule: %u %u %u %u. Packet %u %u %u %u", fr->source_ip,
                   fr->source_port, fr->dest_port, fr->protocol, pk.source_ip,
                   pk.source_port, pk.dest_port, pk.protocol);
#endif
        push_log(&pk);
        return XDP_DROP;
      }

      push_log(&pk);
    }
  }

  return XDP_PASS;
}

char _license[4] SEC("license") = "GPL";
