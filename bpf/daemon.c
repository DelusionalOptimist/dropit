//+build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

extern int LINUX_KERNEL_VERSION __kconfig;

struct packet {
  u32 source_ip;
  u32 dest_ip;
  u32 size;
  u16 source_port;
  u16 dest_port;
  u8 protocol;
  bool is_dropped;
};

struct filter_rule {
  u32 source_ip;
  u16 source_port;
  u16 dest_port;
  u8 protocol;
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

struct lookup_ctx {
  struct packet *pk;
  struct filter_rule *fr;
  int output;
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

  if( (value->source_ip == 0 || value->source_ip == pk->source_ip) && // match source IP 
      (value->source_port == 0 || value->source_port == pk->source_port) && //match source port
      (value->dest_port == 0 || value->dest_port == pk->dest_port) && // match destination port
      (value->protocol == 0 || value->protocol == pk->protocol)){ // match protocol
          ctx->output = XDP_DROP;
          ctx->fr = value;
          return 1;
      }
  return 0;
}

SEC("xdp")
int intercept_packets(struct xdp_md *ctx) {
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
          .output = 0,
      };

      bpf_for_each_map_elem(&filter_rules, filter_packet, &data, 0);

      if (data.output == XDP_DROP) {
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
