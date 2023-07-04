//+build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct packet {
  u32 source_ip;
  u32 dest_ip;
  u32 size;
  u16 source_port;
  u16 dest_port;
  u8 protocol;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

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

  bpf_ringbuf_submit(packet, 0);
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

      // bpf_trace_printk("%d", pk.dest_ip);
      // bpf_trace_printk("%d", pk.protocol);

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

      push_log(&pk);
    }
  }

  return XDP_PASS;
}
