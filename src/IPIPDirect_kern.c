#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <inttypes.h>

#ifndef __BPF__
#define __BPF__
#endif

#include "include/bpf_helpers.h"
#include "include/common.h"

#define PIN_GLOBAL_NS 2

struct bpf_elf_map 
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

// MAC map for gateway interface's MAC address. The program only worked for me if I had the Ethernet header's destination MAC address set to the gateway.
struct bpf_elf_map SEC("maps") mac_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint64_t),
    .max_elem = 1,
    .pinning = PIN_GLOBAL_NS
};

SEC("egress")
int tc_egress(struct __sk_buff *skb)
{
    // Initialize packet data.
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Initialize Ethernet header. 
    struct ethhdr *ethhdr = data;

    // Check Ethernet header's length.
    if (ethhdr + 1 > (struct ethhdr *)data_end)
    {
        return TC_ACT_OK;
    }

    // Check Ethernet protocol and ensure it's IP.
    if (likely(ethhdr->h_proto == htons(ETH_P_IP)))
    {
        // Initialize outer IP header.
        struct iphdr *iphdr = data + sizeof(struct ethhdr);

        // Check outer IP header's length.
        if (unlikely(iphdr + 1 > (struct iphdr *)data_end))
        {
            return TC_ACT_SHOT;
        }

        // Check for IPIP protocol.
        if (iphdr->protocol == IPPROTO_IPIP)
        {
            // Initialize inner IP header.            
            struct iphdr *inner_ip = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

            // Check inner IP header length.
            if (unlikely(inner_ip + 1 > (struct iphdr *)data_end))
            {
                return TC_ACT_SHOT;
            }

            // Save inner IP source address for checksum calculation later on..
            uint32_t oldAddr;
            oldAddr = inner_ip->saddr;

            // Initialize offset.
            int offset;

            // Save forwarding address.
            uint32_t forwardAddr = iphdr->daddr;

            // Remove outer IP header and check if it was successful.
            if (bpf_skb_adjust_room(skb, -(int)sizeof(struct iphdr), BPF_ADJ_ROOM_MAC, 0) != 0)
            {
                return TC_ACT_SHOT;
            }
            
            // Reinitialize values.
            data_end = (void *)(long)skb->data_end;
            data = (void *)(long)skb->data;
            iphdr = data + sizeof(struct ethhdr);

            // Check IP header length.
            if (iphdr + 1 > (struct iphdr *)data_end)
            {
                return TC_ACT_OK;
            }

            // Recalculate layer three checksum (IP header).
            offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
            bpf_l3_csum_replace(skb, offset, oldAddr, forwardAddr, sizeof(forwardAddr));

            // Reinitialize values.
            data_end = (void *)(long)skb->data_end;
            data = (void *)(long)skb->data;
            iphdr = data + sizeof(struct ethhdr);

            // Check IP header length.
            if (iphdr + 1 > (struct iphdr *)data_end)
            {
                return TC_ACT_OK;
            }
            
            // Change source address to forwarding address.
            offset = sizeof(struct ethhdr) + offsetof(struct iphdr, saddr);
            bpf_skb_store_bytes(skb, offset, &forwardAddr, sizeof(forwardAddr), 0);

            // Reinitialize values.
            data_end = (void *)(long)skb->data_end;
            data = (void *)(long)skb->data;
            iphdr = data + sizeof(struct ethhdr);

            // Check IP header length.
            if (iphdr + 1 > (struct iphdr *)data_end)
            {
                return TC_ACT_OK;
            }

            // Check for gateway address from BPF map.
            uint64_t *val;
            uint32_t key = 0;

            val = bpf_map_lookup_elem(&mac_map, &key);

            if (!val)
            {
                // Print debug message. This can be found by performing 'cat /sys/kernel/debug/tracing/trace_pipe'.
                printk("MAC map bad value.\n");

                return TC_ACT_OK;
            }

            uint8_t dstMAC[ETH_ALEN];

            int2mac(*val, dstMAC);

            // Get offset of destination MAC in Ethernet header.
            offset = offsetof(struct ethhdr, h_dest);

            // Replace destination MAC.
            bpf_skb_store_bytes(skb, offset, &dstMAC, ETH_ALEN, 0);

            // Reinitialize values.
            data_end = (void *)(long)skb->data_end;
            data = (void *)(long)skb->data;
            iphdr = data + sizeof(struct ethhdr);

            // Check IP header length.
            if (iphdr + 1 > (struct iphdr *)data_end)
            {
                return TC_ACT_OK;
            }

            // Recalculate transport protocol header.
            switch (iphdr->protocol)
            {
                case IPPROTO_UDP:
                {
                    // Initialize UDP header.
                    struct udphdr *udphdr = data + sizeof(struct ethhdr) + (iphdr->ihl * 4);

                    // Check UDP header length.
                    if (udphdr + 1 > (struct udphdr *)data_end)
                    {
                        return TC_ACT_SHOT;
                    }

                    // Get UDP header checksum's offset.
                    offset = sizeof(struct ethhdr) + (iphdr->ihl * 4) + offsetof(struct udphdr, check);

                    // Recalculate layer four checksum (UDP checksum).
                    bpf_l4_csum_replace(skb, offset, oldAddr, iphdr->saddr, 0x10 | sizeof(iphdr->saddr));

                    break;
                }

                case IPPROTO_TCP:
                {
                    // Initialize TCP header.
                    struct tcphdr *tcphdr = data + sizeof(struct ethhdr) + (iphdr->ihl * 4);

                    // Check TCP header length.
                    if (tcphdr + 1 > (struct tcphdr *)data_end)
                    {
                        return TC_ACT_SHOT;
                    }

                    // Get TCP header checksum's offset.
                    offset = sizeof(struct ethhdr) + (iphdr->ihl * 4) + offsetof(struct tcphdr, check);

                    // Recalculate layer four checksum (TCP checksum).
                    bpf_l4_csum_replace(skb, offset, oldAddr, iphdr->saddr, 0x10 | sizeof(iphdr->saddr));

                    break;
                }

                case IPPROTO_ICMP:
                {
                    // Initialize ICMP header.
                    struct icmphdr *icmphdr = data + sizeof(struct ethhdr) + (iphdr->ihl * 4);

                    // Check ICMP header length.
                    if (icmphdr + 1 > (struct icmphdr *)data_end)
                    {
                        return TC_ACT_SHOT;
                    }

                    // Get ICMP header checksum's offset.
                    offset = sizeof(struct ethhdr) + (iphdr->ihl * 4) + offsetof(struct icmphdr, checksum);

                    // Recalculate layer four checksum (ICMP header).
                    bpf_l4_csum_replace(skb, offset, oldAddr, iphdr->saddr, 0x10 | sizeof(iphdr->saddr));

                    break;
                }
            }
        }
    }

    // Pass packet to upper layers.
    return TC_ACT_OK;
}

// License.
char __license[] SEC("license") = "GPL";