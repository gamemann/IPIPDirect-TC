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

#include "include/common.h"
#include "include/bpf_helpers.h"

// Uncomment this line if you want to exempt A2S_INFO responses from being sent directly. https://developer.valvesoftware.com/wiki/Server_queries#A2S_INFO
//#define EXCLUDE_A2S_INFO

// Debug
//#define DEBUG

#define ETH_LEN sizeof(struct ethhdr)

#define ETH_DEST_OFF (offsetof(struct ethhdr, h_dest))
#define IP_CHECK_OFF (ETH_LEN + offsetof(struct iphdr, check))
#define IP_SADDR_OFF (ETH_LEN + offsetof(struct iphdr, saddr))

// MAC map for gateway interface's MAC address. The program only worked for me if I had the Ethernet header's destination MAC address set to the gateway.
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} mac_map SEC(".maps");

SEC("tc/egress")
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

#ifdef EXCLUDE_A2S_INFO
            // Before we move ahead, let's check for A2S_INFO response and exempt that from modification.
            if (inner_ip->protocol == IPPROTO_UDP)
            {
                // Initialize UDP header.
                struct udphdr *udphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_ip->ihl * 4);

                // Check UDP header length.
                if (unlikely(udphdr + 1 > (struct udphdr *)data_end))
                {
                    return TC_ACT_SHOT;
                }

                // Initialize UDP data.
                uint8_t *pcktData = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + (inner_ip->ihl * 4) + sizeof(struct udphdr);

                // Check UDP data length.
                if (!(pcktData + 5 > (uint8_t *)data_end))
                {
                    // Check first byte of data and see if it matches A2S_INFO response header. If it does, pass to upper layers and ignore packet modification.
                    if ((*pcktData++) == 0xFF && (*pcktData++) == 0xFF && (*pcktData++) == 0xFF && (*pcktData++) == 0xFF && (*pcktData) == 0x49)
                    {
                        return TC_ACT_OK;
                    }
                }
            }
#endif

            // Save inner IP source address for checksum calculation later on..
            uint32_t oldAddr;
            oldAddr = inner_ip->saddr;

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
            bpf_l3_csum_replace(skb, IP_CHECK_OFF, oldAddr, forwardAddr, sizeof(forwardAddr));

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
            bpf_skb_store_bytes(skb, IP_SADDR_OFF, &forwardAddr, sizeof(forwardAddr), 0);

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
                #ifdef DEBUG
                // Print debug message. This can be found by performing 'cat /sys/kernel/debug/tracing/trace_pipe'.
                //printk("MAC map bad value.\n");
                #endif

                return TC_ACT_OK;
            }

            uint8_t dstMAC[ETH_ALEN];

            int2mac(*val, dstMAC);

            // Replace destination MAC.
            bpf_skb_store_bytes(skb, ETH_DEST_OFF, &dstMAC, ETH_ALEN, 0);

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

                    uint32_t offset = sizeof(struct ethhdr) + (iphdr->ihl * 4) + offsetof(struct udphdr, check);

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
                    uint32_t offset = sizeof(struct ethhdr) + (iphdr->ihl * 4) + offsetof(struct tcphdr, check);

                    // Recalculate layer four checksum (TCP checksum).
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