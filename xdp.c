// +build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// One /24
#define MAX_MAP_ENTRIES 256

struct bpf_map_def SEC("maps") allowance_table = {
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .max_entries = MAX_MAP_ENTRIES,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .map_flags = 0,
};

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_dst_addr(struct xdp_md *ctx, __u32 *ip_src_addr, __u32 *ip_dst_addr)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // First, parse the ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // The protocol is not IPv4, so we can't parse an IPv4 source address.
        return 0;
    }

    // Then parse the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return 0;
    }

    // Return the source IP address in network byte order.
    *ip_src_addr = (__u32)(ip->saddr);
    *ip_dst_addr = (__u32)(ip->daddr);

    return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
    __u32 src_ip, dst_ip;
    if (!parse_ip_src_dst_addr(ctx, &src_ip, &dst_ip))
    {
        goto done;
    }

    __u8 *blocked = bpf_map_lookup_elem(&allowance_table, &src_ip);
    if (blocked)
    {

        return XDP_PASS;
    }

done:
    // Try changing this to XDP_DROP and see what happens!
    return XDP_DROP;
}