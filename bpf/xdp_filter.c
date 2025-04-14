/* SPDX-License-Identifier: GPL-2.0 */
#include "common.h"

/* 필터링 룰 맵 정의 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct filter_key);
    __type(value, struct filter_value);
} filter_map SEC(".maps");

/* 검사를 위해 패킷을 사용자 공간으로 전달하는 맵 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} inspect_map SEC(".maps");

/* IP 체크섬 계산 */
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    return ~((csum & 0xffff) + (csum >> 16));
}

/* 메인 XDP 필터 프로그램 */
SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    /* 이더넷 헤더 파싱 */
    struct ethhdr *eth = data;
    if (eth + 1 > data_end)
        return XDP_DROP;
        
    /* IP 패킷이 아니면 통과 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    /* IP 헤더 파싱 */
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if (iph + 1 > data_end)
        return XDP_DROP;
        
    /* 필터링 룰 키 설정 */
    struct filter_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .proto = iph->protocol,
        .src_port = 0,
        .dst_port = 0
    };
    
    /* TCP/UDP 포트 정보 추출 */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if (tcph + 1 > data_end)
            return XDP_DROP;
            
        key.src_port = bpf_ntohs(tcph->source);
        key.dst_port = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if (udph + 1 > data_end)
            return XDP_DROP;
            
        key.src_port = bpf_ntohs(udph->source);
        key.dst_port = bpf_ntohs(udph->dest);
    }
    
    /* 필터링 룰 맵에서 룰 확인 */
    struct filter_value *value = bpf_map_lookup_elem(&filter_map, &key);
    if (value) {
        /* 룰에 따라 액션 수행 */
        if (value->action == XDP_DROP) {
            return XDP_DROP;
        } else if (value->action == XDP_INSPECT) {
            /* 패킷 데이터를 사용자 공간으로 전달 */
            bpf_perf_event_output(ctx, &inspect_map, BPF_F_CURRENT_CPU, 
                                  ctx->data, ctx->data_end - ctx->data);
        }
    }
    
    /* 기본적으로 패킷 통과 */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
