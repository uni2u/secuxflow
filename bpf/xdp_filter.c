/* SPDX-License-Identifier: GPL-2.0 */
#include "common.h"

#define INSPECT_K_THRESHOLD 12

/* 필터링 룰 맵 정의 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct filter_key);
    __type(value, struct filter_value);
} filter_map SEC(".maps");

/* 플로우별 패킷 카운터 (Stateful Path: k값 추적용) */
struct flow_stats {
    __u32 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct filter_key);
    __type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

/* 검사를 위해 패킷을 사용자 공간으로 전달하는 맵 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} inspect_map SEC(".maps");

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
    
    // 기본 필터링
    struct filter_value *value = bpf_map_lookup_elem(&filter_map, &key);
    if (!value)
        return XDP_PASS;

    // Action이 DROP일 때
    if (value->action == XDP_DROP) {
        return XDP_DROP;
    }

    // Action이 INSPECT일 때
    else if (value->action == XDP_INSPECT) {
        struct flow_stats *stats = bpf_map_lookup_elem(&flow_stats_map, &key);

        if (stats) {
            // k(12)개 미만일 때만 WASM으로 전송
            if (stats->packet_count < INSPECT_K_THRESHOLD) {
                __sync_fetch_and_add(&stats->packet_count, 1);
                bpf_perf_event_output(ctx, &inspect_map, BPF_F_CURRENT_CPU, data, data_end - data);
                return XDP_PASS; // 유저 공간 분석 중이므로 통과
            }
            // k개 이상이면 더 이상 WASM으로 보내지 않고 즉시 통과 (Early Exit)
            return XDP_PASS;
        } else {
            // 새로운 플로우 등록 및 첫 번째 패킷 전송
            struct flow_stats new_stats = { .packet_count = 1 };
            bpf_map_update_elem(&flow_stats_map, &key, &new_stats, BPF_ANY);
            bpf_perf_event_output(ctx, &inspect_map, BPF_F_CURRENT_CPU, data, data_end - data);
            return XDP_PASS;
        }
    }
    
    /* 기본적으로 패킷 통과 */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
