/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 필터링 액션 정의 */
enum xdp_action {
    XDP_PASS = 0,       /* 패킷 통과 */
    XDP_DROP = 1,       /* 패킷 차단 */
    XDP_INSPECT = 2,    /* 패킷 검사를 위해 사용자 공간으로 전달 */
};

/* 필터링 룰 키 */
struct filter_key {
    __u32 src_ip;       /* 소스 IP 주소 */
    __u32 dst_ip;       /* 목적지 IP 주소 */
    __u16 src_port;     /* 소스 포트 */
    __u16 dst_port;     /* 목적지 포트 */
    __u8 proto;         /* 프로토콜 (TCP/UDP) */
};

/* 필터링 룰 값 */
struct filter_value {
    __u8 action;        /* 취할 액션 (XDP_PASS, XDP_DROP, XDP_INSPECT) */
};

#endif /* __COMMON_H */
