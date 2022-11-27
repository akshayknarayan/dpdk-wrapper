#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mem.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_udp.h>
#include <rte_flow.h>
#include <rte_thash.h>
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef unsigned long physaddr_t;
typedef unsigned long virtaddr_t;

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define RX_PACKET_LEN 9216
#define MBUF_HEADER_SIZE 64
#define MBUF_PRIV_SIZE 8
#define PGSIZE_2MB (1 <<  21)
#define MAX_CORES 6

struct rte_mbuf* rte_pktmbuf_alloc_(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

void rte_pktmbuf_free_(struct rte_mbuf *packet) {
    rte_pktmbuf_free(packet);
}

uint16_t rte_eth_tx_burst_(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

uint16_t rte_eth_rx_burst_(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, const uint16_t nb_pkts) {
    uint16_t ret = rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
    return ret;
}

int rte_errno_() {
    return rte_errno;
}

void rte_memcpy_(void *dst, const void *src, size_t n) {
    rte_memcpy(dst, src, n);
}

uint32_t make_ip_(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (((uint32_t) a << 24) | ((uint32_t) b << 16) |	\
	 ((uint32_t) c << 8) | (uint32_t) d);
}

bool parse_packet_(
    struct rte_mbuf *mbuf,  // the packet to parse.
    const struct rte_ether_addr *our_eth,  // our local ethernet address, to compare eth_hdr.dst_addr to
    uint32_t our_ip,  // our local ip address, to compare ip_hdr.dst_addr to
    struct rte_ether_addr *eth_src_addr, // out: the packet's ethernet source addr
    uint32_t *ip_src_addr, // out: the packet's ip source addr
    uint16_t *udp_src_port, // out: the packet's udp src port
    uint16_t *udp_dst_port, // out: the packet's udp dst port
    size_t *payload_len  // out: the length of the packet payload.
) {
    const struct rte_ether_addr ether_broadcast = {
        .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    };
    size_t header_size = 0;
    uint8_t *ptr = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)ptr;
    
    ptr += sizeof(*eth_hdr);
    header_size += sizeof(*eth_hdr);
    struct rte_ipv4_hdr *const ip_hdr = (struct rte_ipv4_hdr *)(ptr);
    ptr += sizeof(*ip_hdr);
    header_size += sizeof(*ip_hdr);
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ptr);
    ptr += sizeof(*udp_hdr);
    header_size += sizeof(*udp_hdr);

    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    if (!rte_is_same_ether_addr(our_eth, &eth_hdr->d_addr) && !rte_is_same_ether_addr(&ether_broadcast, &eth_hdr->d_addr)) {
    //    printf("Bad MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	//		   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
    //        eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1],
	//		eth_hdr->d_addr.addr_bytes[2], eth_hdr->d_addr.addr_bytes[3],
	//		eth_hdr->d_addr.addr_bytes[4], eth_hdr->d_addr.addr_bytes[5]);
        return false;
    }
    if (RTE_ETHER_TYPE_IPV4 != eth_type) {
        //printf("Bad ether type");
        return false;
    }

    // In network byte order.
    if (ip_hdr->dst_addr != rte_cpu_to_be_32(our_ip)) {
        //printf("Bad dst ip addr; got: %u, expected: %u, our_ip in lE: %u\n", (unsigned)(ip_hdr->dst_addr), (unsigned)(rte_cpu_to_be_32(our_ip)), (unsigned)(our_ip));
        return false;
    }

    if (IPPROTO_UDP != ip_hdr->next_proto_id) {
        //printf("Bad next proto_id\n");
        return false;
    }

    *eth_src_addr = eth_hdr->s_addr;
    *ip_src_addr = rte_be_to_cpu_32(ip_hdr->src_addr);
    *udp_src_port = rte_be_to_cpu_16(udp_hdr->src_port);
    *udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    *payload_len = (size_t) (mbuf->pkt_len - header_size);
    // printf("[parse_packet_] Received packet with %u pkt_len, %u data_Len, %u header_size, set payload_len to %u\n", (unsigned)mbuf->pkt_len, (unsigned)mbuf->data_len, (unsigned)header_size, (unsigned)*payload_len);
    return true;
}

static uint8_t sym_rss_key[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

int eth_dev_configure_(uint16_t port_id, uint16_t rx_rings, uint16_t tx_rings) {
	struct rte_fdir_conf fdir_conf = {
		.mode = RTE_FDIR_MODE_PERFECT,
		.pballoc = RTE_FDIR_PBALLOC_64K,
		.status = RTE_FDIR_REPORT_STATUS,
		.mask = {
			.vlan_tci_mask = 0xFFEF,
			.ipv4_mask     = {
				.src_ip = 0xFFFFFFFF,
				.dst_ip = 0xFFFFFFFF,
			},
			.ipv6_mask     = {
				.src_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
				.dst_ip = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},
			},
			.src_port_mask = 0xFFFF,
			.dst_port_mask = 0xFFFF,
			.mac_addr_byte_mask = 0xFF,
			.tunnel_type_mask = 1,
			.tunnel_id_mask = 0xFFFFFFFF,
		},
		.drop_queue = 127,
	};

    struct rte_eth_dev_info dev_info = {};
    rte_eth_dev_info_get(port_id, &dev_info);
    rte_eth_dev_set_mtu(port_id, RX_PACKET_LEN);
    struct rte_eth_conf port_conf = {};

    port_conf.fdir_conf = fdir_conf;

    port_conf.rxmode.max_rx_pkt_len = RX_PACKET_LEN;

    port_conf.rxmode.offloads = DEV_RX_OFFLOAD_JUMBO_FRAME | DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_RSS_HASH;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;

    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_NONFRAG_IPV4_UDP;

    port_conf.txmode.offloads = DEV_TX_OFFLOAD_MULTI_SEGS | DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

    printf("port_id: %u, rx_rings; %u, tx_rings: %u\n", port_id, rx_rings, tx_rings);
    int ret = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        printf("Unable to configure eth device: %u: %s\n", -ret, rte_strerror(-ret));
        return ret;
    }

    ret = rte_eth_stats_reset(port_id);
    if (ret != 0) {
        printf("Unable to reset ethdev stats: %u: %s\n", -ret, rte_strerror(-ret));
    }

    return 0;
}

/**
 * compute_flow_affinity - compute rss hash for incoming packets
 * @local_port: the local port number
 * @remote_port: the remote port
 * @local_ip: local ip (in host-order)
 * @remote_ip: remote ip (in host-order)
 * @num_queues: total number of queues
 *
 * Returns the 32 bit hash mod maxks
 */
uint32_t compute_flow_affinity_(
    uint32_t local_ip,
    uint32_t remote_ip,
    uint16_t local_port,
    uint16_t remote_port,
    uint32_t num_queues
) {
	const uint8_t *rss_key = (uint8_t *)sym_rss_key;

	uint32_t input_tuple[] = {
        remote_ip, local_ip, local_port | remote_port << 16
	};

    uint32_t ret = rte_softrss((uint32_t *)&input_tuple, ARRAY_SIZE(input_tuple),
         (const uint8_t *)rss_key);
	return ret % num_queues;
}

/* Masks to match any source but a specific destination port */
static const struct rte_flow_item_udp udp_dst_port_mask = {
	.hdr.dst_port = RTE_BE16(0xffff),
};

static const struct rte_flow_item_udp udp_src_port_mask = {
	.hdr.src_port = RTE_BE16(0xffff),
};

static const struct rte_flow_item_udp udp_src_dst_port_mask = {
	.hdr.src_port = RTE_BE16(0xffff),
	.hdr.dst_port = RTE_BE16(0xffff),
};

static const struct rte_flow_item_ipv4 ipv4_any_addr = {
	.hdr = {
		.src_addr = 0,
		.dst_addr = 0,
	}
};

static const struct rte_flow_item_eth eth_proto_mask = {
#ifdef __cx3_mlx__
    .dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
    .src.addr_bytes = "\x00\x00\x00\x00\x00\x00",
    .type = RTE_BE16(0x0),
#else
    .dst.addr_bytes = "\x00\x00\x00\x00\x00\x00",
    .src.addr_bytes = "\x00\x00\x00\x00\x00\x00",
    .type = RTE_BE16(0xffff),
#endif
};

static int config_udp_match_rule_helper(
    uint16_t dpdk_port_id,
    struct rte_flow_item_eth *eth_proto_ipv4,
    struct rte_flow_attr *attr_out,
    uint32_t priority
) {
    if (attr_out == NULL) {
        return -EINVAL;
    }

	struct rte_flow_attr attr = {
		.group = 0,
		.priority = priority,
		.ingress = 1,
	};

    *attr_out = attr;
#ifdef __cx3_mlx__
    // We don't actually care about matching on the local eth address. But:
    // (1) if we match on nothing, like so:
    //         struct rte_flow_item_eth eth_proto_mask = {};
    //     then we get complaints from mlx4 about not supporting additional matching (which we want for
    //     the UDP dst port matching below) because the eth-level match is "indiscriminate".
    // (2) if we match on IPv4 EtherType (we do this on I40E, see below), like so:
    //         struct rte_flow_item_eth eth_proto_ipv4 = {};
    //         eth_proto_ipv4.type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    //         struct rte_flow_item_eth eth_proto_mask = {};
    //         eth_proto_mask.type = 0xffff;
    //     then we get complaints about "unsupported field found in "mask".
    //
    // Fortunately, it seems that the dst eth addr is a supported field, and since we apparently need
    // to have some field, we use that.
    struct rte_ether_addr local_eth_addr;
    int ret = rte_eth_macaddr_get(dpdk_port_id, &local_eth_addr);
    if (ret != 0) {
        return ret;
    }

    memcpy(&(eth_proto_ipv4->dst), &local_eth_addr, sizeof(struct rte_ether_addr));
#else
    // on I40E and mlx5 matching on just EtherType seems to be fine.
    eth_proto_ipv4->type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
#endif

    return 0;
}

/* Helper function to construct UDP dst port matching rule.
 * @dst_port: the local destination UDP port to match on.
 * @attr_out: where to put the initialized `rte_flow_attr`.
 * @pattern_out: where to put the initialized `rte_flow_item[]` containing the pattern to match. 
 *               this is a length-4 `rte_flow_item` array.
 *
 * Returns 0 on success and nonzero if arguments are malformed (-EINVAL) or `rte_eth_macaddr_get` fails.
 */
static int config_udp_dst_port_match_rule(
    uint16_t dst_port,
    uint16_t dpdk_port_id,
    struct rte_flow_item_eth *eth_proto_ipv4,
    struct rte_flow_item_udp *udp_flow,
    struct rte_flow_attr *attr_out,
    struct rte_flow_item (*pattern_out)[4]
) {
    if (pattern_out == NULL) {
        return -EINVAL;
    }

    int ok = config_udp_match_rule_helper(dpdk_port_id, eth_proto_ipv4, attr_out, 2);
    if (ok < 0) {
        return ok;
    }

	(udp_flow->hdr).dst_port = RTE_BE16(dst_port);

	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
            .mask = &eth_proto_mask,
            .spec = eth_proto_ipv4,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.mask = &ipv4_any_addr,
			.spec = &ipv4_any_addr,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.mask = &udp_dst_port_mask,
			.spec = udp_flow,
			.last = NULL, /* not a range */
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

    memcpy(pattern_out, &patterns, 4 * sizeof(struct rte_flow_item));
    return 0;
}

/* Helper function to construct UDP src port matching rule.
 * @src_port: the remote source UDP port to match on.
 * @attr_out: where to put the initialized `rte_flow_attr`.
 * @pattern_out: where to put the initialized `rte_flow_item[]` containing the pattern to match. 
 *               this is a length-4 `rte_flow_item` array.
 *
 * Returns 0 on success and nonzero if arguments are malformed (-EINVAL) or `rte_eth_macaddr_get` fails.
 */
static int config_udp_src_port_match_rule(
    uint16_t src_port,
    uint16_t dpdk_port_id,
    struct rte_flow_item_eth *eth_proto_ipv4,
    struct rte_flow_item_udp *udp_flow,
    struct rte_flow_attr *attr_out,
    struct rte_flow_item (*pattern_out)[4]
) {
    if (pattern_out == NULL) {
        return -EINVAL;
    }

    int ok = config_udp_match_rule_helper(dpdk_port_id, eth_proto_ipv4, attr_out, 1);
    if (ok < 0) {
        return ok;
    }

	(udp_flow->hdr).src_port = RTE_BE16(src_port);

	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
            .mask = &eth_proto_mask,
            .spec = eth_proto_ipv4,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.mask = &ipv4_any_addr,
			.spec = &ipv4_any_addr,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.mask = &udp_src_port_mask,
			.spec = udp_flow,
			.last = NULL, /* not a range */
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

    memcpy(pattern_out, &patterns, 4 * sizeof(struct rte_flow_item));
    return 0;
}

/* Helper function to construct UDP (src,dst) port matching rule.
 * @src_port: the remote source UDP port to match on.
 * @dst_port: the local dest UDP port to match on.
 * @attr_out: where to put the initialized `rte_flow_attr`.
 * @pattern_out: where to put the initialized `rte_flow_item[]` containing the pattern to match. 
 *               this is a length-4 `rte_flow_item` array.
 *
 * Returns 0 on success and nonzero if arguments are malformed (-EINVAL) or `rte_eth_macaddr_get` fails.
 */
static int config_udp_port_pair_match_rule(
    uint16_t src_port,
    uint16_t dst_port,
    uint16_t dpdk_port_id,
    struct rte_flow_item_eth *eth_proto_ipv4,
    struct rte_flow_item_udp *udp_flow,
    struct rte_flow_attr *attr_out,
    struct rte_flow_item (*pattern_out)[4]
) {
    if (pattern_out == NULL) {
        return -EINVAL;
    }

    int ok = config_udp_match_rule_helper(dpdk_port_id, eth_proto_ipv4, attr_out, 0);
    if (ok < 0) {
        return ok;
    }

	(udp_flow->hdr).src_port = RTE_BE16(src_port);
	(udp_flow->hdr).dst_port = RTE_BE16(dst_port);

	struct rte_flow_item patterns[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
            .mask = &eth_proto_mask,
            .spec = eth_proto_ipv4,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.mask = &ipv4_any_addr,
			.spec = &ipv4_any_addr,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.mask = &udp_src_dst_port_mask,
			.spec = udp_flow,
			.last = NULL, /* not a range */
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

    memcpy(pattern_out, &patterns, 4 * sizeof(struct rte_flow_item));
    return 0;
}

static int validate_and_install(
    uint16_t dpdk_port_id,
    struct rte_flow_attr *attr,
    struct rte_flow_item *patterns,
    struct rte_flow_action *actions,
    struct rte_flow **flow_handle_out
) {
    int ret;
	struct rte_flow_error err;
	ret = rte_flow_validate(dpdk_port_id, attr, patterns, actions, &err);
	if (ret != 0) {
        printf("flow validate failed: %s: error type %u: %s\n",
                rte_strerror(-ret), err.type, err.message);
		return ret;
	}

    if (flow_handle_out == NULL) {
        printf("invalid out-pointer provided to setup_flow_steering\n");
        return -EINVAL;
    }

    *flow_handle_out = NULL;
    *flow_handle_out = rte_flow_create(dpdk_port_id, attr, patterns, actions, &err);
	if (*flow_handle_out == NULL) {
        printf("flow create failed: %s: error type %u: %s\n",
                rte_strerror(-rte_errno), err.type, err.message);
        return -rte_errno;
    }

    return 0;
}

/** Use DPDK `rte_flow` API to configure steering for the flow to the given queue.
 * @dpdk_port_id: the DPDK port to act on.
 * @dst_port: the local destination UDP port to match on.
 * @dpdk_queue_id: the queue id to steer the flow's packets to.
 * @flow_handle_out: a returned handle to the flow object which can be used to delete the steering rule.
 *
 * Returns 0 if no error.
 */
int setup_flow_steering_solo_local_port_(
    uint16_t dpdk_port_id,
    uint16_t dst_port,
    uint16_t dpdk_queue_id,
	struct rte_flow **flow_handle_out
) {
	int ret;
    struct rte_flow_attr attr = {};
    struct rte_flow_item patterns[4] = {};
    struct rte_flow_item_eth eth_pattern = {};
    struct rte_flow_item_udp udp_pattern = {};

    ret = config_udp_dst_port_match_rule(dst_port, dpdk_port_id, &eth_pattern, &udp_pattern, &attr, &patterns);
    if (ret != 0) {
        return ret;
    }

	struct rte_flow_action_queue queue_action = {
		.index = dpdk_queue_id,
	};

    struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

    return validate_and_install(dpdk_port_id, &attr, patterns, actions, flow_handle_out);
}

/** Use DPDK `rte_flow` API to configure steering for the flow to the given queue.
 * @dpdk_port_id: the DPDK port to act on.
 * @dst_port: the local destination UDP port to match on.
 * @dpdk_queue_id: the queue id to steer the flow's packets to.
 * @flow_handle_out: a returned handle to the flow object which can be used to delete the steering rule.
 *
 * Returns 0 if no error.
 */
int setup_flow_steering_solo_remote_port_(
    uint16_t dpdk_port_id,
    uint16_t src_port,
    uint16_t dpdk_queue_id,
	struct rte_flow **flow_handle_out
) {
	int ret;
    struct rte_flow_attr attr = {};
    struct rte_flow_item patterns[4] = {};
    struct rte_flow_item_eth eth_pattern = {};
    struct rte_flow_item_udp udp_pattern = {};

    ret = config_udp_src_port_match_rule(src_port, dpdk_port_id, &eth_pattern, &udp_pattern, &attr, &patterns);
    if (ret != 0) {
        return ret;
    }

	struct rte_flow_action_queue queue_action = {
		.index = dpdk_queue_id,
	};

    struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

    return validate_and_install(dpdk_port_id, &attr, patterns, actions, flow_handle_out);
}

/** Use DPDK `rte_flow` API to configure steering for the flow to the given queue.
 * @dpdk_port_id: the DPDK port to act on.
 * @dst_port: the local destination UDP port to match on.
 * @dpdk_queue_id: the queue id to steer the flow's packets to.
 * @flow_handle_out: a returned handle to the flow object which can be used to delete the steering rule.
 *
 * Returns 0 if no error.
 */
int setup_flow_steering_solo_port_pair_(
    uint16_t dpdk_port_id,
    uint16_t src_port,
    uint16_t dst_port,
    uint16_t dpdk_queue_id,
	struct rte_flow **flow_handle_out
) {
	int ret;
    struct rte_flow_attr attr = {};
    struct rte_flow_item patterns[4] = {};
    struct rte_flow_item_eth eth_pattern = {};
    struct rte_flow_item_udp udp_pattern = {};

    ret = config_udp_port_pair_match_rule(src_port, dst_port, dpdk_port_id, &eth_pattern, &udp_pattern, &attr, &patterns);
    if (ret != 0) {
        return ret;
    }

	struct rte_flow_action_queue queue_action = {
		.index = dpdk_queue_id,
	};

    struct rte_flow_action actions[] = {
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

    return validate_and_install(dpdk_port_id, &attr, patterns, actions, flow_handle_out);
}

/** Use DPDK `rte_flow` API to configure RSS for the flow among the given queues.
 * @dpdk_port_id: the DPDK port to act on.
 * @dst_port: the local destination UDP port to match on.
 * @dpdk_queue_ids: the queue ids to RSS the flow's packets among.
 * @flow_handle_out: a returned handle to the flow object which can be used to delete the steering rule.
 *
 * Returns 0 if no error.
 */
int setup_flow_steering_rss_(
    uint16_t dpdk_port_id,
    uint16_t dst_port,
    uint16_t num_queues,
    const uint16_t *dpdk_queue_ids,
	struct rte_flow **flow_handle_out
) {
	struct rte_flow_attr attr = {
		.group = 0,
		.priority = 3,
		.ingress = 1,
	};
    struct rte_flow_action_rss rss_action = {};
    struct rte_flow_action actions[] = {
        {
            .type = RTE_FLOW_ACTION_TYPE_RSS,
            .conf = &rss_action,
        },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };

    rss_action.queue_num = num_queues;
    rss_action.queue = dpdk_queue_ids;
#ifdef __cx3_mlx__
    int ret;
    struct rte_flow_item patterns[4] = {};
    struct rte_flow_item_eth eth_pattern = {};
    struct rte_flow_item_udp udp_pattern = {};

    ret = config_udp_dst_port_match_rule(dst_port, dpdk_port_id, &eth_pattern, &udp_pattern, &attr, &patterns);
    if (ret != 0) {
        return ret;
    }
#else
    // on I40E and mlx5, don't attempt matching rules on RSS rules; it seems to not work.
    struct rte_flow_item patterns[] = { { .type = RTE_FLOW_ITEM_TYPE_END } };
#endif

    return validate_and_install(dpdk_port_id, &attr, patterns, actions, flow_handle_out);
}

/* Remove struct rte_flow entry.
 * @dpdk_port_id: the DPDK port to act on.
 * @flow_handle_out: a handle to the flow object which we will delete.
 *
 * Returns 0 on success, negative rte_errno value otherwise.
 */
int clear_flow_steering_(
   uint16_t dpdk_port_id,
   struct rte_flow *handle
) {
    if (handle == NULL) {
        return -EINVAL;
    }

    int ok = rte_flow_destroy(dpdk_port_id, handle, NULL);
    if (ok >= 0) {
        return ok;
    } else {
        return -rte_errno;
    }
}

/* Remove *all* flow steering rules on the dpdk port.
 * @dpdk_port_id: the DPDK port to act on.
 *
 * Returns 0 on success, negative rte_errno value otherwise.
 */
int flush_flow_steering_(uint16_t dpdk_port_id) {
    struct rte_flow_error err;
    int ret = rte_flow_flush(dpdk_port_id, &err);
	if (ret != 0) {
        printf("flow flush failed: %s: error type %u: %s\n",
                rte_strerror(-ret), err.type, err.message);
		return -rte_errno;
	}

    return 0;
}

int affinitize_(uint32_t core) {
    int ok;
    rte_cpuset_t cpuset;

    ok = rte_thread_register();
    if (ok < 0) {
        return ok;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    ok = rte_thread_set_affinity(&cpuset);
    if (ok >= 0) {
        RTE_PER_LCORE(_lcore_id) = core;
    }

    return ok;
}

uint32_t lcore_id_() {
    return rte_lcore_id();
}

int get_lcore_map_(uint32_t *lcores, uint32_t lcore_arr_size) {
    uint32_t idx = 0;
    uint32_t num_lcores = rte_lcore_count();
    if (num_lcores > lcore_arr_size) {
        return -2;
    }

    int this_lcore = rte_lcore_id();
    lcores[idx++] = this_lcore;
    int curr_lcore = rte_get_next_lcore(this_lcore, false, true);
    while (curr_lcore != this_lcore) {
        if (idx >= lcore_arr_size) {
            return -1;
        }

        lcores[idx++] = curr_lcore;
        curr_lcore = rte_get_next_lcore(curr_lcore, false, true);
    }

    return 0;
}
