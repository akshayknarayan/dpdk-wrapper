#include <ctype.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mem.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rte_mempool.h>
#include <rte_flow.h>
#include <custom_mempool.h>
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

void eth_dev_configure_(uint16_t port_id, uint16_t rx_rings, uint16_t tx_rings) {
    uint16_t mtu;
    struct rte_eth_dev_info dev_info = {};
    rte_eth_dev_info_get(port_id, &dev_info);
    rte_eth_dev_set_mtu(port_id, RX_PACKET_LEN);
    rte_eth_dev_get_mtu(port_id, &mtu);
    fprintf(stderr, "Dev info MTU:%u\n", mtu);
    struct rte_eth_conf port_conf = {};
    port_conf.rxmode.max_rx_pkt_len = RX_PACKET_LEN;

    port_conf.rxmode.offloads = DEV_RX_OFFLOAD_JUMBO_FRAME | DEV_RX_OFFLOAD_IPV4_CKSUM;
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS | ETH_MQ_RX_RSS_FLAG;
    //port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
    port_conf.rx_adv_conf.rss_conf.rss_key = sym_rss_key;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_UDP | ETH_RSS_IP;
    port_conf.txmode.offloads = DEV_TX_OFFLOAD_MULTI_SEGS | DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

    printf("port_id: %u, rx_rings; %u, tx_rings: %u\n", port_id, rx_rings, tx_rings);
    rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
}

uint64_t rte_get_timer_cycles_() {
    return rte_get_timer_cycles();
}

uint64_t rte_get_timer_hz_() {
    return rte_get_timer_hz();
}
