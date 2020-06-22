/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "l3fwd.h"
#include "ndpi_detection.h"

#ifndef _cas
#define _cas(ptr, oldval, newval) \
    __sync_bool_compare_and_swap(ptr, oldval, newval)
#endif


/*
 * Common ring buffer between capture module and processing module.
 * capture module -> capture the packets.
 * processing module ->　analyze and forward/block the packets.
 */
struct rte_ring *msgq[16];

struct msg_struct_t {
    struct pcap_pkthdr *header;
    u_char *data;
} msg_struct_t;

/*
 * Define structures and functions.
 *
 * @common_params
 *   A structure that is shared between capture and forward.
 * @queue
 *   queue_t: A queue contains a head, tail and a dummy node.
 *   queue_ele_t: Node of queue which contains a nb_rx, pkts_burst and next.
 */
typedef struct queue_ele_t {
    struct queue_ele_t *next;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    int nb_rx;
    struct timeval start;
} queue_ele_t;

typedef struct queue_t {
    struct queue_ele_t *head;
    struct queue_ele_t *tail;
    struct queue_ele_t *tmp;
    pthread_mutex_t lock;
} queue_t;

struct common_params_t {
    unsigned lcore_id;
    uint16_t portid;
    uint8_t queueid;
    struct lcore_conf *qconf;
    struct timeval total_start, total_end;

    /* msg exchange between threads */
    queue_t *q;
#ifdef USE_PIPE
    int fd[2];
#endif
    struct rte_ring *msgq;
};

static inline queue_ele_t *queue_ele_new()
{
    queue_ele_t *node = malloc(sizeof(queue_ele_t));
    node->next = NULL;
    node->start.tv_sec = 0;
    node->start.tv_usec = 0;

    return node;
}

static queue_t *queue_new()
{
    queue_t *q = malloc(sizeof(queue_t));
    if (q) {
        pthread_mutex_init(&q->lock, NULL);
        q->tmp = queue_ele_new();
        q->head = q->tmp;
        q->tail = q->tmp;
        return q;
    }
    return NULL;
}

static void queue_free(queue_t *q)
{
    if (q) {
        if (q->head) {
            queue_ele_t *tmp = q->head;
            while (tmp) {
                q->head = q->head->next;
                free(tmp);
                tmp = q->head;
            }
        }
    }
    free(q);
}

static bool queue_add(queue_t *q, queue_ele_t *buf)
{
    bool ret;
    if (!q || !buf)
        ret = false;
    else {
#ifdef USE_NQUEUE
        queue_ele_t *new_ele = queue_ele_new();
        rte_memcpy(new_ele, buf, sizeof(queue_ele_t));
        new_ele->next = NULL;
        queue_ele_t *tail, *next;
        while (1) {
            tail = q->tail;
            next = tail->next;
            if (tail == q->tail) {
                if (_cas(&q->tail->next, NULL, new_ele)) {
                    ret = true;
                    break;
                } else
                    _cas(&q->tail, tail, next);
            }
        }
        _cas(&q->tail, tail, new_ele);  // Update q->tail
#else
        queue_ele_t *new_ele = malloc(sizeof(queue_ele_t));
        rte_memcpy(new_ele, buf, sizeof(queue_ele_t));

        pthread_mutex_lock(&q->lock);
        if (new_ele) {
            if (!q->head)
                q->head = new_ele;
            if (q->tail)
                q->tail->next = new_ele;
            q->tail = new_ele;
            ret = true;
        } else {
            free(new_ele);
            ret = false;
        }
        pthread_mutex_unlock(&q->lock);
#endif
    }
    return ret;
}

static int queue_pop(queue_t *q, queue_ele_t *buf)
{
    int ret;
    if (!q || !buf)
        return -1;
    else {
#ifdef USE_NQUEUE
        queue_ele_t *head, *tail, *next;
        while (1) {
            head = q->head;
            tail = q->tail;
            next = head->next;
            if (head == q->head) {
                if (head == tail) {
                    if (next == NULL) {
                        return 0;
                        /* continue; */
                    }
                    _cas(&q->tail, tail, next);
                } else {
                    rte_memcpy(buf, next, sizeof(queue_ele_t));
                    if (_cas(&q->head, head, next)) {
                        free(head);
                        return 1;
                    }
                }
            }
        }
#else
        pthread_mutex_lock(&q->lock);
        if (!q->head)
            ret = 0;
        else {
            rte_memcpy(buf, q->head, sizeof(queue_ele_t));
            queue_ele_t *tmp = q->head;
            q->head = q->head->next;
            ret = 1;
        }
        pthread_mutex_unlock(&q->lock);
        return ret;
#endif
    }
}

static inline int MyWrite(queue_t *q, queue_ele_t *buf)
{
    int ret;
    if (queue_add(q, buf))
        ret = 0;
    else
        ret = -1;
    return ret;
}

static inline int MyRead(queue_t *q, queue_ele_t *buf)
{
    return queue_pop(q, buf);
}

/* dpdk l3fwd  */
struct ipv4_l3fwd_lpm_route {
    uint32_t ip;
    uint8_t depth;
    uint8_t if_out;
};

struct ipv6_l3fwd_lpm_route {
    uint8_t ip[16];
    uint8_t depth;
    uint8_t if_out;
};

/* Setup route table */
static struct ipv4_l3fwd_lpm_route ipv4_l3fwd_lpm_route_array[] = {
    {IPv4(192, 168, 2, 1), 24, 0}, {IPv4(192, 168, 1, 1), 24, 1},
    {IPv4(3, 1, 1, 0), 24, 2},     {IPv4(4, 1, 1, 0), 24, 3},
    {IPv4(5, 1, 1, 0), 24, 4},     {IPv4(6, 1, 1, 0), 24, 5},
    {IPv4(7, 1, 1, 0), 24, 6},     {IPv4(8, 1, 1, 0), 24, 7},
};

static struct ipv6_l3fwd_lpm_route ipv6_l3fwd_lpm_route_array[] = {
    {{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 0},
    {{2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 1},
    {{3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 2},
    {{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 3},
    {{5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 4},
    {{6, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 5},
    {{7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 6},
    {{8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 48, 7},
};

#define IPV4_L3FWD_LPM_NUM_ROUTES \
    (sizeof(ipv4_l3fwd_lpm_route_array) / sizeof(ipv4_l3fwd_lpm_route_array[0]))
#define IPV6_L3FWD_LPM_NUM_ROUTES \
    (sizeof(ipv6_l3fwd_lpm_route_array) / sizeof(ipv6_l3fwd_lpm_route_array[0]))

#define IPV4_L3FWD_LPM_MAX_RULES 1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES 1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];
struct rte_lpm6 *ipv6_l3fwd_lpm_lookup_struct[NB_SOCKETS];

static inline uint16_t lpm_get_ipv4_dst_port(void *ipv4_hdr,
                                             uint16_t portid,
                                             void *lookup_struct)
{
    uint32_t next_hop;
    struct rte_lpm *ipv4_l3fwd_lookup_struct = (struct rte_lpm *) lookup_struct;

    return (uint16_t)(
        (rte_lpm_lookup(
             ipv4_l3fwd_lookup_struct,
             rte_be_to_cpu_32(((struct ipv4_hdr *) ipv4_hdr)->dst_addr),
             &next_hop) == 0)
            ? next_hop
            : portid);
}

static inline uint16_t lpm_get_ipv6_dst_port(void *ipv6_hdr,
                                             uint16_t portid,
                                             void *lookup_struct)
{
    uint32_t next_hop;
    struct rte_lpm6 *ipv6_l3fwd_lookup_struct =
        (struct rte_lpm6 *) lookup_struct;

    return (uint16_t)((rte_lpm6_lookup(ipv6_l3fwd_lookup_struct,
                                       ((struct ipv6_hdr *) ipv6_hdr)->dst_addr,
                                       &next_hop) == 0)
                          ? next_hop
                          : portid);
}

static __rte_always_inline uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf,
                 struct rte_mbuf *pkt,
                 uint16_t portid)
{
    struct ipv6_hdr *ipv6_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct ether_hdr *eth_hdr;

    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
        eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);

        return lpm_get_ipv4_dst_port(ipv4_hdr, portid,
                                     qconf->ipv4_lookup_struct);
    } else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {
        eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        ipv6_hdr = (struct ipv6_hdr *) (eth_hdr + 1);

        return lpm_get_ipv6_dst_port(ipv6_hdr, portid,
                                     qconf->ipv6_lookup_struct);
    }

    return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static __rte_always_inline uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf,
                           struct rte_mbuf *pkt,
                           uint32_t dst_ipv4,
                           uint16_t portid)
{
    uint32_t next_hop;
    struct ipv6_hdr *ipv6_hdr;
    struct ether_hdr *eth_hdr;

    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
        return (uint16_t)((rte_lpm_lookup(qconf->ipv4_lookup_struct, dst_ipv4,
                                          &next_hop) == 0)
                              ? next_hop
                              : portid);

    } else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {
        eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
        ipv6_hdr = (struct ipv6_hdr *) (eth_hdr + 1);

        return (uint16_t)((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
                                           ipv6_hdr->dst_addr, &next_hop) == 0)
                              ? next_hop
                              : portid);
    }

    return portid;
}

#if defined(RTE_ARCH_X86)
#include "l3fwd_lpm_sse.h"
#elif defined RTE_MACHINE_CPUFLAG_NEON
#include "l3fwd_lpm_neon.h"
#elif defined(RTE_ARCH_PPC_64)
#include "l3fwd_lpm_altivec.h"
#else
#include "l3fwd_lpm.h"
#endif

/* main loop. Capturing and processing */
int lpm_main_loop(__attribute__((unused)) void *dummy)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    int i, nb_rx;
    uint16_t portid;
    uint8_t queueid;
    struct lcore_conf *qconf;
    struct timeval total_start = {0, 0}, total_end = {0, 0},
                   capture_start = {0, 0}, analyze_start = {0, 0}, analyze_end;

    uint64_t prev_tsc, diff_tsc, cur_tsc;
    const uint64_t drain_tsc =
        (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];

    if (qconf->n_rx_queue == 0) {
        RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_queue; i++) {
        portid = qconf->rx_queue_list[i].port_id;
        queueid = qconf->rx_queue_list[i].queue_id;
        RTE_LOG(INFO, L3FWD, " -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
                lcore_id, portid, queueid);
    }

    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        /* TX burst queue drain */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = qconf->tx_port_id[i];
                if (qconf->tx_mbufs[portid].len == 0)
                    continue;
                send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
                qconf->tx_mbufs[portid].len = 0;
            }

            prev_tsc = cur_tsc;
        }


        /* Read packet from RX queues */
        for (i = 0; i < qconf->n_rx_queue; ++i) {
            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;
            nb_rx =
                rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);

            if (unlikely(nb_rx == 0))
                continue;

            /* Time record */
            gettimeofday(&capture_start, NULL);

            dpiresults[lcore_id].capturing_packets += nb_rx;

            gettimeofday(&analyze_start, NULL);
            dpiresults[lcore_id].capturing_time +=
                (analyze_start.tv_sec - capture_start.tv_sec) * 1000000 +
                (analyze_start.tv_usec - capture_start.tv_usec);

            /* Create pcap header and call analyze function */
            for (i = 0; i < nb_rx; i++) {
                char *data = rte_pktmbuf_mtod(pkts_burst[i], char *);
                int pkt_len = rte_pktmbuf_pkt_len(pkts_burst[i]);
                struct pcap_pkthdr h;

                dpiresults[lcore_id].total_bytes += pkt_len;

                h.len = h.caplen = pkt_len;
                gettimeofday(&h.ts, NULL);

                /* Recored the first time seeing a packets */
                if (total_start.tv_sec == 0)
                    gettimeofday(&total_start, NULL);

                /* Call the function to process the packets */
                ndpi_process_packet(lcore_id, &h, (const u_char *) data);
            }

            /* Forwarding */
#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON || \
    defined RTE_ARCH_PPC_64
            l3fwd_lpm_send_packets(nb_rx, pkts_burst, portid, qconf);
#else
            l3fwd_lpm_no_opt_send_packets(nb_rx, pkts_burst, portid, qconf);
#endif /* X86 */

            /* Time record */
            gettimeofday(&analyze_end, NULL);

            dpiresults[lcore_id].system_time +=
                (analyze_end.tv_sec - capture_start.tv_sec) * 1000000 +
                (analyze_end.tv_usec - capture_start.tv_usec);
        }
    }

    return 0;
}

/*
 * This function will be called by master lcore.
 * This function will act as a producer.
 * Call rx_burst to get packets and write to a ring buffer.
 */
int lpm_main_loop_capture(__attribute__((unused)) void *dummy)
{
    int i, nb_rx, nb_enqueue, ret;
    uint8_t queueid;
    uint16_t portid;
    unsigned lcore_id;
    struct lcore_conf *qconf;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST], *tmp[MAX_PKT_BURST];
    struct timeval start = {0, 0}, end = {0, 0};
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    const uint64_t drain_tsc =
        (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;


    RTE_LOG(INFO, L3FWD, "entering caputure module on lcore %u\n",
            rte_lcore_id());

    for (int j = 0; j < 16; j++) {
        char msgq_name[20];
        snprintf(msgq_name, sizeof(msgq_name), "msg_queue_%d", j);

        msgq[j] = rte_ring_create(msgq_name, 64, SOCKET_ID_ANY, RING_F_SP_ENQ);
        if (msgq[j] == NULL) {
            rte_exit(EXIT_FAILURE, "Create msg_ring for port_%d error!\n", j);
        }
    }


    rte_eal_mp_remote_launch(lpm_main_loop_processing, NULL, SKIP_MASTER);
    while (!force_quit) {
        RTE_LCORE_FOREACH(lcore_id)
        {
            qconf = &lcore_conf[lcore_id];

            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = qconf->tx_port_id[i];
                if (qconf->tx_mbufs[portid].len == 0)
                    continue;
                send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
                qconf->tx_mbufs[portid].len = 0;
            }

            for (i = 0; i < qconf->n_rx_queue; ++i) {
                portid = qconf->rx_queue_list[i].port_id;
                queueid = qconf->rx_queue_list[i].queue_id;
                nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
                                         MAX_PKT_BURST);

                if (unlikely(nb_rx == 0))
                    continue;

                nb_enqueue = rte_ring_enqueue_burst(
                    msgq[0], (void **) pkts_burst, nb_rx, NULL);

                dpiresults[lcore_id].capturing_packets += nb_rx;
            }
        }
#ifdef read_pcap
        gettimeofday(&start, NULL);
        int repeats = 100;
        for (int i = 0; i < repeats; i++) {
            int ret, nb_read = 0;
            char *pcapfile = "sqlmap.pcap";
            char errbuff[PCAP_ERRBUF_SIZE];
            struct pcap_pkthdr *header;
            struct msg_struct_t *pkts[32];
            const u_char *data;
            pcap_t *handler = pcap_open_offline(pcapfile, errbuff);

            while (pcap_next_ex(handler, &header, &data) >= 0) {
                struct msg_struct_t *msg = malloc(sizeof(struct msg_struct_t));
                msg->header = malloc(sizeof(struct pcap_pkthdr));
                msg->data = malloc(sizeof(u_char) * header->caplen);

                rte_memcpy(msg->header, header, sizeof(struct pcap_pkthdr));
                rte_memcpy(msg->data, data, sizeof(u_char) * header->caplen);
                pkts[nb_read] = msg;
                nb_read++;

                /*
                 * Try to enqueue.
                 * If enqueing failed -> read the next packets.
                 * If the pkts array is full -> keep enqueing.
                 */
                do {
                    ret = rte_ring_enqueue_bulk(msgq[0], (void **) pkts,
                                                nb_read, NULL);
                } while (ret == 0 && nb_read == MAX_PKT_BURST);
                if (ret > 0) {
                    /* printf("[Capturing] Enqueued %d packets.\n", ret); */
                    dpiresults[0].capturing_packets += nb_read;
                    nb_read = 0;
                }
            }
        }
        break;
#endif
    }
    gettimeofday(&end, NULL);

    dpiresults[rte_lcore_id()].capturing_time =
        (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);

    printf("[lcore_%u] Capturing module closed.\n", rte_lcore_id());
    /* Wait for processing modules */
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            break;
    }
    return 0;
}

/*
 * This function will be called by slave lcores.
 * This function will act as a consumer.
 * Read packets from a ring buffer then analyze and forward.
 */
int lpm_main_loop_processing(__attribute__((unused)) void *dummy)
{
    int i, ret, dequeue_num = 16, read_fail = 0;
    uint16_t portid;
    unsigned lcore_id, msgqid;
    struct lcore_conf *qconf;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct timeval start = {0, 0}, end = {0, 0}, p_start = {0, 0},
                   p_end = {0, 0};

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];
    portid = qconf->rx_queue_list[0].port_id;

    RTE_LOG(INFO, L3FWD, "entering processing module on lcore %u\n",
            rte_lcore_id());

    gettimeofday(&start, NULL);
    while (!force_quit) {
#ifdef read_pcap
        void *buff[32];
        ret = rte_ring_dequeue_burst(msgq[0], buff, MAX_PKT_BURST, NULL);
        if (ret == 0) {
            usleep(10);
            continue;
        } else {
            gettimeofday(&p_start, NULL);
            /* printf("[Processing_%u] Dequeued %d packets.\n", lcore_id, ret);
             */
            dpiresults[lcore_id].processing_packets += ret;
            for (i = 0; i < ret; i++) {
                struct msg_struct_t *msg = (struct msg_struct_t *) buff[i];


                ndpi_process_packet(lcore_id - 1, msg->header, msg->data);
                free(msg->header);
                free(msg->data);
                free(msg);
            }

            gettimeofday(&p_end, NULL);
            gettimeofday(&end, NULL);

            dpiresults[lcore_id].processing_time +=
                (p_end.tv_sec - p_start.tv_sec) * 1000000 +
                (p_end.tv_usec - p_start.tv_usec);
        }
#else
        ret = rte_ring_dequeue_burst(msgq[0], (void **) pkts_burst, dequeue_num,
                                     NULL);
        if (ret == 0)
            continue;
        else {
            /* printf("[Processing_%u] Dequeue %d packets from ring.\n",
               lcore_id, ret); */
            for (i = 0; i < ret; i++) {
                struct pcap_pkthdr h;
                char *data = rte_pktmbuf_mtod(pkts_burst[i], char *);
                int pkt_len = rte_pktmbuf_pkt_len(pkts_burst[i]);

                dpiresults[lcore_id].total_bytes += pkt_len;
                h.len = h.caplen = pkt_len;
                gettimeofday(&h.ts, NULL);

                ndpi_process_packet(lcore_id - 1, &h, (const u_char *) data);
            }
            l3fwd_lpm_send_packets(ret, pkts_burst, portid, qconf);
        }
#endif
    }
    dpiresults[lcore_id].system_time +=
        (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);

    printf("[lcore_%u] Processing module closed.\n", lcore_id);
    return 0;
}

void setup_lpm(const int socketid)
{
    struct rte_lpm6_config config;
    struct rte_lpm_config config_ipv4;
    unsigned i;
    int ret;
    char s[64];

    /* create the LPM table */
    config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
    config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
    config_ipv4.flags = 0;
    snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
    ipv4_l3fwd_lpm_lookup_struct[socketid] =
        rte_lpm_create(s, socketid, &config_ipv4);
    if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
        rte_exit(EXIT_FAILURE,
                 "Unable to create the l3fwd LPM table on socket %d\n",
                 socketid);

    /* populate the LPM table */
    for (i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {
        /* skip unused ports */
        if ((1 << ipv4_l3fwd_lpm_route_array[i].if_out & enabled_port_mask) ==
            0)
            continue;

        ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
                          ipv4_l3fwd_lpm_route_array[i].ip,
                          ipv4_l3fwd_lpm_route_array[i].depth,
                          ipv4_l3fwd_lpm_route_array[i].if_out);

        if (ret < 0) {
            rte_exit(EXIT_FAILURE,
                     "Unable to add entry %u to the l3fwd LPM table on "
                     "socket %d\n",
                     i, socketid);
        }

        printf("LPM: Adding route 0x%08x / %d (%d)\n",
               (unsigned) ipv4_l3fwd_lpm_route_array[i].ip,
               ipv4_l3fwd_lpm_route_array[i].depth,
               ipv4_l3fwd_lpm_route_array[i].if_out);
    }

    /* create the LPM6 table */
    snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

    config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
    config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
    config.flags = 0;
    ipv6_l3fwd_lpm_lookup_struct[socketid] =
        rte_lpm6_create(s, socketid, &config);
    if (ipv6_l3fwd_lpm_lookup_struct[socketid] == NULL)
        rte_exit(EXIT_FAILURE,
                 "Unable to create the l3fwd LPM table on socket %d\n",
                 socketid);

    /* populate the LPM table */
    for (i = 0; i < IPV6_L3FWD_LPM_NUM_ROUTES; i++) {
        /* skip unused ports */
        if ((1 << ipv6_l3fwd_lpm_route_array[i].if_out & enabled_port_mask) ==
            0)
            continue;

        ret = rte_lpm6_add(ipv6_l3fwd_lpm_lookup_struct[socketid],
                           ipv6_l3fwd_lpm_route_array[i].ip,
                           ipv6_l3fwd_lpm_route_array[i].depth,
                           ipv6_l3fwd_lpm_route_array[i].if_out);

        if (ret < 0) {
            rte_exit(EXIT_FAILURE,
                     "Unable to add entry %u to the l3fwd LPM table on "
                     "socket %d\n",
                     i, socketid);
        }

        printf("LPM: Adding route %s / %d (%d)\n", "IPV6",
               ipv6_l3fwd_lpm_route_array[i].depth,
               ipv6_l3fwd_lpm_route_array[i].if_out);
    }
}

int lpm_check_ptype(int portid)
{
    int i, ret;
    int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
    uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

    ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
    if (ret <= 0)
        return 0;

    uint32_t ptypes[ret];

    ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
    for (i = 0; i < ret; ++i) {
        if (ptypes[i] & RTE_PTYPE_L3_IPV4)
            ptype_l3_ipv4 = 1;
        if (ptypes[i] & RTE_PTYPE_L3_IPV6)
            ptype_l3_ipv6 = 1;
    }

    if (ptype_l3_ipv4 == 0)
        printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

    if (ptype_l3_ipv6 == 0)
        printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

    if (ptype_l3_ipv4 && ptype_l3_ipv6)
        return 1;

    return 0;
}

static inline void lpm_parse_ptype(struct rte_mbuf *m)
{
    struct ether_hdr *eth_hdr;
    uint32_t packet_type = RTE_PTYPE_UNKNOWN;
    uint16_t ether_type;

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_type = eth_hdr->ether_type;

    if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))
        packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
    else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))
        packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

    m->packet_type = packet_type;
}

uint16_t lpm_cb_parse_ptype(uint16_t port __rte_unused,
                            uint16_t queue __rte_unused,
                            struct rte_mbuf *pkts[],
                            uint16_t nb_pkts,
                            uint16_t max_pkts __rte_unused,
                            void *user_param __rte_unused)
{
    unsigned i;

    for (i = 0; i < nb_pkts; ++i)
        lpm_parse_ptype(pkts[i]);

    return nb_pkts;
}

/* Return ipv4/ipv6 lpm fwd lookup struct. */
void *lpm_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
    return ipv4_l3fwd_lpm_lookup_struct[socketid];
}

void *lpm_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
    return ipv6_l3fwd_lpm_lookup_struct[socketid];
}
