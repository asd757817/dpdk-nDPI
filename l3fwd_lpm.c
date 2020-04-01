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

/* Define structures and functions for shared variables */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct queue_ele_t {
    struct queue_ele_t *next;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    int nb_rx;
} queue_ele_t;

typedef struct my_queue_t {
    struct queue_ele_t *head;
    struct queue_ele_t *tail;
    int length;
    bool can_access;
} my_queue_t;

typedef struct shared_vars_t {
    int fd[2];
    unsigned lcore_id;
    uint16_t portid;
    uint8_t queueid;
    struct lcore_conf *qconf;
    struct timeval total_start, total_end;
    my_queue_t *q;
} shared_vars_t;

my_queue_t *queue_new()
{
    my_queue_t *q = malloc(sizeof(my_queue_t));
    if (q) {
        q->head = NULL;
        q->tail = NULL;
        q->length = 0;
        q->can_access = true;

        return q;
    }
    return NULL;
}

void queue_free(my_queue_t *q)
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

bool queue_add(my_queue_t *q, queue_ele_t *buf)
{
    if (!q || !buf)
        return false;
    else {
        queue_ele_t *new_ele = malloc(sizeof(queue_ele_t));
        memcpy(new_ele, buf, sizeof(queue_ele_t));

        if (new_ele) {
            if (!q->head)
                q->head = new_ele;
            if (q->tail)
                q->tail->next = new_ele;
            q->tail = new_ele;
            q->length += 1;
            return true;

        } else {
            free(new_ele);
            return false;
        }
    }
}

int queue_pop(my_queue_t *q, queue_ele_t *buf)
{
    if (!q || !buf)
        return -1;
    else {
        if (q->length == 0)
            return 0;
        else {
            memcpy(buf, q->head, sizeof(queue_ele_t));
            queue_ele_t *tmp = q->head;
            q->head = q->head->next;
            q->length -= 1;
            return q->length + 1;
        }
    }
}

static int MyWrite(my_queue_t *q, queue_ele_t *buf)
{
    int ret;
    pthread_mutex_lock(&mutex);
    if (queue_add(q, buf))
        ret = 0;
    else
        ret = -1;
    pthread_mutex_unlock(&mutex);
    return ret;
}

static int MyRead(my_queue_t *q, queue_ele_t *buf)
{
    pthread_mutex_lock(&mutex);
    int ret = queue_pop(q, buf);  // return queue length before pop
    pthread_mutex_unlock(&mutex);
    return ret;
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
    {IPv4(192, 168, 1, 0), 24, 0}, {IPv4(192, 168, 2, 0), 24, 1},
    {IPv4(192, 168, 3, 0), 24, 2}, {IPv4(4, 1, 1, 0), 24, 3},
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

/* main processing loop */
int lpm_main_loop(__attribute__((unused)) void *dummy)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    int i, nb_rx;
    uint16_t portid;
    uint8_t queueid;
    struct lcore_conf *qconf;
    struct timeval total_start, total_end, capture_start, analyze_start,
        analyze_end;

    total_start.tv_sec = 0, total_start.tv_usec = 0;
    capture_start.tv_sec = 0, capture_start.tv_usec = 0;
    analyze_start.tv_sec = 0, analyze_start.tv_usec = 0;

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
            dpiresults[lcore_id].total_rx_packets += nb_rx;
            gettimeofday(&analyze_start, NULL);
            dpiresults[lcore_id].capture_time +=
                (analyze_start.tv_sec - capture_start.tv_sec) * 1000000 +
                (analyze_start.tv_usec - capture_start.tv_usec);

            /* Create pcap header and call analyze function */
            for (i = 0; i < nb_rx; i++) {
                char *data = rte_pktmbuf_mtod(pkts_burst[i], char *);
                int pkt_len = rte_pktmbuf_pkt_len(pkts_burst[i]);
                struct pcap_pkthdr h;

                dpiresults[lcore_id].total_bytes += pkt_len;
                /* Get pcap format */
                h.len = h.caplen = pkt_len;
                gettimeofday(&h.ts, NULL);
                /* Recored the first time seeing a packets */
                if (total_start.tv_sec == 0)
                    gettimeofday(&total_start, NULL);

                /* Call the function to process the packets */
                ndpi_process_packet((u_char *) &lcore_id, &h,
                                    (const u_char *) data);
            }

            /* Forwarding */
            l3fwd_lpm_send_packets(nb_rx, pkts_burst, portid, qconf);
            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = qconf->tx_port_id[i];
                if (qconf->tx_mbufs[portid].len == 0)
                    continue;
                send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
                qconf->tx_mbufs[portid].len = 0;
            }

            /* Time record */
            gettimeofday(&analyze_end, NULL);
            gettimeofday(&total_end, NULL);
            dpiresults[lcore_id].analyze_time +=
                (analyze_end.tv_sec - analyze_start.tv_sec) * 1000000 +
                (analyze_end.tv_usec - analyze_start.tv_usec);
        }
    }
    /* Time record */
    dpiresults[lcore_id].total_time +=
        (total_end.tv_sec - total_start.tv_sec) * 1000000 +
        (total_end.tv_usec - total_start.tv_usec);

    return 0;
}

/*
 * Capture the packets then pass to analyze_module by pipe
 */
static void *capture_module(void *arguments)
{
    struct shared_vars_t *shared_vars = (struct shared_vars_t *) arguments;
    struct queue_ele_t buf, tmp;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];  // buffer for packets
    struct timeval capture_start, capture_end;
    my_queue_t *myqueue = shared_vars->q;

    int *fd = shared_vars->fd;
    int i, ret, nb_rx, count = 0;
    uint16_t portid;
    uint8_t queueid;

    capture_start.tv_sec = 0, capture_start.tv_usec = 0;
    capture_end.tv_sec = 0, capture_end.tv_usec = 0;

    while (!force_quit) {
        /* Polling for all rx_queues */
        for (i = 0; i < shared_vars->qconf->n_rx_queue; ++i) {
            portid = shared_vars->qconf->rx_queue_list[i].port_id;
            queueid = shared_vars->qconf->rx_queue_list[i].queue_id;
            nb_rx =
                rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);

            if (unlikely(nb_rx == 0))
                continue;

            if (shared_vars->total_start.tv_sec == 0) {
                gettimeofday(&shared_vars->total_start, NULL);
            }

            gettimeofday(&capture_start, NULL);

            buf.nb_rx = nb_rx;
            memcpy(buf.pkts_burst, pkts_burst, sizeof(pkts_burst));

            ret = write(fd[1], &buf, sizeof(buf));
            /* ret = MyWrite(myqueue, &buf); */
            if (ret < 0)
                continue;
            
            gettimeofday(&capture_end, NULL);
            dpiresults[shared_vars->lcore_id].capture_time +=
                (capture_end.tv_sec - capture_start.tv_sec) * 1000000 +
                (capture_end.tv_usec - capture_start.tv_usec);
        }
    
    }
    /* Close module */
    close(fd[1]);
    close(fd[0]);
    printf("[lcore_%u] Capture module closed.\n", shared_vars->lcore_id);
    pthread_exit(NULL);
}

/*
 * Analyze packets from capture_module
 */
static void *analyze_module(void *arguments)
{
    struct shared_vars_t *shared_vars = (struct shared_vars_t *) arguments;
    struct queue_ele_t buf;
    struct timeval analyze_start, analyze_end;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    int *fd = shared_vars->fd, ret = 0, i;
    my_queue_t *myqueue = shared_vars->q;

    analyze_start.tv_sec = 0, analyze_start.tv_usec = 0;
    analyze_end.tv_sec = 0, analyze_end.tv_usec = 0;

    while (!force_quit) {
        ret = read(fd[0], &buf, sizeof(buf));

        /* if (unlikely(myqueue->length == 0))
            continue;
        ret = MyRead(myqueue, &buf); */

        if (ret == 0)
            continue;
        else if (ret < 0)
            break;

        gettimeofday(&analyze_start, NULL);

        dpiresults[shared_vars->lcore_id].total_rx_packets += buf.nb_rx;


        for (i = 0; i < buf.nb_rx; i++) {
            char *data = rte_pktmbuf_mtod(buf.pkts_burst[i], char *);
            int pkt_len = rte_pktmbuf_pkt_len(buf.pkts_burst[i]);

            dpiresults[shared_vars->lcore_id].total_bytes += pkt_len;

            // Get pcap format
            struct pcap_pkthdr h;
            h.len = h.caplen = pkt_len;
            gettimeofday(&h.ts, NULL);

            // Call the function to process the packets
            ndpi_process_packet((u_char *) &shared_vars->lcore_id, &h,
                                (const u_char *) data);
        }

        /* Forwarding packets */
        l3fwd_lpm_send_packets(buf.nb_rx, buf.pkts_burst, shared_vars->portid,
                               shared_vars->qconf);
        for (i = 0; i < shared_vars->qconf->n_tx_port; ++i) {
            shared_vars->portid = shared_vars->qconf->tx_port_id[i];
            if (shared_vars->qconf->tx_mbufs[shared_vars->portid].len == 0)
                continue;
            send_burst(shared_vars->qconf,
                       shared_vars->qconf->tx_mbufs[shared_vars->portid].len,
                       shared_vars->portid);
            shared_vars->qconf->tx_mbufs[shared_vars->portid].len = 0;
        }

        gettimeofday(&analyze_end, NULL);
        gettimeofday(&shared_vars->total_end, NULL);

        /* Recored total analyze_time */
        dpiresults[shared_vars->lcore_id].analyze_time +=
            (analyze_end.tv_sec - analyze_start.tv_sec) * 1000000 +
            (analyze_end.tv_usec - analyze_start.tv_usec);
    }

    /* Close module */
    dpiresults[shared_vars->lcore_id].total_time =
        (shared_vars->total_end.tv_sec - shared_vars->total_start.tv_sec) *
            1000000 +
        (shared_vars->total_end.tv_usec - shared_vars->total_start.tv_usec);

    close(fd[0]);
    printf("[lcore_%u] Analyze module closed.\n", shared_vars->lcore_id);
    pthread_exit(NULL);
}

int lpm_main_loop_thread_pipe(__attribute__((unused)) void *dummy)
{
    int i;
    struct shared_vars_t shared_vars;

    /* Shared variables init */
    shared_vars.q = queue_new();
    shared_vars.lcore_id = rte_lcore_id();
    shared_vars.qconf = &lcore_conf[shared_vars.lcore_id];
    shared_vars.total_start.tv_sec = 0, shared_vars.total_start.tv_usec = 0;
    shared_vars.total_end.tv_sec = 0, shared_vars.total_end.tv_usec = 0;

    /* Show info */
    if (shared_vars.qconf->n_rx_queue == 0) {
        RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n",
                shared_vars.lcore_id);
        return 0;
    }

    RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n",
            shared_vars.lcore_id);

    for (i = 0; i < shared_vars.qconf->n_rx_queue; i++) {
        shared_vars.portid = shared_vars.qconf->rx_queue_list[i].port_id;
        shared_vars.queueid = shared_vars.qconf->rx_queue_list[i].queue_id;
        RTE_LOG(INFO, L3FWD, " -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
                shared_vars.lcore_id, shared_vars.portid, shared_vars.queueid);
    }

    /* pipe init */
    if (pipe(shared_vars.fd) < 0) {
        fprintf(stderr, "Pipe init error.\n");
        exit(1);
    }

    /* Declaration */
    cpu_set_t cpuset_capture, cpuset_analyze;
    pthread_t p_capture, p_analyze;
    int ret;

    /* Create threads */
    pthread_create(&p_capture, NULL, capture_module, (void *) &shared_vars);
    pthread_create(&p_analyze, NULL, analyze_module, (void *) &shared_vars);

    /* Set CPU affinity */
    bool set_affinity = true;
    if (set_affinity) {
        CPU_ZERO(&cpuset_capture);
        CPU_ZERO(&cpuset_analyze);

        CPU_SET(shared_vars.lcore_id, &cpuset_capture);
        CPU_SET(shared_vars.lcore_id + 2, &cpuset_analyze);

        ret = pthread_setaffinity_np(p_capture, sizeof(cpu_set_t),
                                     &cpuset_capture);
        if (ret != 0)
            fprintf(stderr, "[lcore.%u Capture]Set affinity error.\n",
                    shared_vars.lcore_id);

        ret = pthread_setaffinity_np(p_analyze, sizeof(cpu_set_t),
                                     &cpuset_analyze);
        if (ret != 0)
            fprintf(stderr, "[lcore.%u Analyze]Set affinity error.\n",
                    shared_vars.lcore_id);
    }
    /* pthread join */
    pthread_join(p_capture, NULL);
    pthread_join(p_analyze, NULL);

    queue_free(shared_vars.q);
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
