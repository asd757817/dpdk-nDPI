/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-19 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef linux
#include <sched.h>
#endif
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <math.h>
#include <pcap.h>
#include <pthread.h>
#include <search.h>
#include <signal.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#ifdef WIN32
#include <io.h>
#include <process.h>
#include <winsock2.h> /* winsock.h is included automatically */
#define getopt getopt____
#else
#include <netinet/in.h>
#include <unistd.h>
#endif

#ifdef USE_DPDK
/* DPDK lib*/
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vect.h>
#endif

/* nDPI lib */
#include "ndpi_api.h"
#include "ndpi_config.h"
#include "ndpi_detection.h"
#include "pattern_matching.h"

/* local source */
#include "intrusion_detection.h"
#include "l3fwd.h"
#include "reader_util.h"
#include "uthash.h"

/* ============== l3fwd ============== */

/*
 * Macro define
 * Configurable number of RX/TX reing descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Select Longest-Prefix or Exact match. */
static int l3fwd_lpm_on;
static int l3fwd_em_on;

static int numa_on = 1; /**< NUMA is enabled by default. */
static int parse_ptype; /**< Parse packet type using rx callback, and */
                        /**< disabled by default */

/* Global variables. */

volatile bool force_quit;

/* ethernet addresses of ports */
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

xmm_t val_eth[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
uint32_t enabled_port_mask;

/* Used only in exact match mode. */
int ipv6; /**< ipv6 is false by default. */
uint32_t hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params {
    uint16_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2}, {0, 1, 2}, {0, 2, 2}, {1, 0, 2}, {1, 1, 2},
    {1, 2, 2}, {2, 0, 2}, {3, 0, 3}, {3, 1, 3},
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params =
    sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode = ETH_MQ_RX_RSS,
            .max_rx_pkt_len = ETHER_MAX_LEN,
            .split_hdr_size = 0,
            .offloads = DEV_RX_OFFLOAD_CHECKSUM,
        },
    .rx_adv_conf =
        {
            .rss_conf =
                {
                    .rss_key = NULL,
                    .rss_hf = ETH_RSS_IP,
                },
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

struct l3fwd_lkp_mode {
    void (*setup)(int);
    int (*check_ptype)(int);
    rte_rx_callback_fn cb_parse_ptype;
    int (*main_loop)(void *);
    void *(*get_ipv4_lookup_struct)(int);
    void *(*get_ipv6_lookup_struct)(int);
};

static struct l3fwd_lkp_mode l3fwd_lkp;

static struct l3fwd_lkp_mode l3fwd_em_lkp = {
    .setup = setup_hash,
    .check_ptype = em_check_ptype,
    .cb_parse_ptype = em_cb_parse_ptype,
    .main_loop = em_main_loop,
    .get_ipv4_lookup_struct = em_get_ipv4_l3fwd_lookup_struct,
    .get_ipv6_lookup_struct = em_get_ipv6_l3fwd_lookup_struct,
};

static struct l3fwd_lkp_mode l3fwd_lpm_lkp = {
    .setup = setup_lpm,
    .check_ptype = lpm_check_ptype,
    .cb_parse_ptype = lpm_cb_parse_ptype,
    /* .main_loop = lpm_main_loop, */
    .main_loop = lpm_main_loop_multi_threads,
    .get_ipv4_lookup_struct = lpm_get_ipv4_l3fwd_lookup_struct,
    .get_ipv6_lookup_struct = lpm_get_ipv6_l3fwd_lookup_struct,
};

/*
 * Setup lookup methods for forwarding.
 * Currently exact-match and longest-prefix-match
 * are supported ones.
 */
static void setup_l3fwd_lookup_tables(void)
{
    /* Setup HASH lookup functions. */
    if (l3fwd_em_on)
        l3fwd_lkp = l3fwd_em_lkp;
    /* Setup LPM lookup functions. */
    else
        l3fwd_lkp = l3fwd_lpm_lkp;
}

static int check_lcore_params(void)
{
    uint8_t queue, lcore;
    uint16_t i;
    int socketid;

    for (i = 0; i < nb_lcore_params; ++i) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            printf("invalid queue number: %hhu\n", queue);
            return -1;
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("error: lcore %hhu is not enabled in lcore mask\n", lcore);
            return -1;
        }
        if ((socketid = rte_lcore_to_socket_id(lcore) != 0) && (numa_on == 0)) {
            printf("warning: lcore %hhu is on socket %d with numa off \n",
                   lcore, socketid);
        }
    }
    return 0;
}

static int check_port_config(void)
{
    uint16_t portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        portid = lcore_params[i].port_id;
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("port %u is not enabled in port mask\n", portid);
            return -1;
        }
        if (!rte_eth_dev_is_valid_port(portid)) {
            printf("port %u is not present on the board\n", portid);
            return -1;
        }
    }
    return 0;
}

static uint8_t get_port_n_rx_queues(const uint16_t port)
{
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port) {
            if (lcore_params[i].queue_id == queue + 1)
                queue = lcore_params[i].queue_id;
            else
                rte_exit(EXIT_FAILURE,
                         "queue ids of the port %d must be"
                         " in sequence and must start with 0\n",
                         lcore_params[i].port_id);
        }
    }
    return (uint8_t)(++queue);
}

static int init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    uint8_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore: %u\n",
                   (unsigned) nb_rx_queue + 1, (unsigned) lcore);
            return -1;
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
                lcore_params[i].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
                lcore_params[i].queue_id;
            lcore_conf[lcore].n_rx_queue++;
        }
    }
    return 0;
}

/* display usage */
static void print_usage(const char *prgname)
{
    fprintf(
        stderr,
        "%s [EAL options] --"
        " -p PORTMASK"
        " [-P]"
        " [-E]"
        " [-L]"
        " --config (port,queue,lcore)[,(port,queue,lcore)]"
        " [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
        " [--enable-jumbo [--max-pkt-len PKTLEN]]"
        " [--no-numa]"
        " [--hash-entry-num]"
        " [--ipv6]"
        " [--parse-ptype]\n\n"

        "  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
        "  -P : Enable promiscuous mode\n"
        "  -E : Enable exact match\n"
        "  -L : Enable longest prefix match (default)\n"
        "  --config (port,queue,lcore): Rx queue configuration\n"
        "  --eth-dest=X,MM:MM:MM:MM:MM:MM: Ethernet destination for port X\n"
        "  --enable-jumbo: Enable jumbo frames\n"
        "  --max-pkt-len: Under the premise of enabling jumbo,\n"
        "                 maximum packet length in decimal (64-9600)\n"
        "  --no-numa: Disable numa awareness\n"
        "  --hash-entry-num: Specify the hash entry number in hexadecimal to "
        "be setup\n"
        "  --ipv6: Set if running ipv6 packets\n"
        "  --parse-ptype: Set to use software to analyze packet type\n\n",
        prgname);
}

static int parse_max_pkt_len(const char *pktlen)
{
    char *end = NULL;
    unsigned long len;

    /* parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
}

static int parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static int parse_hash_entry_number(const char *hash_entry_num)
{
    char *end = NULL;
    unsigned long hash_en;
    /* parse hexadecimal string */
    hash_en = strtoul(hash_entry_num, &end, 16);
    if ((hash_entry_num[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (hash_en == 0)
        return -1;

    return hash_en;
}

static int parse_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames { FLD_PORT = 0, FLD_QUEUE, FLD_LCORE, _NUM_FLD };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int i;
    unsigned size;

    nb_lcore_params = 0;

    while ((p = strchr(p0, '(')) != NULL) {
        ++p;
        if ((p0 = strchr(p, ')')) == NULL)
            return -1;

        size = p0 - p;
        if (size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++) {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("exceeded max number of lcore params: %hu\n",
                   nb_lcore_params);
            return -1;
        }
        lcore_params_array[nb_lcore_params].port_id =
            (uint8_t) int_fld[FLD_PORT];
        lcore_params_array[nb_lcore_params].queue_id =
            (uint8_t) int_fld[FLD_QUEUE];
        lcore_params_array[nb_lcore_params].lcore_id =
            (uint8_t) int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    lcore_params = lcore_params_array;
    return 0;
}

static void parse_eth_dest(const char *optarg)
{
    uint16_t portid;
    char *port_end;
    uint8_t c, *dest, peer_addr[6];

    errno = 0;
    portid = strtoul(optarg, &port_end, 10);
    if (errno != 0 || port_end == optarg || *port_end++ != ',')
        rte_exit(EXIT_FAILURE, "Invalid eth-dest: %s", optarg);
    if (portid >= RTE_MAX_ETHPORTS)
        rte_exit(EXIT_FAILURE, "eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
                 portid, RTE_MAX_ETHPORTS);

    if (cmdline_parse_etheraddr(NULL, port_end, &peer_addr, sizeof(peer_addr)) <
        0)
        rte_exit(EXIT_FAILURE, "Invalid ethernet address: %s\n", port_end);
    dest = (uint8_t *) &dest_eth_addr[portid];
    for (c = 0; c < 6; c++)
        dest[c] = peer_addr[c];
    *(uint64_t *) (val_eth + portid) = dest_eth_addr[portid];
}

#define MAX_JUMBO_PKT_LEN 9600
#define MEMPOOL_CACHE_SIZE 256

static const char short_options[] =
    "p:" /* portmask */
    "P"  /* promiscuous */
    "L"  /* enable long prefix match */
    "E"  /* enable exact match */
    ;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"
enum {
    /* long options mapped to a short option */

    /* first long only option value must be >= 256, so that we won't
     * conflict with short options */
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_CONFIG_NUM,
    CMD_LINE_OPT_ETH_DEST_NUM,
    CMD_LINE_OPT_NO_NUMA_NUM,
    CMD_LINE_OPT_IPV6_NUM,
    CMD_LINE_OPT_ENABLE_JUMBO_NUM,
    CMD_LINE_OPT_HASH_ENTRY_NUM_NUM,
    CMD_LINE_OPT_PARSE_PTYPE_NUM,
};

static const struct option lgopts[] = {
    {CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
    {CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
    {CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
    {CMD_LINE_OPT_IPV6, 0, 0, CMD_LINE_OPT_IPV6_NUM},
    {CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, CMD_LINE_OPT_ENABLE_JUMBO_NUM},
    {CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, CMD_LINE_OPT_HASH_ENTRY_NUM_NUM},
    {CMD_LINE_OPT_PARSE_PTYPE, 0, 0, CMD_LINE_OPT_PARSE_PTYPE_NUM},
    {NULL, 0, 0, 0}};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF                                                                \
    RTE_MAX((nb_ports * nb_rx_queue * nb_rxd +                                 \
             nb_ports * nb_lcores * MAX_PKT_BURST +                            \
             nb_ports * n_tx_queue * nb_txd + nb_lcores * MEMPOOL_CACHE_SIZE), \
            (unsigned) 16384)

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];

    argvopt = argv;

    /* Error or normal output strings. */
    while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
                              &option_index)) != EOF) {
        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                fprintf(stderr, "Invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;

        case 'P':
            promiscuous_on = 1;
            break;

        case 'E':
            l3fwd_em_on = 1;
            break;

        case 'L':
            l3fwd_lpm_on = 1;
            break;

        /* long options */
        case CMD_LINE_OPT_CONFIG_NUM:
            ret = parse_config(optarg);
            if (ret) {
                fprintf(stderr, "Invalid config\n");
                print_usage(prgname);
                return -1;
            }
            break;

        case CMD_LINE_OPT_ETH_DEST_NUM:
            parse_eth_dest(optarg);
            break;

        case CMD_LINE_OPT_NO_NUMA_NUM:
            numa_on = 0;
            break;

        case CMD_LINE_OPT_IPV6_NUM:
            ipv6 = 1;
            break;

        case CMD_LINE_OPT_ENABLE_JUMBO_NUM: {
            const struct option lenopts = {"max-pkt-len", required_argument, 0,
                                           0};

            port_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
            port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;

            /*
             * if no max-pkt-len set, use the default
             * value ETHER_MAX_LEN.
             */
            if (getopt_long(argc, argvopt, "", &lenopts, &option_index) == 0) {
                ret = parse_max_pkt_len(optarg);
                if (ret < 64 || ret > MAX_JUMBO_PKT_LEN) {
                    fprintf(stderr, "invalid maximum packet length\n");
                    print_usage(prgname);
                    return -1;
                }
                port_conf.rxmode.max_rx_pkt_len = ret;
            }
            break;
        }

        case CMD_LINE_OPT_HASH_ENTRY_NUM_NUM:
            ret = parse_hash_entry_number(optarg);
            if ((ret > 0) && (ret <= L3FWD_HASH_ENTRIES)) {
                hash_entry_number = ret;
            } else {
                fprintf(stderr, "invalid hash entry number\n");
                print_usage(prgname);
                return -1;
            }
            break;

        case CMD_LINE_OPT_PARSE_PTYPE_NUM:
            printf("soft parse-ptype is enabled\n");
            parse_ptype = 1;
            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    /* If both LPM and EM are selected, return error. */
    if (l3fwd_lpm_on && l3fwd_em_on) {
        fprintf(stderr, "LPM and EM are mutually exclusive, select only one\n");
        return -1;
    }

    /*
     * Nothing is selected, pick longest-prefix match
     * as default match.
     */
    if (!l3fwd_lpm_on && !l3fwd_em_on) {
        fprintf(stderr, "LPM or EM none selected, default LPM on\n");
        l3fwd_lpm_on = 1;
    }

    /*
     * ipv6 and hash flags are valid only for
     * exact macth, reset them to default for
     * longest-prefix match.
     */
    if (l3fwd_lpm_on) {
        ipv6 = 0;
        hash_entry_number = HASH_ENTRY_NUMBER_DEFAULT;
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; /* reset getopt lib */
    return ret;
}

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

static int init_mem(unsigned nb_mbuf)
{
    struct lcore_conf *qconf;
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on)
            socketid = rte_lcore_to_socket_id(lcore_id);
        else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE, "Socket %d of lcore %u is out of range %d\n",
                     socketid, lcore_id, NB_SOCKETS);
        }

        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
            if (pktmbuf_pool[socketid] == NULL)
                rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n",
                         socketid);
            else
                printf("Allocated mbuf pool on socket %d\n", socketid);

            /* Setup either LPM or EM(f.e Hash).  */
            l3fwd_lkp.setup(socketid);
        }
        qconf = &lcore_conf[lcore_id];
        qconf->ipv4_lookup_struct = l3fwd_lkp.get_ipv4_lookup_struct(socketid);
        qconf->ipv6_lookup_struct = l3fwd_lkp.get_ipv6_lookup_struct(socketid);
    }
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid)
        {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port%d Link Up. Speed %u Mbps -%s\n", portid,
                           link.link_speed,
                           (link.link_duplex == ETH_LINK_FULL_DUPLEX)
                               ? ("full-duplex")
                               : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

static int prepare_ptype_parser(uint16_t portid, uint16_t queueid)
{
    if (parse_ptype) {
        printf("Port %d: softly parse packet type info\n", portid);
        if (rte_eth_add_rx_callback(portid, queueid, l3fwd_lkp.cb_parse_ptype,
                                    NULL))
            return 1;

        printf("Failed to add rx callback: port=%d\n", portid);
        return 0;
    }

    if (l3fwd_lkp.check_ptype(portid))
        return 1;

    printf("port %d cannot parse packet type, please add --%s\n", portid,
           CMD_LINE_OPT_PARSE_PTYPE);
    return 0;
}

static int dpdk_l3fwd_init(int argc, char **argv)
{
    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    int ret, ret_nb;
    unsigned nb_ports;
    uint16_t queueid, portid;
    unsigned lcore_id;
    uint32_t n_tx_queue, nb_lcores;
    uint8_t nb_rx_queue, queue, socketid;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;
    ret_nb += ret;

    force_quit = false;
    /* pre-init dst MACs for all ports to 02:00:00:00:00:xx */

    /*
    dest_eth_addr[0] = 0xad46ef290c00;
    dest_eth_addr[1] = 0x6109ec290c00;
    for (uint16_t i = 0; i < 2; i++) {
        *(uint64_t *) (val_eth + i) = dest_eth_addr[i];
    }
    */

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    ret_nb += ret;
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count_avail();

    if (check_port_config() < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    nb_lcores = rte_lcore_count();

    /* Setup function pointers for lookup method. */
    setup_l3fwd_lookup_tables();

    /* initialize all ports */
    RTE_ETH_FOREACH_DEV(portid)
    {
        struct rte_eth_conf local_port_conf = port_conf;

        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            continue;
        }

        /* init port */
        printf("Initializing port %d ... ", portid);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        n_tx_queue = 1;  // nb_lcores;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue,
               (unsigned) n_tx_queue);

        rte_eth_dev_info_get(portid, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
            dev_info.flow_type_rss_offloads;
        if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
            port_conf.rx_adv_conf.rss_conf.rss_hf) {
            printf(
                "Port %u modified RSS hash function based on hardware support,"
                "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
                portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
                local_port_conf.rx_adv_conf.rss_conf.rss_hf);
        }

        ret = rte_eth_dev_configure(portid, nb_rx_queue, (uint16_t) n_tx_queue,
                                    &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
                     ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot adjust number of descriptors: err=%d, "
                     "port=%d\n",
                     ret, portid);

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        print_ethaddr(" Address:", &ports_eth_addr[portid]);
        printf(", ");
        print_ethaddr("Destination:",
                      (const struct ether_addr *) &dest_eth_addr[portid]);
        printf(", ");

        /*
         * prepare src MACs for each port.
         */
        ether_addr_copy(&ports_eth_addr[portid],
                        (struct ether_addr *) (val_eth + portid) + 1);

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            if (numa_on)
                socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
            fflush(stdout);

            txconf = &dev_info.default_txconf;
            txconf->offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid,
                                         txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_tx_queue_setup: err=%d, "
                         "port=%d\n",
                         ret, portid);

            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            // queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
        fflush(stdout);
        /* init RX queues */
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            struct rte_eth_dev *dev;
            struct rte_eth_conf *conf;
            struct rte_eth_rxconf rxq_conf;

            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
            dev = &rte_eth_devices[portid];
            conf = &dev->data->dev_conf;

            if (numa_on)
                socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("rxq=%d,%d,%d ", portid, queueid, socketid);
            fflush(stdout);

            rte_eth_dev_info_get(portid, &dev_info);
            rxq_conf = dev_info.default_rxconf;
            rxq_conf.offloads = conf->rxmode.offloads;
            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid,
                                         &rxq_conf, pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret,
                         portid);
        }
    }

    printf("\n");

    /* start ports */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if ((enabled_port_mask & (1 << portid)) == 0) {
            continue;
        }
        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret,
                     portid);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    printf("\n");

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
            if (prepare_ptype_parser(portid, queueid) == 0)
                rte_exit(EXIT_FAILURE, "ptype check fails\n");
        }
    }

    check_all_ports_link_status(enabled_port_mask);

    return ret_nb;
}

/* ============== nDPI ============== */

#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
#endif



// ID tracking
typedef struct ndpi_id {
    u_int8_t ip[4];                  // Ip address
    struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// used memory counters
#ifdef USE_DPDK
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

void test_lib(); /* Forward */


#ifdef DEBUG_TRACE
FILE *trace = NULL;
#endif

static void reduceBDbits(uint32_t *bd, unsigned int len)
{
    int mask = 0;
    int shift = 0;
    unsigned int i = 0;

    for (i = 0; i < len; i++)
        mask = mask | bd[i];

    mask = mask >> 8;
    for (i = 0; i < 24 && mask; i++) {
        mask = mask >> 1;
        if (mask == 0) {
            shift = i + 1;
            break;
        }
    }

    for (i = 0; i < len; i++)
        bd[i] = bd[i] >> shift;
}


/**
 * @brief Print help instructions
 */
static void help(u_int long_help)
{
    printf("Welcome to nDPI %s\n\n", ndpi_revision());

    printf(
        "ndpiReader "
#ifndef USE_DPDK
        "-i <file|device> "
#endif
        "[-f <filter>][-s <duration>][-m <duration>]\n"
        "          [-p <protos>][-l <loops> [-q][-d][-J][-h][-e <len>][-t][-v "
        "<level>]\n"
        "          [-n <threads>][-w <file>][-c <file>][-C <file>][-j "
        "<file>][-x <file>]\n"
        "          [-T <num>][-U <num>]\n\n"
        "Usage:\n"
        "  -i <file.pcap|device>     | Specify a pcap file/playlist to read "
        "packets from or a\n"
        "                            | device for live capture "
        "(comma-separated list)\n"
        "  -f <BPF filter>           | Specify a BPF filter for filtering "
        "selected traffic\n"
        "  -s <duration>             | Maximum capture duration in seconds "
        "(live traffic capture only)\n"
        "  -m <duration>             | Split analysis duration in <duration> "
        "max seconds\n"
        "  -p <file>.protos          | Specify a protocol file (eg. "
        "protos.txt)\n"
        "  -l <num loops>            | Number of detection loops (test only)\n"
        "  -n <num threads>          | Number of threads. Default: number of "
        "interfaces in -i.\n"
        "                            | Ignored with pcap files.\n"
#ifdef linux
        "  -g <id:id...>             | Thread affinity mask (one core id per "
        "thread)\n"
#endif
        "  -d                        | Disable protocol guess and use only "
        "DPI\n"
        "  -e <len>                  | Min human readeable string match len. "
        "Default %u\n"
        "  -q                        | Quiet mode\n"
        "  -J                        | Display flow SPLT (sequence of packet "
        "length and time)\n"
        "                            | and BD (byte distribution). See "
        "https://github.com/cisco/joy\n"
        "  -t                        | Dissect GTP/TZSP tunnels\n"
        "  -P <a>:<b>:<c>:<d>:<e>    | Enable payload analysis:\n"
        "                            | <a> = min pattern len to search\n"
        "                            | <b> = max pattern len to search\n"
        "                            | <c> = max num packets per flow\n"
        "                            | <d> = max packet payload dissection\n"
        "                            | <d> = max num reported payloads\n"
        "                            | Default: %u:%u:%u:%u:%u\n"
        "  -r                        | Print nDPI version and git revision\n"
        "  -c <path>                 | Load custom categories from the "
        "specified file\n"
        "  -C <path>                 | Write output in CSV format on the "
        "specified file\n"
        "  -w <path>                 | Write test output on the specified "
        "file. This is useful for\n"
        "                            | testing purposes in order to compare "
        "results across runs\n"
        "  -h                        | This help\n"
        "  -v <1|2|3>                | Verbose 'unknown protocol' packet "
        "print.\n"
        "                            | 1 = verbose\n"
        "                            | 2 = very verbose\n"
        "                            | 3 = port stats\n"
        "  -V <1-4>                  | nDPI logging level\n"
        "                            | 1 - trace, 2 - debug, 3 - full debug\n"
        "                            | >3 - full debug + dbg_proto = all\n"
        "  -T <num>                  | Max number of TCP processed packets "
        "before giving up [default: %u]\n"
        "  -U <num>                  | Max number of UDP processed packets "
        "before giving up [default: %u]\n",
        human_readeable_string_len, min_pattern_len, max_pattern_len,
        max_num_packets_per_flow, max_packet_payload_dissection,
        max_num_reported_top_payloads, max_num_tcp_dissected_pkts,
        max_num_udp_dissected_pkts);

#ifndef WIN32
    printf(
        "\nExcap (wireshark) options:\n"
        "  --extcap-interfaces\n"
        "  --extcap-version\n"
        "  --extcap-dlts\n"
        "  --extcap-interface <name>\n"
        "  --extcap-config\n"
        "  --capture\n"
        "  --extcap-capture-filter\n"
        "  --fifo <path to file or pipe>\n"
        "  --debug\n"
        "  --dbg-proto proto|num[,...]\n");
#endif

    if (long_help) {
        NDPI_PROTOCOL_BITMASK all;

        printf("\n\nnDPI supported protocols:\n");
        printf("%3s %-22s %-8s %-12s %s\n", "Id", "Protocol", "Layer_4",
               "Breed", "Category");
        num_threads = 1;

        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);

        ndpi_dump_protocols(ndpi_info_mod);
    }
    exit(!long_help);
}

static struct option longopts[] = {
    /* mandatory extcap options */
    {"extcap-interfaces", no_argument, NULL, '0'},
    {"extcap-version", optional_argument, NULL, '1'},
    {"extcap-dlts", no_argument, NULL, '2'},
    {"extcap-interface", required_argument, NULL, '3'},
    {"extcap-config", no_argument, NULL, '4'},
    {"capture", no_argument, NULL, '5'},
    {"extcap-capture-filter", required_argument, NULL, '6'},
    {"fifo", required_argument, NULL, '7'},
    {"debug", no_argument, NULL, '8'},
    {"dbg-proto", required_argument, NULL, 257},
    {"ndpi-proto-filter", required_argument, NULL, '9'},

    /* ndpiReader options */
    {"enable-protocol-guess", no_argument, NULL, 'd'},
    {"categories", required_argument, NULL, 'c'},
    {"csv-dump", required_argument, NULL, 'C'},
    {"interface", required_argument, NULL, 'i'},
    {"filter", required_argument, NULL, 'f'},
    {"cpu-bind", required_argument, NULL, 'g'},
    {"loops", required_argument, NULL, 'l'},
    {"num-threads", required_argument, NULL, 'n'},

    {"protos", required_argument, NULL, 'p'},
    {"capture-duration", required_argument, NULL, 's'},
    {"decode-tunnels", no_argument, NULL, 't'},
    {"revision", no_argument, NULL, 'r'},
    {"verbose", no_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {"joy", required_argument, NULL, 'J'},
    {"payload-analysis", required_argument, NULL, 'P'},
    {"result-path", required_argument, NULL, 'w'},
    {"quiet", no_argument, NULL, 'q'},

    {0, 0, 0, 0}};

/* ********************************** */

void extcap_interfaces()
{
    printf("extcap {version=%s}\n", ndpi_revision());
    printf("interface {value=ndpi}{display=nDPI interface}\n");
    exit(0);
}

/* ********************************** */

void extcap_dlts()
{
    u_int dlts_number = DLT_EN10MB;
    printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi",
           "nDPI Interface");
    exit(0);
}

/* ********************************** */


/* ********************************** */

/* ********************************** */

/* ********************************** */

void extcap_config()
{
    int i, argidx = 0;
    struct ndpi_proto_sorter *protos;
    u_int ndpi_num_supported_protocols =
        ndpi_get_ndpi_num_supported_protocols(ndpi_info_mod);
    ndpi_proto_defaults_t *proto_defaults =
        ndpi_get_proto_defaults(ndpi_info_mod);

    /* -i <interface> */
    printf(
        "arg {number=%d}{call=-i}{display=Capture Interface}{type=string}"
        "{tooltip=The interface name}\n",
        argidx++);
    printf(
        "arg {number=%d}{call=-i}{display=Pcap File to "
        "Analyze}{type=fileselect}"
        "{tooltip=The pcap file to analyze (if the interface is "
        "unspecified)}\n",
        argidx++);

    protos = (struct ndpi_proto_sorter *) malloc(
        sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
    if (!protos)
        exit(0);

    for (i = 0; i < (int) ndpi_num_supported_protocols; i++) {
        protos[i].id = i;
        snprintf(protos[i].name, sizeof(protos[i].name), "%s",
                 proto_defaults[i].protoName);
    }

    qsort(protos, ndpi_num_supported_protocols,
          sizeof(struct ndpi_proto_sorter), cmpProto);

    printf(
        "arg {number=%d}{call=-9}{display=nDPI Protocol Filter}{type=selector}"
        "{tooltip=nDPI Protocol to be filtered}\n",
        argidx);

    printf("value {arg=%d}{value=%d}{display=%s}\n", argidx, -1,
           "All Protocols (no nDPI filtering)");

    for (i = 0; i < (int) ndpi_num_supported_protocols; i++)
        printf("value {arg=%d}{value=%d}{display=%s (%d)}\n", argidx,
               protos[i].id, protos[i].name, protos[i].id);

    free(protos);

    exit(0);
}

/* ********************************** */

void extcap_capture()
{
#ifdef DEBUG_TRACE
    if (trace)
        fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

    if ((extcap_dumper =
             pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */),
                            extcap_capture_fifo)) == NULL) {
        fprintf(stderr, "Unable to open the pcap dumper on %s",
                extcap_capture_fifo);

#ifdef DEBUG_TRACE
        if (trace)
            fprintf(trace, "Unable to open the pcap dumper on %s\n",
                    extcap_capture_fifo);
#endif
        return;
    }

#ifdef DEBUG_TRACE
    if (trace)
        fprintf(trace, "Starting packet capture [%p]\n", extcap_dumper);
#endif
}

/* ********************************** */

void printCSVHeader()
{
    if (!csv_fp)
        return;

    fprintf(csv_fp,
            "#flow_id,protocol,first_seen,last_seen,duration,src_ip,src_port,"
            "dst_ip,dst_port,ndpi_proto_num,ndpi_proto,server_name,");
    fprintf(csv_fp,
            "benign_score,dos_slow_score,dos_goldeneye_score,dos_hulk_score,"
            "ddos_score,hearthbleed_score,ftp_patator_score,ssh_patator_score,"
            "infiltration_score,");
    fprintf(csv_fp,
            "c_to_s_pkts,c_to_s_bytes,c_to_s_goodput_bytes,s_to_c_pkts,s_to_c_"
            "bytes,s_to_c_goodput_bytes,");
    fprintf(
        csv_fp,
        "data_ratio,str_data_ratio,c_to_s_goodput_ratio,s_to_c_goodput_ratio,");

    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "iat_flow_min,iat_flow_avg,iat_flow_max,iat_flow_stddev,");
    fprintf(csv_fp,
            "iat_c_to_s_min,iat_c_to_s_avg,iat_c_to_s_max,iat_c_to_s_stddev,");
    fprintf(csv_fp,
            "iat_s_to_c_min,iat_s_to_c_avg,iat_s_to_c_max,iat_s_to_c_stddev,");

    /* Packet Length */
    fprintf(csv_fp,
            "pktlen_c_to_s_min,pktlen_c_to_s_avg,pktlen_c_to_s_max,pktlen_c_to_"
            "s_stddev,");
    fprintf(csv_fp,
            "pktlen_s_to_c_min,pktlen_s_to_c_avg,pktlen_s_to_c_max,pktlen_s_to_"
            "c_stddev,");

    /* TCP flags */
    fprintf(csv_fp, "cwr,ece,urg,ack,psh,rst,syn,fin,");

    fprintf(csv_fp,
            "c_to_s_cwr,c_to_s_ece,c_to_s_urg,c_to_s_ack,c_to_s_psh,c_to_s_rst,"
            "c_to_s_syn,c_to_s_fin,");

    fprintf(csv_fp,
            "s_to_c_cwr,s_to_c_ece,s_to_c_urg,s_to_c_ack,s_to_c_psh,s_to_c_rst,"
            "s_to_c_syn,s_to_c_fin,");

    /* TCP window */
    fprintf(csv_fp, "c_to_s_init_win,s_to_c_init_win,");

    /* Flow info */
    fprintf(csv_fp, "client_info,server_info,");
    fprintf(csv_fp, "tls_version,ja3c,tls_client_unsafe,");
    fprintf(csv_fp, "ja3s,tls_server_unsafe,");
    fprintf(csv_fp, "ssh_client_hassh,ssh_server_hassh,flow_info");

    /* Joy */
    if (enable_joy_stats) {
        fprintf(csv_fp, ",byte_dist_mean,byte_dist_std,entropy,total_entropy");
    }

    fprintf(csv_fp, "\n");
}

/* ********************************** */

/*
 * nDPI option parser
 */
static void parseOptions(int argc, char **argv)
{
    int option_idx = 0, do_capture = 0;
    char *__pcap_file = NULL, *bind_mask = NULL;
    int thread_id, opt;
#ifdef linux
    u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif

#ifdef DEBUG_TRACE
    trace = fopen("/tmp/ndpiReader.log", "a");

    if (trace)
        fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

#ifdef USE_DPDK
    int ret = dpdk_l3fwd_init(argc, argv);
    argc -= ret, argv += ret;
#endif

    while ((opt = getopt_long(
                argc, argv,
                "e:c:C:df:g:i:hp:P:l:s:tv:V:n:Jrp:w:q0123:456:7:89:m:T:U:",
                longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
        if (trace)
            fprintf(trace, " #### -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

        switch (opt) {
        case 'd':
            enable_protocol_guess = 0;
            break;

        case 'e':
            human_readeable_string_len = atoi(optarg);
            break;

        case 'i':
        case '3':
            _pcap_file[0] = optarg;
            break;

        case 'm':
            pcap_analysis_duration = atol(optarg);
            break;

        case 'f':
        case '6':
            bpfFilter = optarg;
            break;

        case 'g':
            bind_mask = optarg;
            break;

        case 'l':
            num_loops = atoi(optarg);
            break;

        case 'n':
            num_threads = atoi(optarg);
            break;

        case 'p':
            _protoFilePath = optarg;
            break;

        case 'c':
            _customCategoryFilePath = optarg;
            break;

        case 'C':
            if ((csv_fp = fopen(optarg, "w")) == NULL)
                printf("Unable to write on CSV file %s\n", optarg);
            break;

        case 's':
            capture_for = atoi(optarg);
            capture_until = capture_for + time(NULL);
            break;

        case 't':
            decode_tunnels = 1;
            break;

        case 'r':
            printf("ndpiReader - nDPI (%s)\n", ndpi_revision());
            exit(0);

        case 'v':
            verbose = atoi(optarg);
            break;

        case 'V':
            nDPI_LogLevel = atoi(optarg);
            if (nDPI_LogLevel < 0)
                nDPI_LogLevel = 0;
            if (nDPI_LogLevel > 3) {
                nDPI_LogLevel = 3;
                _debug_protocols = strdup("all");
            }
            break;

        case 'h':
            help(1);
            break;

        case 'J':
            enable_joy_stats = 1;
            break;

        case 'P': {
            int _min_pattern_len, _max_pattern_len, _max_num_packets_per_flow,
                _max_packet_payload_dissection, _max_num_reported_top_payloads;

            enable_payload_analyzer = 1;
            if (sscanf(optarg, "%d:%d:%d:%d:%d", &_min_pattern_len,
                       &_max_pattern_len, &_max_num_packets_per_flow,
                       &_max_packet_payload_dissection,
                       &_max_num_reported_top_payloads) == 5) {
                min_pattern_len = _min_pattern_len,
                max_pattern_len = _max_pattern_len;
                max_num_packets_per_flow = _max_num_packets_per_flow,
                max_packet_payload_dissection = _max_packet_payload_dissection;
                max_num_reported_top_payloads = _max_num_reported_top_payloads;
                if (min_pattern_len > max_pattern_len)
                    min_pattern_len = max_pattern_len;
                if (min_pattern_len < 2)
                    min_pattern_len = 2;
                if (max_pattern_len > 16)
                    max_pattern_len = 16;
                if (max_num_packets_per_flow == 0)
                    max_num_packets_per_flow = 1;
                if (max_packet_payload_dissection < 4)
                    max_packet_payload_dissection = 4;
                if (max_num_reported_top_payloads == 0)
                    max_num_reported_top_payloads = 1;
            } else {
                printf("Invalid -P format. Ignored\n");
                help(0);
            }
        } break;

        case 'w':
            results_path = strdup(optarg);
            if ((results_file = fopen(results_path, "w")) == NULL) {
                printf("Unable to write in file %s: quitting\n", results_path);
                return;
            }
            break;

        case 'q':
            quiet_mode = 1;
            nDPI_LogLevel = 0;
            break;

            /* Extcap */
        case '0':
            extcap_interfaces();
            break;

        case '1':
            printf("extcap {version=%s}\n", ndpi_revision());
            break;

        case '2':
            extcap_dlts();
            break;

        case '4':
            extcap_config();
            break;

        case '5':
            do_capture = 1;
            break;

        case '7':
            extcap_capture_fifo = strdup(optarg);
            break;

        case '8':
            nDPI_LogLevel = NDPI_LOG_DEBUG_EXTRA;
            _debug_protocols = strdup("all");
            break;

        case '9':
            extcap_packet_filter =
                ndpi_get_proto_by_name(ndpi_info_mod, optarg);
            if (extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN)
                extcap_packet_filter = atoi(optarg);
            break;

        case 257:
            _debug_protocols = strdup(optarg);
            break;

        case 'T':
            max_num_tcp_dissected_pkts = atoi(optarg);
            if (max_num_tcp_dissected_pkts < 3)
                max_num_tcp_dissected_pkts = 3;
            break;

        case 'U':
            max_num_udp_dissected_pkts = atoi(optarg);
            if (max_num_udp_dissected_pkts < 3)
                max_num_udp_dissected_pkts = 3;
            break;

        default:
            help(0);
            break;
        }
    }

#ifndef USE_DPDK
    if (_pcap_file[0] == NULL)
        help(0);
#endif
    if (csv_fp)
        printCSVHeader();

#ifndef USE_DPDK
    if (strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
        num_threads = 0; /* setting number of threads = number of interfaces */
        __pcap_file = strtok(_pcap_file[0], ",");
        while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
            _pcap_file[num_threads++] = __pcap_file;
            __pcap_file = strtok(NULL, ",");
        }
    } else {
        if (num_threads > MAX_NUM_READER_THREADS)
            num_threads = MAX_NUM_READER_THREADS;
        for (thread_id = 1; thread_id < num_threads; thread_id++)
            _pcap_file[thread_id] = _pcap_file[0];
    }

#ifdef linux
    for (thread_id = 0; thread_id < num_threads; thread_id++)
        core_affinity[thread_id] = -1;

    if (num_cores > 1 && bind_mask != NULL) {
        char *core_id = strtok(bind_mask, ":");
        thread_id = 0;
        while (core_id != NULL && thread_id < num_threads) {
            core_affinity[thread_id++] = atoi(core_id) % num_cores;
            core_id = strtok(NULL, ":");
        }
    }
#endif
#endif

#ifdef DEBUG_TRACE
    if (trace)
        fclose(trace);
#endif
}

#if 0
/**
 * @brief A faster replacement for inet_ntoa().
 */
char* intoaV4(u_int32_t addr, char* buf, u_int16_t bufLen) {
  char *cp;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    if(n > 1)
      *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  return(cp);
}
#endif

/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id)
{
    ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
}

/**
 * @brief Force a pcap_dispatch() or pcap_loop() call to return
 */
static void breakPcapLoop(u_int16_t thread_id)
{
#ifdef USE_DPDK
    dpdk_run_capture = 0;
#else
    if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL) {
        pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
    }
#endif
}

/**
 * @brief Sigproc is executed for each packet in the pcap file
 */
void sigproc(int sig)
{
    static int called = 0;
    int thread_id;

    if (called)
        return;
    else
        called = 1;
    shutdown_app = 1;

    for (thread_id = 0; thread_id < num_threads; thread_id++)
        breakPcapLoop(thread_id);
}

/**
 * @brief Get the next pcap file from a passed playlist
 */
static int getNextPcapFileFromPlaylist(u_int16_t thread_id,
                                       char filename[],
                                       u_int32_t filename_len)
{
    if (playlist_fp[thread_id] == NULL) {
        if ((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) ==
            NULL)
            return -1;
    }

next_line:
    if (fgets(filename, filename_len, playlist_fp[thread_id])) {
        int l = strlen(filename);
        if (filename[0] == '\0' || filename[0] == '#')
            goto next_line;
        if (filename[l - 1] == '\n')
            filename[l - 1] = '\0';
        return 0;
    } else {
        fclose(playlist_fp[thread_id]);
        playlist_fp[thread_id] = NULL;
        return -1;
    }
}

/**
 * @brief Configure the pcap handle
 */
static void configurePcapHandle(pcap_t *pcap_handle)
{
    if (bpfFilter != NULL) {
        struct bpf_program fcode;

        if (pcap_compile(pcap_handle, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
            printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
        } else {
            if (pcap_setfilter(pcap_handle, &fcode) < 0) {
                printf("pcap_setfilter error: '%s'\n",
                       pcap_geterr(pcap_handle));
            } else
                printf("Successfully set BPF filter to '%s'\n", bpfFilter);
        }
    }
}

/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t *openPcapFileOrDevice(u_int16_t thread_id,

                                    const u_char *pcap_file)
{
    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = NULL;

    /*
     * If startup without dpdk
     * -> Try to open a live interface or pcap file.
     * else
     * -> Do nothing.
     */
#ifndef USE_DPDK
    if ((pcap_handle = pcap_open_live((char *) pcap_file, snaplen, promisc, 500,
                                      pcap_error_buffer)) == NULL) {
        capture_for = capture_until = 0;

        live_capture = 0;
        num_threads = 1; /* Open pcap files in single threads mode */

        /* trying to open a pcap file */
        if ((pcap_handle = pcap_open_offline((char *) pcap_file,
                                             pcap_error_buffer)) == NULL) {
            char filename[256] = {0};

            if (strstr((char *) pcap_file, (char *) ".pcap"))
                printf("ERROR: could not open pcap file %s: %s\n", pcap_file,
                       pcap_error_buffer);
            else if ((getNextPcapFileFromPlaylist(thread_id, filename,
                                                  sizeof(filename)) != 0) ||
                     ((pcap_handle = pcap_open_offline(
                           filename, pcap_error_buffer)) == NULL)) {
                printf("ERROR: could not open playlist %s: %s\n", filename,
                       pcap_error_buffer);
                exit(-1);
            } else {
                if ((!quiet_mode))
                    printf("Reading packets from playlist %s...\n", pcap_file);
            }
        } else {
            if ((!quiet_mode))
                printf("Reading packets from pcap file %s...\n", pcap_file);
        }
    } else {
        live_capture = 1;

        if ((!quiet_mode)) {
#ifdef USE_DPDK
            printf("Capturing from DPDK (port 0)...\n");
#else
            printf("Capturing live traffic from device %s...\n", pcap_file);
#endif
        }
    }

    configurePcapHandle(pcap_handle);
#endif /* !DPDK */

    if (capture_for > 0) {
        if ((!quiet_mode))
            printf("Capturing traffic up to %u seconds\n",
                   (unsigned int) capture_for);

#ifndef WIN32
        alarm(capture_for);
        signal(SIGALRM, sigproc);
#endif
    }

    return pcap_handle;
}

/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id)
{
    if ((!shutdown_app) &&
        (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL))
        if (pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1,
                      &ndpi_process_packet, (u_char *) &thread_id) < 0)
            printf(
                "Error while reading pcap file: '%s'\n",
                pcap_geterr(ndpi_thread_info[thread_id].workflow->pcap_handle));
}

/**
 * @brief Process a running thread
 */
void *processing_thread(void *_thread_id)
{
    long thread_id = (long) _thread_id;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

#if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
    if (core_affinity[thread_id] >= 0) {
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(core_affinity[thread_id], &cpuset);

        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                   &cpuset) != 0)
            fprintf(stderr, "Error while binding thread %ld to core %d\n",
                    thread_id, core_affinity[thread_id]);
        else {
            if ((!quiet_mode))
                printf("Running thread %ld on core %d...\n", thread_id,
                       core_affinity[thread_id]);
        }
    } else
#endif
        if ((!quiet_mode))
        printf("Running thread %ld...\n", thread_id);

pcap_loop:
    runPcapLoop(thread_id);

    if (playlist_fp[thread_id] != NULL) { /* playlist: read next file */
        char filename[256];

        if (getNextPcapFileFromPlaylist(thread_id, filename,
                                        sizeof(filename)) == 0 &&
            (ndpi_thread_info[thread_id].workflow->pcap_handle =
                 pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
            configurePcapHandle(
                ndpi_thread_info[thread_id].workflow->pcap_handle);
            goto pcap_loop;
        }
    }
    return NULL;
}

/* Create threads, Start to capture, analyze and transfer packets */
void test_lib()
{
    u_int64_t processing_time_usec, setup_time_usec;
#ifdef USE_DPDK
    uint16_t portid;
    unsigned lcore_id;
    int nb_ports = rte_eth_dev_count_avail();

    /* Setup Detection model */
    for (portid = 0; portid < nb_ports; portid++) {
        pcap_t *cap;
        cap = openPcapFileOrDevice(portid, (const u_char *) _pcap_file[portid]);
        setupDetection(portid, cap);
    }

    gettimeofday(&begin, NULL);  // program startup_time

    /* Launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(l3fwd_lkp.main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            break;
        }
    }

    /* Stop ports */
    RTE_ETH_FOREACH_DEV(portid)
    {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
    printf("Bye...\n");

    gettimeofday(&end, NULL);  // program close_time
    /* Calculate the running time of nDPI */
    processing_time_usec = end.tv_sec * 1000000 + end.tv_usec -
                           (begin.tv_sec * 1000000 + begin.tv_usec);
    setup_time_usec = begin.tv_sec * 1000000 + begin.tv_usec -
                      (startup_time.tv_sec * 1000000 + startup_time.tv_usec);

    /* Printing cumulative results */
    printResults(processing_time_usec, setup_time_usec);

    /* pcap close */
    for (portid = 0; portid < nb_ports; portid++) {
        if (ndpi_thread_info[portid].workflow->pcap_handle != NULL)
            pcap_close(ndpi_thread_info[portid].workflow->pcap_handle);

        terminateDetection(portid);
    }
    snort_parser_release();
#else
    long thread_id;
    int status;
    void *thd_res;

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        pcap_t *cap;

        cap = openPcapFileOrDevice(thread_id,
                                   (const u_char *) _pcap_file[thread_id]);
        setupDetection(thread_id, cap);
    }
    gettimeofday(&begin, NULL);


    /* Running processing threads */
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL,
                                processing_thread, (void *) thread_id);
        /* check pthreade_create return value */
        if (status != 0) {
            fprintf(stderr, "error on create %ld thread\n", thread_id);
            exit(-1);
        }
    }
    /* Waiting for completion */
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
        /* check pthreade_join return value */
        if (status != 0) {
            fprintf(stderr, "error on join %ld thread\n", thread_id);
            exit(-1);
        }
        if (thd_res != NULL) {
            fprintf(stderr, "error on returned value of %ld joined thread\n",
                    thread_id);
            exit(-1);
        }
    }

    gettimeofday(&end, NULL);
    processing_time_usec = end.tv_sec * 1000000 + end.tv_usec -
                           (begin.tv_sec * 1000000 + begin.tv_usec);
    setup_time_usec = begin.tv_sec * 1000000 + begin.tv_usec -
                      (startup_time.tv_sec * 1000000 + startup_time.tv_usec);

    /* Printing cumulative results */
    printResults(processing_time_usec, setup_time_usec);

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        if (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
            pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

        terminateDetection(thread_id);
    }
#endif
}

/* *********************************************** */

void automataUnitTest()
{
    void *automa = ndpi_init_automa();

    assert(automa);
    assert(ndpi_add_string_to_automa(automa, "hello") == 0);
    assert(ndpi_add_string_to_automa(automa, "world") == 0);
    ndpi_finalize_automa(automa);
    assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") ==
           1);
    ndpi_free_automa(automa);
}

/* *********************************************** */

void serializerUnitTest()
{
    ndpi_serializer serializer, deserializer;
    int i;
    u_int8_t trace = 0;

    assert(ndpi_init_serializer(&serializer, ndpi_serialization_format_tlv) !=
           -1);

    for (i = 0; i < 16; i++) {
        char kbuf[32], vbuf[32];
        assert(ndpi_serialize_uint32_uint32(&serializer, i, i * i) != -1);

        snprintf(kbuf, sizeof(kbuf), "Hello %d", i);
        snprintf(vbuf, sizeof(vbuf), "World %d", i);
        assert(ndpi_serialize_uint32_string(&serializer, i, "Hello") != -1);
        assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
        assert(ndpi_serialize_string_uint32(&serializer, kbuf, i * i) != -1);
        assert(ndpi_serialize_string_float(&serializer, kbuf, (float) (i * i),
                                           "%f") != -1);
    }

    if (trace)
        printf("Serialization size: %u\n",
               ndpi_serializer_get_buffer_len(&serializer));

    assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);

    while (1) {
        ndpi_serialization_type kt, et;
        et = ndpi_deserialize_get_item_type(&deserializer, &kt);

        if (et == ndpi_serialization_unknown)
            break;
        else {
            u_int32_t k32, v32;
            ndpi_string ks, vs;
            float vf;

            switch (kt) {
            case ndpi_serialization_uint32:
                ndpi_deserialize_key_uint32(&deserializer, &k32);
                if (trace)
                    printf("%u=", k32);
                break;
            case ndpi_serialization_string:
                ndpi_deserialize_key_string(&deserializer, &ks);
                if (trace) {
                    u_int8_t bkp = ks.str[ks.str_len];
                    ks.str[ks.str_len] = '\0';
                    printf("%s=", ks.str);
                    ks.str[ks.str_len] = bkp;
                }
                break;
            default:
                printf("Unsupported TLV key type %u\n", kt);
                return;
            }

            switch (et) {
            case ndpi_serialization_uint32:
                assert(ndpi_deserialize_value_uint32(&deserializer, &v32) !=
                       -1);
                if (trace)
                    printf("%u\n", v32);
                break;

            case ndpi_serialization_string:
                assert(ndpi_deserialize_value_string(&deserializer, &vs) != -1);
                if (trace) {
                    u_int8_t bkp = vs.str[vs.str_len];
                    vs.str[vs.str_len] = '\0';
                    printf("%s\n", vs.str);
                    vs.str[vs.str_len] = bkp;
                }
                break;

            case ndpi_serialization_float:
                assert(ndpi_deserialize_value_float(&deserializer, &vf) != -1);
                if (trace)
                    printf("%f\n", vf);
                break;

            default:
                if (trace)
                    printf("\n");
                printf("serializerUnitTest: unsupported type %u detected!\n",
                       et);
                return;
                break;
            }
        }

        ndpi_deserialize_next(&deserializer);
    }

    ndpi_term_serializer(&serializer);
}

/* *********************************************** */

// #define RUN_DATA_ANALYSIS_THEN_QUIT 1

void analyzeUnitTest()
{
    struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
    u_int32_t i;

    for (i = 0; i < 256; i++) {
        ndpi_data_add_value(s, rand() * i);
        // ndpi_data_add_value(s, i+1);
    }

    // ndpi_data_print_window_values(s);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
    printf("Average: [all: %f][window: %f]\n", ndpi_data_average(s),
           ndpi_data_window_average(s));
    printf("Entropy: %f\n", ndpi_data_entropy(s));

    printf("Min/Max: %u/%u\n", ndpi_data_min(s), ndpi_data_max(s));
#endif

    ndpi_free_data_analysis(s);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
    exit(0);
#endif
}

/* *********************************************** */
/**
 * @brief Initialize port array
 */

void bpf_filter_port_array_init(int array[], int size)
{
    int i;
    for (i = 0; i < size; i++)
        array[i] = INIT_VAL;
}

/* *********************************************** */
/**
 * @brief Initialize host array
 */

void bpf_filter_host_array_init(const char *array[48], int size)
{
    int i;
    for (i = 0; i < size; i++)
        array[i] = NULL;
}

/* *********************************************** */

/**
 * @brief Add host to host filter array
 */

void bpf_filter_host_array_add(const char *filter_array[48],
                               int size,
                               const char *host)
{
    int i;
    int r;
    for (i = 0; i < size; i++) {
        if ((filter_array[i] != NULL) &&
            (r = strcmp(filter_array[i], host)) == 0)
            return;
        if (filter_array[i] == NULL) {
            filter_array[i] = host;
            return;
        }
    }
    fprintf(stderr, "bpf_filter_host_array_add: max array size is reached!\n");
    exit(-1);
}

/* *********************************************** */

/**
 * @brief Add port to port filter array
 */

void bpf_filter_port_array_add(int filter_array[], int size, int port)
{
    int i;
    for (i = 0; i < size; i++) {
        if (filter_array[i] == port)
            return;
        if (filter_array[i] == INIT_VAL) {
            filter_array[i] = port;
            return;
        }
    }
    fprintf(stderr, "bpf_filter_port_array_add: max array size is reached!\n");
    exit(-1);
}

static void dpiresults_init()
{
    for (int i = 0; i < MAX_NUM_READER_THREADS; i++) {
        /* Time record init */
        dpiresults[i].total_time = 0;
        dpiresults[i].capture_time = 0;
        dpiresults[i].analyze_time = 0;
        /* Number of packets and packets size */
        dpiresults[i].total_rx_packets = 0;
        dpiresults[i].total_tx_packets = 0;
        dpiresults[i].total_bytes = 0;
        dpiresults[i].total_malicious = 0;
    }
    return;
}

int main(int argc, char **argv)
{
    int i;

    if (ndpi_get_api_version() != NDPI_API_VERSION) {
        printf(
            "nDPI Library version mismatch: please make sure this code and the "
            "nDPI library are in sync\n");
        return (-1);
    }

    /* Internal checks */
    automataUnitTest();
    serializerUnitTest();
    analyzeUnitTest();

    pattern_search_module_init();
    dpiresults_init();

    gettimeofday(&startup_time, NULL);
    ndpi_info_mod = ndpi_init_detection_module(ndpi_no_prefs);

    if (ndpi_info_mod == NULL)
        return -1;

    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

    parseOptions(argc, argv);

    if (!quiet_mode) {
        printf(
            "\n-----------------------------------------------------------\n"
            "* NOTE: This is demo app to show *some* nDPI features.\n"
            "* In this demo we have implemented only some basic features\n"
            "* just to show you what you can do with the library. Feel \n"
            "* free to extend it and send us the patches for inclusion\n"
            "------------------------------------------------------------\n\n");

        printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(),
               num_threads);
    }

    signal(SIGINT, sigproc);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* for (i = 0; i < num_loops; i++) */
    test_lib();

    /* output file .. not used  */
    /* if(results_path)  free(results_path); */
    /* if(results_file)  fclose(results_file); */
    /* if(extcap_dumper) pcap_dump_close(extcap_dumper); */
    /* if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod); */
    /* if(csv_fp)        fclose(csv_fp); */

    return 0;
}

#ifdef WIN32
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

/**
   @brief Timezone
**/
struct timezone {
    int tz_minuteswest; /* minutes W of Greenwich */
    int tz_dsttime;     /* type of dst correction */
};

/**
   @brief Set time
**/
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    FILETIME ft;
    LARGE_INTEGER li;
    __int64 t;
    static int tzflag;

    if (tv) {
        GetSystemTimeAsFileTime(&ft);
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        t = li.QuadPart;    /* In 100-nanosecond intervals */
        t -= EPOCHFILETIME; /* Offset to the Epoch time */
        t /= 10;            /* In microseconds */
        tv->tv_sec = (long) (t / 1000000);
        tv->tv_usec = (long) (t % 1000000);
    }

    if (tz) {
        if (!tzflag) {
            _tzset();
            tzflag++;
        }

        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    return 0;
}
#endif /* WIN32 */
