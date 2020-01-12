#ifndef _NDPI_DETECTION_H_
#define _NDPI_DETECTION_H_

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <math.h>
#include <pthread.h>

/* nDPI lib */
#include "ndpi_api.h"
#include "ndpi_config.h"

/* local source */
#include "intrusion_detection.h"
#include "ndpi_init.h"
#include "reader_util.h"
#include "uthash.h"

/* variable declaration */

u_int32_t current_ndpi_memory, max_ndpi_memory;
char *_debug_protocols;
u_int8_t enable_protocol_guess, enable_payload_analyzer;
u_int8_t verbose, enable_joy_stats;
u_int8_t human_readeable_string_len;
u_int8_t max_num_udp_dissected_pkts, max_num_tcp_dissected_pkts;

/* Structure declaration */
struct ndpi_packet_trailer {
    u_int32_t magic; /* 0x19682017 */
    u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
    char name[16];
};

// struct associated to a workflow for a thread
struct reader_thread {
    struct ndpi_workflow *workflow;
    pthread_t pthread;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};
// array for every thread created for a flow
struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

struct info_pair {
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16];   /*app level protocol*/
    int count;
};

typedef struct node_a {
    u_int32_t addr;
    u_int8_t version; /* IP version */
    char proto[16];   /*app level protocol*/
    int count;
    struct node_a *left, *right;
} addr_node;

struct port_stats {
    u_int32_t port; /* we'll use this field as the key */
    u_int32_t num_pkts, num_bytes;
    u_int32_t num_flows;
    u_int32_t num_addr;        /*number of distinct IP addresses */
    u_int32_t cumulative_addr; /*cumulative some of IP addresses */
    addr_node *addr_tree;      /* tree of distinct IP addresses */
    struct info_pair top_ip_addrs[MAX_NUM_IP_ADDRESS];
    u_int8_t hasTopHost; /* as boolean flag */
    u_int32_t top_host;  /* host that is contributed to > 95% of traffic */
    u_int8_t version;    /* top host's ip version */
    char proto[16];      /* application level protocol of top host */
    UT_hash_handle hh;   /* makes this structure hashable */
};
static struct port_stats *srcStats = NULL, *dstStats = NULL;

// struct to hold single packet tcp flows sent by source ip address
struct single_flow_info {
    u_int32_t saddr;  /* key */
    u_int8_t version; /* IP version */
    struct port_flow_info *ports;
    u_int32_t tot_flows;
    UT_hash_handle hh;
};
static struct single_flow_info *scannerHosts = NULL;

// struct to hold top receiver hosts
struct receiver {
    u_int32_t addr;   /* key */
    u_int8_t version; /* IP version */
    u_int32_t num_pkts;
    UT_hash_handle hh;
};
static struct receiver *receivers = NULL, *topReceivers = NULL;

// struct to hold count of flows received by destination ports
struct port_flow_info {
    u_int32_t port; /* key */
    u_int32_t num_flows;
    UT_hash_handle hh;
};

struct ndpi_proto_sorter {
    int id;
    char name[16];
};

struct flow_info {
    struct ndpi_flow_info *flow;
    u_int16_t thread_id;
};
static struct flow_info *all_flows;


static struct timeval pcap_start = {0, 0}, pcap_end = {0, 0};
static struct timeval startup_time, begin, end;

static u_int8_t live_capture = 0;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t undetected_flows_deleted = 0;

static char extcap_buf[16384];
static char *extcap_capture_fifo = NULL;
static pcap_dumper_t *extcap_dumper = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t) -1;

static u_int32_t pcap_analysis_duration = (u_int32_t) -1;

/* Detection parameters */
static u_int32_t num_flows;
static time_t capture_for = 0;
static time_t capture_until = 0;
static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection,
    max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;

/* Functions declaration */

void setupDetection(u_int16_t thread_id, pcap_t *pcap_handle);

void ndpi_process_packet(u_char *args,
                         const struct pcap_pkthdr *header,
                         const u_char *packet);

void node_idle_scan_walker(const void *node,
                           ndpi_VISIT which,
                           int depth,
                           void *user_data);

void node_proto_guess_walker(const void *node,
                             ndpi_VISIT which,
                             int depth,
                             void *user_data);

void port_stats_walker(const void *node,
                       ndpi_VISIT which,
                       int depth,
                       void *user_data);

char *formatBytes(u_int32_t howMuch, char *buf, u_int buf_len);
char *formatPackets(float numPkts, char *buf);
char *formatTraffic(float numBits, int bits, char *buf);
char *ipProto2Name(u_int16_t proto_id);

int port_stats_sort(void *_a, void *_b);

int cmpProto(const void *_a, const void *_b);
int cmpFlows(const void *_a, const void *_b);
/* Update */
void updateScanners(struct single_flow_info **scanners,
                    u_int32_t saddr,
                    u_int8_t version,
                    u_int32_t dport);

void updateReceivers(struct receiver **rcvrs,
                     u_int32_t dst_addr,
                     u_int8_t version,
                     u_int32_t num_pkts,
                     struct receiver **topRcvrs);

void updatePortStats(struct port_stats **stats,
                     u_int32_t port,
                     u_int32_t addr,
                     u_int8_t version,
                     u_int32_t num_pkts,
                     u_int32_t num_bytes,
                     const char *proto);

int updateIpTree(u_int32_t key,
                 u_int8_t version,
                 addr_node **vrootp,
                 const char *proto);
/* delete */
void deleteScanners(struct single_flow_info *scanners);
void deletePortsStats(struct port_stats *stats);

void freeIpTree(addr_node *root);
/* Print info */
char *printUrlRisk(ndpi_url_risk risk);
char *print_cipher(ndpi_cipher_weakness c);

void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec);
void printFlowsStats();
void printPortStats(struct port_stats *stats);

extern void ndpi_report_payload_stats();
#endif
