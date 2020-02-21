#include "ndpi_detection.h"

int nDPI_LogLevel = 0;

/* Shared variables in detection, reader_util and main  */
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
char *_debug_protocols = NULL;
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t verbose = 0, enable_joy_stats = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts =
             16 /* 8 is enough for most protocols, Signal requires more */,
         max_num_tcp_dissected_pkts = 80 /* due to telnet */;

/* Function define */
static void on_protocol_discovered(struct ndpi_workflow *workflow,
                                   struct ndpi_flow_info *flow,
                                   void *udata)
{
    ;
}

/* Setup for detection begin */
void setupDetection(u_int16_t thread_id, pcap_t *pcap_handle)
{
    NDPI_PROTOCOL_BITMASK all;
    struct ndpi_workflow_prefs prefs;

    memset(&prefs, 0, sizeof(prefs));
    prefs.decode_tunnels = decode_tunnels;
    prefs.num_roots = NUM_ROOTS;
    prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
    prefs.quiet_mode = quiet_mode;

    memset(&ndpi_thread_info[thread_id], 0,
           sizeof(ndpi_thread_info[thread_id]));
    ndpi_thread_info[thread_id].workflow =
        ndpi_workflow_init(&prefs, pcap_handle);

    /* Preferences */
    ndpi_workflow_set_flow_detected_callback(
        ndpi_thread_info[thread_id].workflow, on_protocol_discovered,
        (void *) (uintptr_t) thread_id);

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(
        ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);

    // clear memory for results
    memset(
        ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0,
        sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes,
           0,
           sizeof(ndpi_thread_info[thread_id]
                      .workflow->stats.protocol_counter_bytes));
    memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0,
           sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));

    if (_protoFilePath != NULL)
        ndpi_load_protocols_file(
            ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);

    if (_customCategoryFilePath)
        ndpi_load_categories_file(
            ndpi_thread_info[thread_id].workflow->ndpi_struct,
            _customCategoryFilePath);

    ndpi_finalize_initalization(
        ndpi_thread_info[thread_id].workflow->ndpi_struct);
}

/* Check packet */
void ndpi_process_packet(u_char *args,
                         const struct pcap_pkthdr *header,
                         const u_char *packet)
{
    struct ndpi_proto p;
    u_int16_t thread_id = (u_int16_t) 0;  //*((u_int16_t *) args);


    /* allocate an exact size buffer to check overflows */
    uint8_t *packet_checked = malloc(header->caplen);

    memcpy(packet_checked, packet, header->caplen);

    p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow,
                                     header, packet_checked);

    if (!pcap_start.tv_sec)
        pcap_start.tv_sec = header->ts.tv_sec,
        pcap_start.tv_usec = header->ts.tv_usec;
    pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;

    /* Idle flows cleanup */
    if (live_capture) {
        if (ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD <
            ndpi_thread_info[thread_id].workflow->last_time) {
            /* scan for idle flows */
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root
                           [ndpi_thread_info[thread_id].idle_scan_idx],
                       node_idle_scan_walker, &thread_id);

            /* remove idle flows (unfortunately we cannot do this inline) */
            while (ndpi_thread_info[thread_id].num_idle_flows > 0) {
                /* search and delete the idle flow from the "ndpi_flow_root"
                 * (see struct reader thread) - here flows are the node of a
                 * b-tree */
                ndpi_tdelete(
                    ndpi_thread_info[thread_id].idle_flows
                        [--ndpi_thread_info[thread_id].num_idle_flows],
                    &ndpi_thread_info[thread_id].workflow->ndpi_flows_root
                         [ndpi_thread_info[thread_id].idle_scan_idx],
                    ndpi_workflow_node_cmp);

                /* free the memory associated to idle flow in "idle_flows" -
                 * (see struct reader thread)*/
                ndpi_free_flow_info_half(
                    ndpi_thread_info[thread_id].idle_flows
                        [ndpi_thread_info[thread_id].num_idle_flows]);
                ndpi_free(ndpi_thread_info[thread_id].idle_flows
                              [ndpi_thread_info[thread_id].num_idle_flows]);
            }

            if (++ndpi_thread_info[thread_id].idle_scan_idx ==
                ndpi_thread_info[thread_id].workflow->prefs.num_roots)
                ndpi_thread_info[thread_id].idle_scan_idx = 0;

            ndpi_thread_info[thread_id].last_idle_scan_time =
                ndpi_thread_info[thread_id].workflow->last_time;
        }
    }

#ifdef DEBUG_TRACE
    if (trace)
        fprintf(trace, "Found %u bytes packet %u.%u\n", header->caplen,
                p.app_protocol, p.master_protocol);
#endif

    if (extcap_dumper && ((extcap_packet_filter == (u_int16_t) -1) ||
                          (p.app_protocol == extcap_packet_filter) ||
                          (p.master_protocol == extcap_packet_filter))) {
        struct pcap_pkthdr h;
        uint32_t *crc, delta = sizeof(struct ndpi_packet_trailer) +
                               4 /* ethernet trailer */;
        struct ndpi_packet_trailer *trailer;

        memcpy(&h, header, sizeof(h));

        if (h.caplen >
            (sizeof(extcap_buf) - sizeof(struct ndpi_packet_trailer) - 4)) {
            printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
            h.caplen =
                sizeof(extcap_buf) - sizeof(struct ndpi_packet_trailer) - 4;
        }

        trailer = (struct ndpi_packet_trailer *) &extcap_buf[h.caplen];
        memcpy(extcap_buf, packet, h.caplen);
        memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
        trailer->magic = htonl(0x19680924);
        trailer->master_protocol = htons(p.master_protocol),
        trailer->app_protocol = htons(p.app_protocol);
        ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p,
                           trailer->name, sizeof(trailer->name));
        crc = (uint32_t *) &extcap_buf[h.caplen +
                                       sizeof(struct ndpi_packet_trailer)];
        *crc = ethernet_crc32((const void *) extcap_buf,
                              h.caplen + sizeof(struct ndpi_packet_trailer));
        h.caplen += delta, h.len += delta;

#ifdef DEBUG_TRACE
        if (trace)
            fprintf(trace, "Dumping %u bytes packet\n", h.caplen);
#endif

        pcap_dump((u_char *) extcap_dumper, &h, (const u_char *) extcap_buf);
        pcap_dump_flush(extcap_dumper);
    }

    /* check for buffer changes */
    if (memcmp(packet, packet_checked, header->caplen) != 0)
        printf(
            "INTERNAL ERROR: ingress packet was modified by nDPI: this should "
            "not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
            thread_id,
            (unsigned long) ndpi_thread_info[thread_id]
                .workflow->stats.raw_packet_count,
            header->caplen);

    if ((pcap_end.tv_sec - pcap_start.tv_sec) > pcap_analysis_duration) {
        int i;
        u_int64_t processing_time_usec, setup_time_usec;

        gettimeofday(&end, NULL);
        processing_time_usec = end.tv_sec * 1000000 + end.tv_usec -
                               (begin.tv_sec * 1000000 + begin.tv_usec);
        setup_time_usec =
            begin.tv_sec * 1000000 + begin.tv_usec -
            (startup_time.tv_sec * 1000000 + startup_time.tv_usec);

        printResults(processing_time_usec, setup_time_usec);

        for (i = 0; i < ndpi_thread_info[thread_id].workflow->prefs.num_roots;
             i++) {
            ndpi_tdestroy(
                ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                ndpi_flow_info_freer);
            ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

            memset(&ndpi_thread_info[thread_id].workflow->stats, 0,
                   sizeof(struct ndpi_stats));
        }

        if (!quiet_mode)
            printf("\n-------------------------------------------\n\n");

        memcpy(&begin, &end, sizeof(begin));
        memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
    }

    /*
       Leave the free as last statement to avoid crashes when
       ndpi_detection_giveup() is called above by printResults()
       */
    free(packet_checked);
}

/*
 * Idle Scan Walker
 */
void node_idle_scan_walker(const void *node,
                           ndpi_VISIT which,
                           int depth,
                           void *user_data)
{
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);

    if (ndpi_thread_info[thread_id].num_idle_flows ==
        IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
        return;

    if ((which == ndpi_preorder) ||
        (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if (flow->last_seen + MAX_IDLE_TIME <
            ndpi_thread_info[thread_id].workflow->last_time) {
            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);

            if ((flow->detected_protocol.app_protocol ==
                 NDPI_PROTOCOL_UNKNOWN) &&
                !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            ndpi_free_flow_info_half(flow);
            ndpi_free_flow_data_analysis(flow);
            ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_thread_info[thread_id]
                .idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] =
                flow;
        }
    }
}

/*
 *Proto Guess Walker
 */
void node_proto_guess_walker(const void *node,
                             ndpi_VISIT which,
                             int depth,
                             void *user_data)
{
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data), proto;

    if ((which == ndpi_preorder) ||
        (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if ((!flow->detection_completed) && flow->ndpi_flow) {
            u_int8_t proto_guessed;

            flow->detected_protocol = ndpi_detection_giveup(
                ndpi_thread_info[0].workflow->ndpi_struct, flow->ndpi_flow,
                enable_protocol_guess, &proto_guessed);
        }

        process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);

        proto = flow->detected_protocol.app_protocol
                    ? flow->detected_protocol.app_protocol
                    : flow->detected_protocol.master_protocol;

        ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto] +=
            flow->src2dst_packets + flow->dst2src_packets;
        ndpi_thread_info[thread_id]
            .workflow->stats.protocol_counter_bytes[proto] +=
            flow->src2dst_bytes + flow->dst2src_bytes;
        ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
    }
}

/*
 * Ports stats
 */
void port_stats_walker(const void *node,
                       ndpi_VISIT which,
                       int depth,
                       void *user_data)
{
    if ((which == ndpi_preorder) ||
        (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
        u_int16_t thread_id = *(int *) user_data;
        u_int16_t sport, dport;
        char proto[16];
        int r;

        sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

        /* get app level protocol */
        if (flow->detected_protocol.master_protocol)
            ndpi_protocol2name(
                ndpi_thread_info[thread_id].workflow->ndpi_struct,
                flow->detected_protocol, proto, sizeof(proto));
        else
            strncpy(proto,
                    ndpi_get_proto_name(
                        ndpi_thread_info[thread_id].workflow->ndpi_struct,
                        flow->detected_protocol.app_protocol),
                    sizeof(proto));

        if (((r = strcmp(ipProto2Name(flow->protocol), "TCP")) == 0) &&
            (flow->src2dst_packets == 1) && (flow->dst2src_packets == 0)) {
            updateScanners(&scannerHosts, flow->src_ip, flow->ip_version,
                           dport);
        }

        updateReceivers(&receivers, flow->dst_ip, flow->ip_version,
                        flow->src2dst_packets, &topReceivers);

        updatePortStats(&srcStats, sport, flow->src_ip, flow->ip_version,
                        flow->src2dst_packets, flow->src2dst_bytes, proto);

        updatePortStats(&dstStats, dport, flow->dst_ip, flow->ip_version,
                        flow->dst2src_packets, flow->dst2src_bytes, proto);
    }
}

/*
 * Bytes stats format
 */
char *formatBytes(u_int32_t howMuch, char *buf, u_int buf_len)
{
    char unit = 'B';

    if (howMuch < 1024) {
        snprintf(buf, buf_len, "%lu %c", (unsigned long) howMuch, unit);
    } else if (howMuch < (1024 * 1024)) {
        snprintf(buf, buf_len, "%.2f K%c", (float) (howMuch) / 1024, unit);
    } else {
        float tmpGB = ((float) howMuch) / (1024 * 1024);

        if (tmpGB < 1024) {
            snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
        } else {
            tmpGB /= 1024;

            snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
        }
    }
    return (buf);
}

/*
 * Packets stats format
 */
char *formatPackets(float numPkts, char *buf)
{
    if (numPkts < 1000) {
        snprintf(buf, 32, "%.2f", numPkts);
    } else if (numPkts < (1000 * 1000)) {
        snprintf(buf, 32, "%.2f K", numPkts / 1000);
    } else {
        numPkts /= (1000 * 1000);
        snprintf(buf, 32, "%.2f M", numPkts);
    }

    return (buf);
}

/*
 * Traffic stats format
 */
char *formatTraffic(float numBits, int bits, char *buf)
{
    char unit;

    if (bits)
        unit = 'b';
    else
        unit = 'B';

    if (numBits < 1024)
        snprintf(buf, 32, "%lu %c", (unsigned long) numBits, unit);
    else if (numBits < (1024 * 1024))
        snprintf(buf, 32, "%.2f K%c", (float) (numBits) / 1024, unit);
    else {
        float tmpMBits = ((float) numBits) / (1024 * 1024);

        if (tmpMBits < 1024)
            snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
        else {
            tmpMBits /= 1024;

            if (tmpMBits < 1024)
                snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
            else
                snprintf(buf, 32, "%.2f T%c", (float) (tmpMBits) / 1024, unit);
        }
    }

    return (buf);
}

int port_stats_sort(void *_a, void *_b)
{
    struct port_stats *a = (struct port_stats *) _a;
    struct port_stats *b = (struct port_stats *) _b;

    if (b->num_pkts == 0 && a->num_pkts == 0)
        return (b->num_flows - a->num_flows);

    return (b->num_pkts - a->num_pkts);
}

/*
 * From IPPROTO to string NAME
 */
char *ipProto2Name(u_int16_t proto_id)
{
    static char proto[8];

    switch (proto_id) {
    case IPPROTO_TCP:
        return ("TCP");
        break;
    case IPPROTO_UDP:
        return ("UDP");
        break;
    case IPPROTO_ICMP:
        return ("ICMP");
        break;
    case IPPROTO_ICMPV6:
        return ("ICMPV6");
        break;
    case 112:
        return ("VRRP");
        break;
    case IPPROTO_IGMP:
        return ("IGMP");
        break;
    }

    snprintf(proto, sizeof(proto), "%u", proto_id);
    return (proto);
}

/* heuristic choice for receiver stats */
static int acceptable(u_int32_t num_pkts)
{
    return num_pkts > 5;
}

static int receivers_sort(void *_a, void *_b)
{
    struct receiver *a = (struct receiver *) _a;
    struct receiver *b = (struct receiver *) _b;

    return (b->num_pkts - a->num_pkts);
}

static int receivers_sort_asc(void *_a, void *_b)
{
    struct receiver *a = (struct receiver *) _a;
    struct receiver *b = (struct receiver *) _b;

    return (a->num_pkts - b->num_pkts);
}

/* Removes first (size - max) elements from hash table.
 * hash table is ordered in ascending order.
 */
static struct receiver *cutBackTo(struct receiver **rcvrs,
                                  u_int32_t size,
                                  u_int32_t max)
{
    struct receiver *r, *tmp;
    int i = 0;
    int count;

    if (size < max)  // return the original table
        return *rcvrs;

    count = size - max;

    HASH_ITER(hh, *rcvrs, r, tmp)
    {
        if (i++ == count)
            return r;
        HASH_DEL(*rcvrs, r);
        free(r);
    }

    return (NULL);
}

int updateIpTree(u_int32_t key,
                 u_int8_t version,
                 addr_node **vrootp,
                 const char *proto)
{
    addr_node *q;
    addr_node **rootp = vrootp;

    if (rootp == (addr_node **) 0)
        return 0;

    while (*rootp != (addr_node *) 0) {
        /* Knuth's T1: */
        if ((version == (*rootp)->version) && (key == (*rootp)->addr)) {
            /* T2: */
            return ++((*rootp)->count);
        }

        rootp = (key < (*rootp)->addr) ? &(*rootp)->left
                                       : /* T3: follow left branch */
                    &(*rootp)->right;    /* T4: follow right branch */
    }

    q = (addr_node *) malloc(sizeof(addr_node)); /* T5: key not found */
    if (q != (addr_node *) 0) {                  /* make new node */
        *rootp = q;                              /* link new node to old */

        q->addr = key;
        q->version = version;
        strncpy(q->proto, proto, sizeof(q->proto));
        q->count = UPDATED_TREE;
        q->left = q->right = (addr_node *) 0;

        return q->count;
    }

    return (0);
}
/* Merge first table to the second table.
 * if element already in the second table
 *  then updates its value
 * else adds it to the second table
 */
static void mergeTables(struct receiver **primary, struct receiver **secondary)
{
    struct receiver *r, *s, *tmp;

    HASH_ITER(hh, *primary, r, tmp)
    {
        HASH_FIND_INT(*secondary, (int *) &(r->addr), s);
        if (s == NULL) {
            s = (struct receiver *) malloc(sizeof(struct receiver));
            if (!s)
                return;

            s->addr = r->addr;
            s->version = r->version;
            s->num_pkts = r->num_pkts;

            HASH_ADD_INT(*secondary, addr, s);
        } else
            s->num_pkts += r->num_pkts;

        HASH_DEL(*primary, r);
        free(r);
    }
}


static void deleteReceivers(struct receiver *rcvrs)
{
    struct receiver *current, *tmp;

    HASH_ITER(hh, rcvrs, current, tmp)
    {
        HASH_DEL(rcvrs, current);
        free(current);
    }
}

void updateTopIpAddress(u_int32_t addr,
                        u_int8_t version,
                        const char *proto,
                        int count,
                        struct info_pair top[],
                        int size)
{
    struct info_pair pair;
    int min = count;
    int update = 0;
    int min_i = 0;
    int i;

    if (count == 0)
        return;

    pair.addr = addr;
    pair.version = version;
    pair.count = count;
    strncpy(pair.proto, proto, sizeof(pair.proto));

    for (i = 0; i < size; i++) {
        /* if the same ip with a bigger
           count just update it     */
        if (top[i].addr == addr) {
            top[i].count = count;
            return;
        }
        /* if array is not full yet
           add it to the first empty place */
        if (top[i].count == 0) {
            top[i] = pair;
            return;
        }
    }

    /* if bigger than the smallest one, replace it */
    for (i = 0; i < size; i++) {
        if (top[i].count < count && top[i].count < min) {
            min = top[i].count;
            min_i = i;
            update = 1;
        }
    }

    if (update)
        top[min_i] = pair;
}


void updateScanners(struct single_flow_info **scanners,
                    u_int32_t saddr,
                    u_int8_t version,
                    u_int32_t dport)
{
    struct single_flow_info *f;
    struct port_flow_info *p;

    HASH_FIND_INT(*scanners, (int *) &saddr, f);

    if (f == NULL) {
        f = (struct single_flow_info *) malloc(sizeof(struct single_flow_info));
        if (!f)
            return;
        f->saddr = saddr;
        f->version = version;
        f->tot_flows = 1;
        f->ports = NULL;

        p = (struct port_flow_info *) malloc(sizeof(struct port_flow_info));

        if (!p) {
            free(f);
            return;
        } else
            p->port = dport, p->num_flows = 1;

        HASH_ADD_INT(f->ports, port, p);
        HASH_ADD_INT(*scanners, saddr, f);
    } else {
        struct port_flow_info *pp;
        f->tot_flows++;

        HASH_FIND_INT(f->ports, (int *) &dport, pp);

        if (pp == NULL) {
            pp =
                (struct port_flow_info *) malloc(sizeof(struct port_flow_info));
            if (!pp)
                return;
            pp->port = dport, pp->num_flows = 1;

            HASH_ADD_INT(f->ports, port, pp);
        } else
            pp->num_flows++;
    }
}

void updateReceivers(struct receiver **rcvrs,
                     u_int32_t dst_addr,
                     u_int8_t version,
                     u_int32_t num_pkts,
                     struct receiver **topRcvrs)
{
    struct receiver *r;
    u_int32_t size;
    int a;

    HASH_FIND_INT(*rcvrs, (int *) &dst_addr, r);
    if (r == NULL) {
        if (((size = HASH_COUNT(*rcvrs)) < MAX_TABLE_SIZE_1) ||
            ((a = acceptable(num_pkts)) != 0)) {
            r = (struct receiver *) malloc(sizeof(struct receiver));
            if (!r)
                return;

            r->addr = dst_addr;
            r->version = version;
            r->num_pkts = num_pkts;

            HASH_ADD_INT(*rcvrs, addr, r);

            if ((size = HASH_COUNT(*rcvrs)) > MAX_TABLE_SIZE_2) {
                HASH_SORT(*rcvrs, receivers_sort_asc);
                *rcvrs = cutBackTo(rcvrs, size, MAX_TABLE_SIZE_1);
                mergeTables(rcvrs, topRcvrs);

                if ((size = HASH_COUNT(*topRcvrs)) > MAX_TABLE_SIZE_1) {
                    HASH_SORT(*topRcvrs, receivers_sort_asc);
                    *topRcvrs = cutBackTo(topRcvrs, size, MAX_TABLE_SIZE_1);
                }

                *rcvrs = NULL;
            }
        }
    } else
        r->num_pkts += num_pkts;
}

void updatePortStats(struct port_stats **stats,
                     u_int32_t port,
                     u_int32_t addr,
                     u_int8_t version,
                     u_int32_t num_pkts,
                     u_int32_t num_bytes,
                     const char *proto)
{
    struct port_stats *s = NULL;
    int count = 0;

    HASH_FIND_INT(*stats, &port, s);
    if (s == NULL) {
        s = (struct port_stats *) calloc(1, sizeof(struct port_stats));
        if (!s)
            return;

        s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
        s->num_addr = 1, s->cumulative_addr = 1;
        s->num_flows = 1;

        updateTopIpAddress(addr, version, proto, 1, s->top_ip_addrs,
                           MAX_NUM_IP_ADDRESS);

        s->addr_tree = (addr_node *) malloc(sizeof(addr_node));
        if (!s->addr_tree) {
            free(s);
            return;
        }

        s->addr_tree->addr = addr;
        s->addr_tree->version = version;
        strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto));
        s->addr_tree->count = 1;
        s->addr_tree->left = NULL;
        s->addr_tree->right = NULL;

        HASH_ADD_INT(*stats, port, s);
    } else {
        count = updateIpTree(addr, version, &(*s).addr_tree, proto);

        if (count == UPDATED_TREE)
            s->num_addr++;

        if (count) {
            s->cumulative_addr++;
            updateTopIpAddress(addr, version, proto, count, s->top_ip_addrs,
                               MAX_NUM_IP_ADDRESS);
        }

        s->num_pkts += num_pkts, s->num_bytes += num_bytes, s->num_flows++;
    }
}

void deleteScanners(struct single_flow_info *scanners)
{
    struct single_flow_info *s, *tmp;
    struct port_flow_info *p, *tmp2;

    HASH_ITER(hh, scanners, s, tmp)
    {
        HASH_ITER(hh, s->ports, p, tmp2)
        {
            if (s->ports)
                HASH_DEL(s->ports, p);
            free(p);
        }
        HASH_DEL(scanners, s);
        free(s);
    }
}

void deletePortsStats(struct port_stats *stats)
{
    struct port_stats *current_port, *tmp;

    HASH_ITER(hh, stats, current_port, tmp)
    {
        HASH_DEL(stats, current_port);
        freeIpTree(current_port->addr_tree);
        free(current_port);
    }
}


void freeIpTree(addr_node *root)
{
    if (root == NULL)
        return;

    freeIpTree(root->left);
    freeIpTree(root->right);
    free(root);
}
int cmpProto(const void *_a, const void *_b)
{
    struct ndpi_proto_sorter *a = (struct ndpi_proto_sorter *) _a;
    struct ndpi_proto_sorter *b = (struct ndpi_proto_sorter *) _b;

    return (strcmp(a->name, b->name));
}

int cmpFlows(const void *_a, const void *_b)
{
    struct ndpi_flow_info *fa = ((struct flow_info *) _a)->flow;
    struct ndpi_flow_info *fb = ((struct flow_info *) _b)->flow;
    uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
    uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
    if (a_size != b_size)
        return a_size < b_size ? 1 : -1;

    // copy from ndpi_workflow_node_cmp();

    if (fa->ip_version < fb->ip_version)
        return (-1);
    else {
        if (fa->ip_version > fb->ip_version)
            return (1);
    }
    if (fa->protocol < fb->protocol)
        return (-1);
    else {
        if (fa->protocol > fb->protocol)
            return (1);
    }
    if (htonl(fa->src_ip) < htonl(fb->src_ip))
        return (-1);
    else {
        if (htonl(fa->src_ip) > htonl(fb->src_ip))
            return (1);
    }
    if (htons(fa->src_port) < htons(fb->src_port))
        return (-1);
    else {
        if (htons(fa->src_port) > htons(fb->src_port))
            return (1);
    }
    if (htonl(fa->dst_ip) < htonl(fb->dst_ip))
        return (-1);
    else {
        if (htonl(fa->dst_ip) > htonl(fb->dst_ip))
            return (1);
    }
    if (htons(fa->dst_port) < htons(fb->dst_port))
        return (-1);
    else {
        if (htons(fa->dst_port) > htons(fb->dst_port))
            return (1);
    }
    return (0);
}

static int info_pair_cmp(const void *_a, const void *_b)
{
    struct info_pair *a = (struct info_pair *) _a;
    struct info_pair *b = (struct info_pair *) _b;

    return b->count - a->count;
}

static char *is_unsafe_cipher(ndpi_cipher_weakness c)
{
    switch (c) {
    case ndpi_cipher_insecure:
        return ("INSECURE");
        break;

    case ndpi_cipher_weak:
        return ("WEAK");
        break;

    default:
        return ("OK");
    }
}

char *print_cipher(ndpi_cipher_weakness c)
{
    switch (c) {
    case ndpi_cipher_insecure:
        return (" (INSECURE)");
        break;

    case ndpi_cipher_weak:
        return (" (WEAK)");
        break;

    default:
        return ("");
    }
}

char *printUrlRisk(ndpi_url_risk risk)
{
    switch (risk) {
    case ndpi_url_no_problem:
        return ("");
        break;
    case ndpi_url_possible_xss:
        return (" ** XSS **");
        break;
    case ndpi_url_possible_sql_injection:
        return (" ** SQL Injection **");
        break;
    }

    return ("");
}

/*
 * Unknown Proto Walker
 */
static void node_print_unknown_proto_walker(const void *node,
                                            ndpi_VISIT which,
                                            int depth,
                                            void *user_data)
{
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);

    if ((flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN) ||
        (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN))
        return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */
        all_flows[num_flows].thread_id = thread_id,
        all_flows[num_flows].flow = flow;
        num_flows++;
    }
}


/*
 * Known Proto Walker
 */
static void node_print_known_proto_walker(const void *node,
                                          ndpi_VISIT which,
                                          int depth,
                                          void *user_data)
{
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);

    if ((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) &&
        (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN))
        return;

    if ((which == ndpi_preorder) || (which == ndpi_leaf)) {
        /* Avoid walking the same node multiple times */
        all_flows[num_flows].thread_id = thread_id,
        all_flows[num_flows].flow = flow;
        num_flows++;
    }
}

/*
 * Get flow byte distribution mean and variance
 */
static void flowGetBDMeanandVariance(struct ndpi_flow_info *flow)
{
    FILE *out = results_file ? results_file : stdout;
    const uint32_t *array = NULL;
    uint32_t tmp[256], i;
    unsigned int num_bytes;
    double mean = 0.0, variance = 0.0;
    struct ndpi_entropy last_entropy = flow->last_entropy;

    fflush(out);

    /*
     * Sum up the byte_count array for outbound and inbound flows,
     * if this flow is bidirectional
     */
    if (!flow->bidirectional) {
        array = last_entropy.src2dst_byte_count;
        num_bytes = last_entropy.src2dst_l4_bytes;
        for (i = 0; i < 256; i++) {
            tmp[i] = last_entropy.src2dst_byte_count[i];
        }

        if (last_entropy.src2dst_num_bytes != 0) {
            mean = last_entropy.src2dst_bd_mean;
            variance = last_entropy.src2dst_bd_variance /
                       (last_entropy.src2dst_num_bytes - 1);
            variance = sqrt(variance);

            if (last_entropy.src2dst_num_bytes == 1) {
                variance = 0.0;
            }
        }
    } else {
        for (i = 0; i < 256; i++) {
            tmp[i] = last_entropy.src2dst_byte_count[i] +
                     last_entropy.dst2src_byte_count[i];
        }
        array = tmp;
        num_bytes =
            last_entropy.src2dst_l4_bytes + last_entropy.dst2src_l4_bytes;

        if (last_entropy.src2dst_num_bytes + last_entropy.dst2src_num_bytes !=
            0) {
            mean = ((double) last_entropy.src2dst_num_bytes) /
                       ((double) (last_entropy.src2dst_num_bytes +
                                  last_entropy.dst2src_num_bytes)) *
                       last_entropy.src2dst_bd_mean +
                   ((double) last_entropy.dst2src_num_bytes) /
                       ((double) (last_entropy.dst2src_num_bytes +
                                  last_entropy.src2dst_num_bytes)) *
                       last_entropy.dst2src_bd_mean;

            variance = ((double) last_entropy.src2dst_num_bytes) /
                           ((double) (last_entropy.src2dst_num_bytes +
                                      last_entropy.dst2src_num_bytes)) *
                           last_entropy.src2dst_bd_variance +
                       ((double) last_entropy.dst2src_num_bytes) /
                           ((double) (last_entropy.dst2src_num_bytes +
                                      last_entropy.src2dst_num_bytes)) *
                           last_entropy.dst2src_bd_variance;

            variance =
                variance / ((double) (last_entropy.src2dst_num_bytes +
                                      last_entropy.dst2src_num_bytes - 1));
            variance = sqrt(variance);
            if (last_entropy.src2dst_num_bytes +
                    last_entropy.dst2src_num_bytes ==
                1) {
                variance = 0.0;
            }
        }
    }

    if (enable_joy_stats) {
        /* Output the mean */
        if (num_bytes != 0) {
            double entropy = ndpi_flow_get_byte_count_entropy(array, num_bytes);

            if (csv_fp) {
                fprintf(csv_fp, ",%.3f,%.3f,%.3f,%.3f", mean, variance, entropy,
                        entropy * num_bytes);
            } else {
                fprintf(out, "[byte_dist_mean: %f", mean);
                fprintf(out, "][byte_dist_std: %f]", variance);
                fprintf(out, "[entropy: %f]", entropy);
                fprintf(out, "[total_entropy: %f]", entropy * num_bytes);
            }
        } else {
            if (csv_fp)
                fprintf(csv_fp, ",%.3f,%.3f,%.3f,%.3f", 0.0, 0.0, 0.0, 0.0);
        }
    }
}



/*
 * Print the flow
 */
static void printFlow(u_int16_t id,
                      struct ndpi_flow_info *flow,
                      u_int16_t thread_id)
{
    FILE *out = results_file ? results_file : stdout;
    u_int8_t known_tls;
    char buf[32], buf1[64];
    u_int i;

    double dos_ge_score;
    double dos_slow_score;
    double dos_hulk_score;
    double ddos_score;

    double hearthbleed_score;

    double ftp_patator_score;
    double ssh_patator_score;

    double inf_score;

    if (csv_fp != NULL) {
        float data_ratio =
            ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
        double f = (double) flow->first_seen, l = (double) flow->last_seen;

        /* PLEASE KEEP IN SYNC WITH printCSVHeader() */
        dos_ge_score = Dos_goldeneye_score(flow);

        dos_slow_score = Dos_slow_score(flow);
        dos_hulk_score = Dos_hulk_score(flow);
        ddos_score = Ddos_score(flow);

        hearthbleed_score = Hearthbleed_score(flow);

        ftp_patator_score = Ftp_patator_score(flow);
        ssh_patator_score = Ssh_patator_score(flow);

        inf_score = Infiltration_score(flow);

        double benign_score = dos_ge_score < 1 && dos_slow_score < 1 &&
                                      dos_hulk_score < 1 && ddos_score < 1 &&
                                      hearthbleed_score < 1 &&
                                      ftp_patator_score < 1 &&
                                      ssh_patator_score < 1 && inf_score < 1
                                  ? 1.1
                                  : 0;

        fprintf(csv_fp, "%u,%u,%.3f,%.3f,%.3f,%s,%u,%s,%u,", flow->flow_id,
                flow->protocol, f / 1000.0, l / 1000.0, (l - f) / 1000.0,
                flow->src_name, ntohs(flow->src_port), flow->dst_name,
                ntohs(flow->dst_port));

        fprintf(
            csv_fp, "%s,",
            ndpi_protocol2id(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                             flow->detected_protocol, buf, sizeof(buf)));

        fprintf(csv_fp, "%s,%s,",
                ndpi_protocol2name(
                    ndpi_thread_info[thread_id].workflow->ndpi_struct,
                    flow->detected_protocol, buf, sizeof(buf)),
                flow->host_server_name);

        fprintf(csv_fp,
                "%.4lf,%.4lf,%.4lf,%.4lf,%.4lf,%.4lf,%.4lf,%.4lf,%.4lf,",
                benign_score, dos_slow_score, dos_ge_score, dos_hulk_score,
                ddos_score, hearthbleed_score, ftp_patator_score,
                ssh_patator_score, inf_score);

        fprintf(csv_fp, "%u,%llu,%llu,", flow->src2dst_packets,
                (long long unsigned int) flow->src2dst_bytes,
                (long long unsigned int) flow->src2dst_goodput_bytes);
        fprintf(csv_fp, "%u,%llu,%llu,", flow->dst2src_packets,
                (long long unsigned int) flow->dst2src_bytes,
                (long long unsigned int) flow->dst2src_goodput_bytes);
        fprintf(csv_fp, "%.3f,%s,", data_ratio,
                ndpi_data_ratio2str(data_ratio));
        fprintf(csv_fp, "%.1f,%.1f,",
                100.0 * ((float) flow->src2dst_goodput_bytes /
                         (float) (flow->src2dst_bytes + 1)),
                100.0 * ((float) flow->dst2src_goodput_bytes /
                         (float) (flow->dst2src_bytes + 1)));

        /* IAT (Inter Arrival Time) */
        fprintf(csv_fp, "%u,%.1f,%u,%.1f,", ndpi_data_min(flow->iat_flow),
                ndpi_data_average(flow->iat_flow),
                ndpi_data_max(flow->iat_flow),
                ndpi_data_stddev(flow->iat_flow));

        fprintf(csv_fp, "%u,%.1f,%u,%.1f,%u,%.1f,%u,%.1f,",
                ndpi_data_min(flow->iat_c_to_s),
                ndpi_data_average(flow->iat_c_to_s),
                ndpi_data_max(flow->iat_c_to_s),
                ndpi_data_stddev(flow->iat_c_to_s),
                ndpi_data_min(flow->iat_s_to_c),
                ndpi_data_average(flow->iat_s_to_c),
                ndpi_data_max(flow->iat_s_to_c),
                ndpi_data_stddev(flow->iat_s_to_c));

        /* Packet Length */
        fprintf(csv_fp, "%u,%.1f,%u,%.1f,%u,%.1f,%u,%.1f,",
                ndpi_data_min(flow->pktlen_c_to_s),
                ndpi_data_average(flow->pktlen_c_to_s),
                ndpi_data_max(flow->pktlen_c_to_s),
                ndpi_data_stddev(flow->pktlen_c_to_s),
                ndpi_data_min(flow->pktlen_s_to_c),
                ndpi_data_average(flow->pktlen_s_to_c),
                ndpi_data_max(flow->pktlen_s_to_c),
                ndpi_data_stddev(flow->pktlen_s_to_c));

        /* TCP flags */
        fprintf(csv_fp, "%d,%d,%d,%d,%d,%d,%d,%d,", flow->cwr_count,
                flow->ece_count, flow->urg_count, flow->ack_count,
                flow->psh_count, flow->rst_count, flow->syn_count,
                flow->fin_count);

        fprintf(csv_fp, "%d,%d,%d,%d,%d,%d,%d,%d,", flow->src2dst_cwr_count,
                flow->src2dst_ece_count, flow->src2dst_urg_count,
                flow->src2dst_ack_count, flow->src2dst_psh_count,
                flow->src2dst_rst_count, flow->src2dst_syn_count,
                flow->src2dst_fin_count);

        fprintf(csv_fp, "%d,%d,%d,%d,%d,%d,%d,%d,", flow->dst2src_cwr_count,
                flow->ece_count, flow->urg_count, flow->ack_count,
                flow->psh_count, flow->rst_count, flow->syn_count,
                flow->fin_count);

        /* TCP window */
        fprintf(csv_fp, "%u,%u,", flow->c_to_s_init_win, flow->s_to_c_init_win);

        fprintf(csv_fp, "%s,%s,",
                (flow->ssh_tls.client_requested_server_name[0] != '\0')
                    ? flow->ssh_tls.client_requested_server_name
                    : "",
                (flow->ssh_tls.server_info[0] != '\0')
                    ? flow->ssh_tls.server_info
                    : "");

        fprintf(
            csv_fp, "%s,%s,%s,",
            (flow->ssh_tls.ssl_version != 0)
                ? ndpi_ssl_version2str(flow->ssh_tls.ssl_version, &known_tls)
                : "0",
            (flow->ssh_tls.ja3_client[0] != '\0') ? flow->ssh_tls.ja3_client
                                                  : "",
            (flow->ssh_tls.ja3_client[0] != '\0')
                ? is_unsafe_cipher(flow->ssh_tls.client_unsafe_cipher)
                : "0");

        fprintf(csv_fp, "%s,%s,",
                (flow->ssh_tls.ja3_server[0] != '\0') ? flow->ssh_tls.ja3_server
                                                      : "",
                (flow->ssh_tls.ja3_server[0] != '\0')
                    ? is_unsafe_cipher(flow->ssh_tls.server_unsafe_cipher)
                    : "0");

        fprintf(
            csv_fp, "%s,%s",
            (flow->ssh_tls.client_hassh[0] != '\0') ? flow->ssh_tls.client_hassh
                                                    : "",
            (flow->ssh_tls.server_hassh[0] != '\0') ? flow->ssh_tls.server_hassh
                                                    : "");

        fprintf(csv_fp, ",%s", flow->info);
    }

    if ((verbose != 1) && (verbose != 2)) {
        if (csv_fp && enable_joy_stats) {
            flowGetBDMeanandVariance(flow);
        }

        fprintf(csv_fp, "\n");
        return;
    }

    if (csv_fp || (verbose > 1)) {
#if 1
        fprintf(out, "\t%u", id);
#else
        fprintf(out, "\t%u(%u)", id, flow->flow_id);
#endif

        fprintf(out, "\t%s ", ipProto2Name(flow->protocol));

        fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
                (flow->ip_version == 6) ? "[" : "", flow->src_name,
                (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
                flow->bidirectional ? "<->" : "->",
                (flow->ip_version == 6) ? "[" : "", flow->dst_name,
                (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port));

        if (flow->vlan_id > 0)
            fprintf(out, "[VLAN: %u]", flow->vlan_id);
        if (enable_payload_analyzer)
            fprintf(out, "[flowId: %u]", flow->flow_id);
    }

    if (enable_joy_stats) {
        /* Print entropy values for monitored flows. */
        flowGetBDMeanandVariance(flow);
        fprintf(csv_fp, "\n");
        fflush(out);
        fprintf(out, "[score: %.4f]", flow->entropy.score);
    }

    fprintf(out, "[proto: ");
    if (flow->tunnel_type != ndpi_no_tunnel)
        fprintf(out, "%s:", ndpi_tunnel2str(flow->tunnel_type));

    fprintf(
        out, "%s/%s]",
        ndpi_protocol2id(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                         flow->detected_protocol, buf, sizeof(buf)),
        ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                           flow->detected_protocol, buf1, sizeof(buf1)));

    if (flow->detected_protocol.category != 0)
        fprintf(out, "[cat: %s/%u]",
                ndpi_category_get_name(
                    ndpi_thread_info[thread_id].workflow->ndpi_struct,
                    flow->detected_protocol.category),
                (unsigned int) flow->detected_protocol.category);

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets,
            (long long unsigned int) flow->src2dst_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
            (flow->dst2src_packets > 0) ? "<->" : "->", flow->dst2src_packets,
            (long long unsigned int) flow->dst2src_bytes);

    fprintf(out, "[Goodput ratio: %.1f/%.1f]",
            100.0 * ((float) flow->src2dst_goodput_bytes /
                     (float) (flow->src2dst_bytes + 1)),
            100.0 * ((float) flow->dst2src_goodput_bytes /
                     (float) (flow->dst2src_bytes + 1)));

    if (flow->last_seen > flow->first_seen)
        fprintf(out, "[%.2f sec]",
                ((float) (flow->last_seen - flow->first_seen)) / (float) 1000);
    else
        fprintf(out, "[< 1 sec]");

    if (flow->telnet.username[0] != '\0')
        fprintf(out, "[Username: %s]", flow->telnet.username);
    if (flow->telnet.password[0] != '\0')
        fprintf(out, "[Password: %s]", flow->telnet.password);
    if (flow->host_server_name[0] != '\0')
        fprintf(out, "[Host: %s]", flow->host_server_name);

    if (flow->info[0] != '\0')
        fprintf(out, "[%s]", flow->info);

    if ((flow->src2dst_packets + flow->dst2src_packets) > 5) {
        if (flow->iat_c_to_s && flow->iat_s_to_c) {
            float data_ratio =
                ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

            fprintf(out, "[bytes ratio: %.3f (%s)]", data_ratio,
                    ndpi_data_ratio2str(data_ratio));

            /* IAT (Inter Arrival Time) */
            fprintf(out,
                    "[IAT c2s/s2c min/avg/max/stddev: %u/%u %.1f/%.1f %u/%u "
                    "%.1f/%.1f]",
                    ndpi_data_min(flow->iat_c_to_s),
                    ndpi_data_min(flow->iat_s_to_c),
                    (float) ndpi_data_average(flow->iat_c_to_s),
                    (float) ndpi_data_average(flow->iat_s_to_c),
                    ndpi_data_max(flow->iat_c_to_s),
                    ndpi_data_max(flow->iat_s_to_c),
                    (float) ndpi_data_stddev(flow->iat_c_to_s),
                    (float) ndpi_data_stddev(flow->iat_s_to_c));

            /* Packet Length */
            fprintf(out,
                    "[Pkt Len c2s/s2c min/avg/max/stddev: %u/%u %.1f/%.1f "
                    "%u/%u %.1f/%.1f]",
                    ndpi_data_min(flow->pktlen_c_to_s),
                    ndpi_data_min(flow->pktlen_s_to_c),
                    ndpi_data_average(flow->pktlen_c_to_s),
                    ndpi_data_average(flow->pktlen_s_to_c),
                    ndpi_data_max(flow->pktlen_c_to_s),
                    ndpi_data_max(flow->pktlen_s_to_c),
                    ndpi_data_stddev(flow->pktlen_c_to_s),
                    ndpi_data_stddev(flow->pktlen_s_to_c));
        }
    }

    if (flow->http.url[0] != '\0')
        fprintf(out,
                "[URL: %s%s][StatusCode: %u][ContentType: %s][UserAgent: %s]",
                flow->http.url, printUrlRisk(ndpi_validate_url(flow->http.url)),
                flow->http.response_status_code, flow->http.content_type,
                flow->http.user_agent);

    if (flow->ssh_tls.ssl_version != 0)
        fprintf(out, "[%s]",
                ndpi_ssl_version2str(flow->ssh_tls.ssl_version, &known_tls));
    if (flow->ssh_tls.client_requested_server_name[0] != '\0')
        fprintf(out, "[Client: %s]",
                flow->ssh_tls.client_requested_server_name);
    if (flow->ssh_tls.client_hassh[0] != '\0')
        fprintf(out, "[HASSH-C: %s]", flow->ssh_tls.client_hassh);

    if (flow->ssh_tls.ja3_client[0] != '\0')
        fprintf(out, "[JA3C: %s%s]", flow->ssh_tls.ja3_client,
                print_cipher(flow->ssh_tls.client_unsafe_cipher));

    if (flow->ssh_tls.server_info[0] != '\0')
        fprintf(out, "[Server: %s]", flow->ssh_tls.server_info);

    if (flow->ssh_tls.server_names)
        fprintf(out, "[ServerNames: %s]", flow->ssh_tls.server_names);
    if (flow->ssh_tls.server_hassh[0] != '\0')
        fprintf(out, "[HASSH-S: %s]", flow->ssh_tls.server_hassh);

    if (flow->ssh_tls.ja3_server[0] != '\0')
        fprintf(out, "[JA3S: %s%s]", flow->ssh_tls.ja3_server,
                print_cipher(flow->ssh_tls.server_unsafe_cipher));
    if (flow->ssh_tls.server_organization[0] != '\0')
        fprintf(out, "[Organization: %s]", flow->ssh_tls.server_organization);

    if ((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS) ||
        (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_TLS)) {
        if (flow->ssh_tls.sha1_cert_fingerprint_set) {
            fprintf(out, "[Certificate SHA-1: ");
            for (i = 0; i < 20; i++)
                fprintf(out, "%s%02X", (i > 0) ? ":" : "",
                        flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF);
            fprintf(out, "]");
        }
    }

    if (flow->ssh_tls.notBefore && flow->ssh_tls.notAfter) {
        char notBefore[32], notAfter[32];
        struct tm a, b;
        struct tm *before = gmtime_r(&flow->ssh_tls.notBefore, &a);
        struct tm *after = gmtime_r(&flow->ssh_tls.notAfter, &b);

        strftime(notBefore, sizeof(notBefore), "%F %T", before);
        strftime(notAfter, sizeof(notAfter), "%F %T", after);

        fprintf(out, "[Validity: %s - %s]", notBefore, notAfter);
    }

    if (flow->ssh_tls.server_cipher != '\0')
        fprintf(out, "[Cipher: %s]",
                ndpi_cipher2str(flow->ssh_tls.server_cipher));
    if (flow->bittorent_hash[0] != '\0')
        fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);
    if (flow->dhcp_fingerprint[0] != '\0')
        fprintf(out, "[DHCP Fingerprint: %s]", flow->dhcp_fingerprint);

    if (flow->has_human_readeable_strings)
        fprintf(out, "[PLAIN TEXT (%s)]", flow->human_readeable_string_buffer);

    fprintf(out, "\n");
}
/*
 * Print results
 */
void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec)
{
    u_int32_t i;
    u_int64_t total_flow_bytes = 0;
    u_int32_t avg_pkt_size = 0;
    struct ndpi_stats cumulative_stats;
    int thread_id;
    char buf[32];
    long long unsigned int breed_stats[NUM_BREEDS] = {0};

    memset(&cumulative_stats, 0, sizeof(cumulative_stats));

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
        if ((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes ==
             0) &&
            (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
            continue;

        for (i = 0; i < NUM_ROOTS; i++) {
            ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                       node_proto_guess_walker, &thread_id);
            if (verbose == 3)
                ndpi_twalk(
                    ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                    port_stats_walker, &thread_id);
        }

        /* Stats aggregation */
        cumulative_stats.guessed_flow_protocols +=
            ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
        cumulative_stats.raw_packet_count +=
            ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
        cumulative_stats.ip_packet_count +=
            ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
        cumulative_stats.total_wire_bytes +=
            ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
        cumulative_stats.total_ip_bytes +=
            ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
        cumulative_stats.total_discarded_bytes +=
            ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;

        for (i = 0; i < ndpi_get_num_supported_protocols(
                            ndpi_thread_info[0].workflow->ndpi_struct);
             i++) {
            cumulative_stats.protocol_counter[i] +=
                ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
            cumulative_stats.protocol_counter_bytes[i] +=
                ndpi_thread_info[thread_id]
                    .workflow->stats.protocol_counter_bytes[i];
            cumulative_stats.protocol_flows[i] +=
                ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];
        }

        cumulative_stats.ndpi_flow_count +=
            ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
        cumulative_stats.tcp_count +=
            ndpi_thread_info[thread_id].workflow->stats.tcp_count;
        cumulative_stats.udp_count +=
            ndpi_thread_info[thread_id].workflow->stats.udp_count;
        cumulative_stats.mpls_count +=
            ndpi_thread_info[thread_id].workflow->stats.mpls_count;
        cumulative_stats.pppoe_count +=
            ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
        cumulative_stats.vlan_count +=
            ndpi_thread_info[thread_id].workflow->stats.vlan_count;
        cumulative_stats.fragmented_count +=
            ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
        for (i = 0; i < sizeof(cumulative_stats.packet_len) /
                            sizeof(cumulative_stats.packet_len[0]);
             i++)
            cumulative_stats.packet_len[i] +=
                ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
        cumulative_stats.max_packet_len +=
            ndpi_thread_info[thread_id].workflow->stats.max_packet_len;
    }

    if (cumulative_stats.total_wire_bytes == 0)
        goto free_stats;

    if (!quiet_mode) {
        printf("\nnDPI Memory statistics:\n");
        printf("\tnDPI Memory (once):      %-13s\n",
               formatBytes(ndpi_get_ndpi_detection_module_size(), buf,
                           sizeof(buf)));
        printf("\tFlow Memory (per flow):  %-13s\n",
               formatBytes(sizeof(struct ndpi_flow_struct), buf, sizeof(buf)));
        printf("\tActual Memory:           %-13s\n",
               formatBytes(current_ndpi_memory, buf, sizeof(buf)));
        printf("\tPeak Memory:             %-13s\n",
               formatBytes(max_ndpi_memory, buf, sizeof(buf)));
        printf("\tSetup Time:              %lu msec\n",
               (unsigned long) (setup_time_usec / 1000));
        printf("\tPacket Processing Time:  %lu msec\n",
               (unsigned long) (processing_time_usec / 1000));

        printf("\nTraffic statistics:\n");
        printf(
            "\tEthernet bytes:        %-13llu (includes ethernet "
            "CRC/IFC/trailer)\n",
            (long long unsigned int) cumulative_stats.total_wire_bytes);
        printf("\tDiscarded bytes:       %-13llu\n",
               (long long unsigned int) cumulative_stats.total_discarded_bytes);
        printf("\tIP packets:            %-13llu of %llu packets total\n",
               (long long unsigned int) cumulative_stats.ip_packet_count,
               (long long unsigned int) cumulative_stats.raw_packet_count);
        /* In order to prevent Floating point exception in case of no traffic*/
        if (cumulative_stats.total_ip_bytes &&
            cumulative_stats.raw_packet_count)
            avg_pkt_size = (unsigned int) (cumulative_stats.total_ip_bytes /
                                           cumulative_stats.raw_packet_count);
        printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
               (long long unsigned int) cumulative_stats.total_ip_bytes,
               avg_pkt_size);
        printf("\tUnique flows:          %-13u\n",
               cumulative_stats.ndpi_flow_count);

        printf("\tTCP Packets:           %-13lu\n",
               (unsigned long) cumulative_stats.tcp_count);
        printf("\tUDP Packets:           %-13lu\n",
               (unsigned long) cumulative_stats.udp_count);
        printf("\tVLAN Packets:          %-13lu\n",
               (unsigned long) cumulative_stats.vlan_count);
        printf("\tMPLS Packets:          %-13lu\n",
               (unsigned long) cumulative_stats.mpls_count);
        printf("\tPPPoE Packets:         %-13lu\n",
               (unsigned long) cumulative_stats.pppoe_count);
        printf("\tFragmented Packets:    %-13lu\n",
               (unsigned long) cumulative_stats.fragmented_count);
        printf("\tMax Packet size:       %-13u\n",
               cumulative_stats.max_packet_len);
        printf("\tPacket Len < 64:       %-13lu\n",
               (unsigned long) cumulative_stats.packet_len[0]);
        printf("\tPacket Len 64-128:     %-13lu\n",
               (unsigned long) cumulative_stats.packet_len[1]);
        printf("\tPacket Len 128-256:    %-13lu\n",
               (unsigned long) cumulative_stats.packet_len[2]);
        printf("\tPacket Len 256-1024:   %-13lu\n",
               (unsigned long) cumulative_stats.packet_len[3]);
        printf("\tPacket Len 1024-1500:  %-13lu\n",
               (unsigned long) cumulative_stats.packet_len[4]);
        printf("\tPacket Len > 1500:     %-13lu\n",
               (unsigned long) cumulative_stats.packet_len[5]);

        if (processing_time_usec > 0) {
            char buf[32], buf1[32], when[64];
            float t = (float) (cumulative_stats.ip_packet_count * 1000000) /
                      (float) processing_time_usec;
            float b =
                (float) (cumulative_stats.total_wire_bytes * 8 * 1000000) /
                (float) processing_time_usec;
            float traffic_duration;

            if (live_capture)
                traffic_duration = processing_time_usec;
            else
                traffic_duration =
                    (pcap_end.tv_sec * 1000000 + pcap_end.tv_usec) -
                    (pcap_start.tv_sec * 1000000 + pcap_start.tv_usec);

            printf("\tnDPI throughput:       %s pps / %s/sec\n",
                   formatPackets(t, buf), formatTraffic(b, 1, buf1));
            t = (float) (cumulative_stats.ip_packet_count * 1000000) /
                (float) traffic_duration;
            b = (float) (cumulative_stats.total_wire_bytes * 8 * 1000000) /
                (float) traffic_duration;

            strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S",
                     localtime(&pcap_start.tv_sec));
            printf("\tAnalysis begin:        %s\n", when);
            strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S",
                     localtime(&pcap_end.tv_sec));
            printf("\tAnalysis end:          %s\n", when);
            printf("\tTraffic throughput:    %s pps / %s/sec\n",
                   formatPackets(t, buf), formatTraffic(b, 1, buf1));
            printf("\tTraffic duration:      %.3f sec\n",
                   traffic_duration / 1000000);
        }

        if (enable_protocol_guess)
            printf("\tGuessed flow protos:   %-13u\n",
                   cumulative_stats.guessed_flow_protocols);
    }

    if (!quiet_mode)
        printf("\n\nDetected protocols:\n");
    for (i = 0; i <= ndpi_get_num_supported_protocols(
                         ndpi_thread_info[0].workflow->ndpi_struct);
         i++) {
        ndpi_protocol_breed_t breed =
            ndpi_get_proto_breed(ndpi_thread_info[0].workflow->ndpi_struct, i);

        if (cumulative_stats.protocol_counter[i] > 0) {
            breed_stats[breed] +=
                (long long unsigned int)
                    cumulative_stats.protocol_counter_bytes[i];

            if (results_file)
                fprintf(results_file, "%s\t%llu\t%llu\t%u\n",
                        ndpi_get_proto_name(
                            ndpi_thread_info[0].workflow->ndpi_struct, i),
                        (long long unsigned int)
                            cumulative_stats.protocol_counter[i],
                        (long long unsigned int)
                            cumulative_stats.protocol_counter_bytes[i],
                        cumulative_stats.protocol_flows[i]);

            if ((!quiet_mode)) {
                printf(
                    "\t%-20s packets: %-13llu bytes: %-13llu "
                    "flows: %-13u\n",
                    ndpi_get_proto_name(
                        ndpi_thread_info[0].workflow->ndpi_struct, i),
                    (long long unsigned int)
                        cumulative_stats.protocol_counter[i],
                    (long long unsigned int)
                        cumulative_stats.protocol_counter_bytes[i],
                    cumulative_stats.protocol_flows[i]);
            }

            total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
        }
    }

    if ((!quiet_mode)) {
        printf("\n\nProtocol statistics:\n");

        for (i = 0; i < NUM_BREEDS; i++) {
            if (breed_stats[i] > 0) {
                printf("\t%-20s %13llu bytes\n",
                       ndpi_get_proto_breed_name(
                           ndpi_thread_info[0].workflow->ndpi_struct, i),
                       breed_stats[i]);
            }
        }
    }

    // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes,
    // cumulative_stats.total_ip_bytes-total_flow_bytes);

    printFlowsStats();

    if (verbose == 3) {
        HASH_SORT(srcStats, port_stats_sort);
        HASH_SORT(dstStats, port_stats_sort);

        printf("\n\nSource Ports Stats:\n");
        printPortStats(srcStats);

        printf("\nDestination Ports Stats:\n");
        printPortStats(dstStats);
    }

    /* Print my info */
    printf("\n\nTime info:\n Capture statge, Analyze statge\n %ld.%ld %ld.%ld\n",
           dpiresults->capture_time.tv_sec, dpiresults->capture_time.tv_usec,
           dpiresults->analyze_time.tv_sec, dpiresults->analyze_time.tv_usec);

free_stats:
    if (scannerHosts) {
        deleteScanners(scannerHosts);
        scannerHosts = NULL;
    }

    if (receivers) {
        deleteReceivers(receivers);
        receivers = NULL;
    }

    if (topReceivers) {
        deleteReceivers(topReceivers);
        topReceivers = NULL;
    }

    if (srcStats) {
        deletePortsStats(srcStats);
        srcStats = NULL;
    }

    if (dstStats) {
        deletePortsStats(dstStats);
        dstStats = NULL;
    }
}

void printFlowsStats()
{
    int thread_id;
    u_int32_t total_flows = 0;
    FILE *out = results_file ? results_file : stdout;

    if (enable_payload_analyzer)
        ndpi_report_payload_stats();

    for (thread_id = 0; thread_id < num_threads; thread_id++)
        total_flows +=
            ndpi_thread_info[thread_id].workflow->num_allocated_flows;

    if ((all_flows = (struct flow_info *) malloc(sizeof(struct flow_info) *
                                                 total_flows)) == NULL) {
        fprintf(out, "Fatal error: not enough memory\n");
        exit(-1);
    }

    if (verbose) {
        ndpi_host_ja3_fingerprints *ja3ByHostsHashT = NULL;  // outer hash table
        ndpi_ja3_fingerprints_host *hostByJA3C_ht = NULL;    // for client
        ndpi_ja3_fingerprints_host *hostByJA3S_ht = NULL;    // for server
        int i;
        ndpi_host_ja3_fingerprints *ja3ByHost_element = NULL;
        ndpi_ja3_info *info_of_element = NULL;
        ndpi_host_ja3_fingerprints *tmp = NULL;
        ndpi_ja3_info *tmp2 = NULL;
        unsigned int num_ja3_client;
        unsigned int num_ja3_server;

        fprintf(out, "\n");

        num_flows = 0;
        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            for (i = 0; i < NUM_ROOTS; i++)
                ndpi_twalk(
                    ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                    node_print_known_proto_walker, &thread_id);
        }

        if ((verbose == 2) || (verbose == 3)) {
            for (i = 0; i < num_flows; i++) {
                ndpi_host_ja3_fingerprints *ja3ByHostFound = NULL;
                ndpi_ja3_fingerprints_host *hostByJA3Found = NULL;

                // check if this is a ssh-ssl flow
                if (all_flows[i].flow->ssh_tls.ja3_client[0] != '\0') {
                    // looking if the host is already in the hash table
                    HASH_FIND_INT(ja3ByHostsHashT, &(all_flows[i].flow->src_ip),
                                  ja3ByHostFound);

                    // host ip -> ja3
                    if (ja3ByHostFound == NULL) {
                        // adding the new host
                        ndpi_host_ja3_fingerprints *newHost =
                            malloc(sizeof(ndpi_host_ja3_fingerprints));
                        newHost->host_client_info_hasht = NULL;
                        newHost->host_server_info_hasht = NULL;
                        newHost->ip_string = all_flows[i].flow->src_name;
                        newHost->ip = all_flows[i].flow->src_ip;
                        newHost->dns_name =
                            all_flows[i]
                                .flow->ssh_tls.client_requested_server_name;

                        ndpi_ja3_info *newJA3 = malloc(sizeof(ndpi_ja3_info));
                        newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
                        newJA3->unsafe_cipher =
                            all_flows[i].flow->ssh_tls.client_unsafe_cipher;
                        // adding the new ja3 fingerprint
                        HASH_ADD_KEYPTR(hh, newHost->host_client_info_hasht,
                                        newJA3->ja3, strlen(newJA3->ja3),
                                        newJA3);
                        // adding the new host
                        HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
                    } else {
                        // host already in the hash table
                        ndpi_ja3_info *infoFound = NULL;

                        HASH_FIND_STR(ja3ByHostFound->host_client_info_hasht,
                                      all_flows[i].flow->ssh_tls.ja3_client,
                                      infoFound);

                        if (infoFound == NULL) {
                            ndpi_ja3_info *newJA3 =
                                malloc(sizeof(ndpi_ja3_info));
                            newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
                            newJA3->unsafe_cipher =
                                all_flows[i].flow->ssh_tls.client_unsafe_cipher;
                            HASH_ADD_KEYPTR(
                                hh, ja3ByHostFound->host_client_info_hasht,
                                newJA3->ja3, strlen(newJA3->ja3), newJA3);
                        }
                    }

                    // ja3 -> host ip
                    HASH_FIND_STR(hostByJA3C_ht,
                                  all_flows[i].flow->ssh_tls.ja3_client,
                                  hostByJA3Found);
                    if (hostByJA3Found == NULL) {
                        ndpi_ip_dns *newHost = malloc(sizeof(ndpi_ip_dns));

                        newHost->ip = all_flows[i].flow->src_ip;
                        newHost->ip_string = all_flows[i].flow->src_name;
                        newHost->dns_name =
                            all_flows[i]
                                .flow->ssh_tls.client_requested_server_name;
                        ;

                        ndpi_ja3_fingerprints_host *newElement =
                            malloc(sizeof(ndpi_ja3_fingerprints_host));
                        newElement->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
                        newElement->unsafe_cipher =
                            all_flows[i].flow->ssh_tls.client_unsafe_cipher;
                        newElement->ipToDNS_ht = NULL;

                        HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
                        HASH_ADD_KEYPTR(hh, hostByJA3C_ht, newElement->ja3,
                                        strlen(newElement->ja3), newElement);
                    } else {
                        ndpi_ip_dns *innerElement = NULL;
                        HASH_FIND_INT(hostByJA3Found->ipToDNS_ht,
                                      &(all_flows[i].flow->src_ip),
                                      innerElement);
                        if (innerElement == NULL) {
                            ndpi_ip_dns *newInnerElement =
                                malloc(sizeof(ndpi_ip_dns));
                            newInnerElement->ip = all_flows[i].flow->src_ip;
                            newInnerElement->ip_string =
                                all_flows[i].flow->src_name;
                            newInnerElement->dns_name =
                                all_flows[i]
                                    .flow->ssh_tls.client_requested_server_name;
                            HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip,
                                         newInnerElement);
                        }
                    }
                }

                if (all_flows[i].flow->ssh_tls.ja3_server[0] != '\0') {
                    // looking if the host is already in the hash table
                    HASH_FIND_INT(ja3ByHostsHashT, &(all_flows[i].flow->dst_ip),
                                  ja3ByHostFound);
                    if (ja3ByHostFound == NULL) {
                        // adding the new host in the hash table
                        ndpi_host_ja3_fingerprints *newHost =
                            malloc(sizeof(ndpi_host_ja3_fingerprints));
                        newHost->host_client_info_hasht = NULL;
                        newHost->host_server_info_hasht = NULL;
                        newHost->ip_string = all_flows[i].flow->dst_name;
                        newHost->ip = all_flows[i].flow->dst_ip;
                        newHost->dns_name =
                            all_flows[i].flow->ssh_tls.server_info;

                        ndpi_ja3_info *newJA3 = malloc(sizeof(ndpi_ja3_info));
                        newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
                        newJA3->unsafe_cipher =
                            all_flows[i].flow->ssh_tls.server_unsafe_cipher;
                        // adding the new ja3 fingerprint
                        HASH_ADD_KEYPTR(hh, newHost->host_server_info_hasht,
                                        newJA3->ja3, strlen(newJA3->ja3),
                                        newJA3);
                        // adding the new host
                        HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
                    } else {
                        // host already in the hashtable
                        ndpi_ja3_info *infoFound = NULL;
                        HASH_FIND_STR(ja3ByHostFound->host_server_info_hasht,
                                      all_flows[i].flow->ssh_tls.ja3_server,
                                      infoFound);
                        if (infoFound == NULL) {
                            ndpi_ja3_info *newJA3 =
                                malloc(sizeof(ndpi_ja3_info));
                            newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
                            newJA3->unsafe_cipher =
                                all_flows[i].flow->ssh_tls.server_unsafe_cipher;
                            HASH_ADD_KEYPTR(
                                hh, ja3ByHostFound->host_server_info_hasht,
                                newJA3->ja3, strlen(newJA3->ja3), newJA3);
                        }
                    }

                    HASH_FIND_STR(hostByJA3S_ht,
                                  all_flows[i].flow->ssh_tls.ja3_server,
                                  hostByJA3Found);
                    if (hostByJA3Found == NULL) {
                        ndpi_ip_dns *newHost = malloc(sizeof(ndpi_ip_dns));

                        newHost->ip = all_flows[i].flow->dst_ip;
                        newHost->ip_string = all_flows[i].flow->dst_name;
                        newHost->dns_name =
                            all_flows[i].flow->ssh_tls.server_info;
                        ;

                        ndpi_ja3_fingerprints_host *newElement =
                            malloc(sizeof(ndpi_ja3_fingerprints_host));
                        newElement->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
                        newElement->unsafe_cipher =
                            all_flows[i].flow->ssh_tls.server_unsafe_cipher;
                        newElement->ipToDNS_ht = NULL;

                        HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
                        HASH_ADD_KEYPTR(hh, hostByJA3S_ht, newElement->ja3,
                                        strlen(newElement->ja3), newElement);
                    } else {
                        ndpi_ip_dns *innerElement = NULL;

                        HASH_FIND_INT(hostByJA3Found->ipToDNS_ht,
                                      &(all_flows[i].flow->dst_ip),
                                      innerElement);
                        if (innerElement == NULL) {
                            ndpi_ip_dns *newInnerElement =
                                malloc(sizeof(ndpi_ip_dns));
                            newInnerElement->ip = all_flows[i].flow->dst_ip;
                            newInnerElement->ip_string =
                                all_flows[i].flow->dst_name;
                            newInnerElement->dns_name =
                                all_flows[i].flow->ssh_tls.server_info;
                            HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip,
                                         newInnerElement);
                        }
                    }
                }
            }

            if (ja3ByHostsHashT) {
                ndpi_ja3_fingerprints_host *hostByJA3Element = NULL;
                ndpi_ja3_fingerprints_host *tmp3 = NULL;
                ndpi_ip_dns *innerHashEl = NULL;
                ndpi_ip_dns *tmp4 = NULL;

                if (verbose == 2) {
                    /* for each host the number of flow with a ja3 fingerprint
                     * is printed */
                    i = 1;

                    fprintf(out, "JA3 Host Stats: \n");
                    fprintf(out, "\t\t IP %-24s \t %-10s \n", "Address",
                            "# JA3C");

                    for (ja3ByHost_element = ja3ByHostsHashT;
                         ja3ByHost_element != NULL;
                         ja3ByHost_element = ja3ByHost_element->hh.next) {
                        num_ja3_client = HASH_COUNT(
                            ja3ByHost_element->host_client_info_hasht);
                        num_ja3_server = HASH_COUNT(
                            ja3ByHost_element->host_server_info_hasht);

                        if (num_ja3_client > 0) {
                            fprintf(out, "\t%d\t %-24s \t %-7u\n", i,
                                    ja3ByHost_element->ip_string,
                                    num_ja3_client);
                            i++;
                        }
                    }
                } else if (verbose == 3) {
                    int i = 1;
                    int againstRepeat;
                    ndpi_ja3_fingerprints_host *hostByJA3Element = NULL;
                    ndpi_ja3_fingerprints_host *tmp3 = NULL;
                    ndpi_ip_dns *innerHashEl = NULL;
                    ndpi_ip_dns *tmp4 = NULL;

                    // for each host it is printted the JA3C and JA3S, along the
                    // server name (if any) and the security status

                    fprintf(out, "JA3C/JA3S Host Stats: \n");
                    fprintf(out, "\t%-7s %-24s %-34s %s\n", "", "IP", "JA3C",
                            "JA3S");

                    // reminder
                    // ja3ByHostsHashT: hash table <ip, (ja3, ht_client,
                    // ht_server)> ja3ByHost_element: element of ja3ByHostsHashT
                    // info_of_element: element of the inner hash table of
                    // ja3ByHost_element
                    HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp)
                    {
                        num_ja3_client = HASH_COUNT(
                            ja3ByHost_element->host_client_info_hasht);
                        num_ja3_server = HASH_COUNT(
                            ja3ByHost_element->host_server_info_hasht);
                        againstRepeat = 0;
                        if (num_ja3_client > 0) {
                            HASH_ITER(hh,
                                      ja3ByHost_element->host_client_info_hasht,
                                      info_of_element, tmp2)
                            {
                                fprintf(out, "\t%-7d %-24s %s %s\n", i,
                                        ja3ByHost_element->ip_string,
                                        info_of_element->ja3,
                                        print_cipher(
                                            info_of_element->unsafe_cipher));
                                againstRepeat = 1;
                                i++;
                            }
                        }

                        if (num_ja3_server > 0) {
                            HASH_ITER(hh,
                                      ja3ByHost_element->host_server_info_hasht,
                                      info_of_element, tmp2)
                            {
                                fprintf(
                                    out, "\t%-7d %-24s %-34s %s %s %s%s%s\n", i,
                                    ja3ByHost_element->ip_string, "",
                                    info_of_element->ja3,
                                    print_cipher(
                                        info_of_element->unsafe_cipher),
                                    ja3ByHost_element->dns_name[0] ? "[" : "",
                                    ja3ByHost_element->dns_name,
                                    ja3ByHost_element->dns_name[0] ? "]" : "");
                                i++;
                            }
                        }
                    }

                    i = 1;

                    fprintf(out, "\nIP/JA3 Distribution:\n");
                    fprintf(out, "%-15s %-39s %-26s\n", "", "JA3", "IP");
                    HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3)
                    {
                        againstRepeat = 0;
                        HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl,
                                  tmp4)
                        {
                            if (againstRepeat == 0) {
                                fprintf(out, "\t%-7d JA3C %s", i,
                                        hostByJA3Element->ja3);
                                fprintf(out, "   %-15s %s\n",
                                        innerHashEl->ip_string,
                                        print_cipher(
                                            hostByJA3Element->unsafe_cipher));
                                againstRepeat = 1;
                                i++;
                            } else {
                                fprintf(out, "\t%45s", "");
                                fprintf(out, "   %-15s %s\n",
                                        innerHashEl->ip_string,
                                        print_cipher(
                                            hostByJA3Element->unsafe_cipher));
                            }
                        }
                    }
                    HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3)
                    {
                        againstRepeat = 0;
                        HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl,
                                  tmp4)
                        {
                            if (againstRepeat == 0) {
                                fprintf(out, "\t%-7d JA3S %s", i,
                                        hostByJA3Element->ja3);
                                fprintf(out, "   %-15s %-10s %s%s%s\n",
                                        innerHashEl->ip_string,
                                        print_cipher(
                                            hostByJA3Element->unsafe_cipher),
                                        innerHashEl->dns_name[0] ? "[" : "",
                                        innerHashEl->dns_name,
                                        innerHashEl->dns_name[0] ? "]" : "");
                                againstRepeat = 1;
                                i++;
                            } else {
                                fprintf(out, "\t%45s", "");
                                fprintf(out, "   %-15s %-10s %s%s%s\n",
                                        innerHashEl->ip_string,
                                        print_cipher(
                                            hostByJA3Element->unsafe_cipher),
                                        innerHashEl->dns_name[0] ? "[" : "",
                                        innerHashEl->dns_name,
                                        innerHashEl->dns_name[0] ? "]" : "");
                            }
                        }
                    }
                }
                fprintf(out, "\n\n");

                // freeing the hash table
                HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp)
                {
                    HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht,
                              info_of_element, tmp2)
                    {
                        if (ja3ByHost_element->host_client_info_hasht)
                            HASH_DEL(ja3ByHost_element->host_client_info_hasht,
                                     info_of_element);
                        free(info_of_element);
                    }
                    HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht,
                              info_of_element, tmp2)
                    {
                        if (ja3ByHost_element->host_server_info_hasht)
                            HASH_DEL(ja3ByHost_element->host_server_info_hasht,
                                     info_of_element);
                        free(info_of_element);
                    }
                    HASH_DEL(ja3ByHostsHashT, ja3ByHost_element);
                    free(ja3ByHost_element);
                }

                HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3)
                {
                    HASH_ITER(hh, hostByJA3C_ht->ipToDNS_ht, innerHashEl, tmp4)
                    {
                        if (hostByJA3Element->ipToDNS_ht)
                            HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
                        free(innerHashEl);
                    }
                    HASH_DEL(hostByJA3C_ht, hostByJA3Element);
                    free(hostByJA3Element);
                }

                hostByJA3Element = NULL;
                HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3)
                {
                    HASH_ITER(hh, hostByJA3S_ht->ipToDNS_ht, innerHashEl, tmp4)
                    {
                        if (hostByJA3Element->ipToDNS_ht)
                            HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
                        free(innerHashEl);
                    }
                    HASH_DEL(hostByJA3S_ht, hostByJA3Element);
                    free(hostByJA3Element);
                }
            }
        }

        /* Print all flows stats */

        qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

        if (verbose > 1) {
            for (i = 0; i < num_flows; i++)
                printFlow(i + 1, all_flows[i].flow, all_flows[i].thread_id);
        }

        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            if (ndpi_thread_info[thread_id]
                    .workflow->stats.protocol_counter[0 /* 0 = Unknown */] >
                0) {
                fprintf(out, "\n\nUndetected flows:%s\n",
                        undetected_flows_deleted
                            ? " (expired flows are not listed below)"
                            : "");
                break;
            }
        }

        num_flows = 0;
        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            if (ndpi_thread_info[thread_id]
                    .workflow->stats.protocol_counter[0] > 0) {
                for (i = 0; i < NUM_ROOTS; i++)
                    ndpi_twalk(ndpi_thread_info[thread_id]
                                   .workflow->ndpi_flows_root[i],
                               node_print_unknown_proto_walker, &thread_id);
            }
        }

        qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

        for (i = 0; i < num_flows; i++)
            printFlow(i + 1, all_flows[i].flow, all_flows[i].thread_id);

    } else if (csv_fp != NULL) {
        int i;

        num_flows = 0;
        for (thread_id = 0; thread_id < num_threads; thread_id++) {
            for (i = 0; i < NUM_ROOTS; i++)
                ndpi_twalk(
                    ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                    node_print_known_proto_walker, &thread_id);
        }

        for (i = 0; i < num_flows; i++)
            printFlow(i + 1, all_flows[i].flow, all_flows[i].thread_id);
    }

    free(all_flows);
}

void printPortStats(struct port_stats *stats)
{
    struct port_stats *s, *tmp;
    char addr_name[48];
    int i = 0, j = 0;

    HASH_ITER(hh, stats, s, tmp)
    {
        i++;
        printf(
            "\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u "
            "bytes]\n\t\tTop IP Stats:\n",
            i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

        qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair),
              info_pair_cmp);

        for (j = 0; j < MAX_NUM_IP_ADDRESS; j++) {
            if (s->top_ip_addrs[j].count != 0) {
                if (s->top_ip_addrs[j].version == IPVERSION) {
                    inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name,
                              sizeof(addr_name));
                } else {
                    inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr), addr_name,
                              sizeof(addr_name));
                }

                printf(
                    "\t\t%-36s ~ %.2f%%\n", addr_name,
                    ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
            }
        }

        printf("\n");
        if (i >= 10)
            break;
    }
}
void printMalicous()
{
    printf("123123\n");
    printf("Time info:\n Capture statge, Analyze statge\n %ld.%ld %ld.%ld\n",
           dpiresults->capture_time.tv_sec, dpiresults->capture_time.tv_usec,
           dpiresults->analyze_time.tv_sec, dpiresults->analyze_time.tv_usec);
}
