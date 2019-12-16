#include "ndpi_config.h"
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>
#include <math.h>
#include "ndpi_api.h"
#include "uthash.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libgen.h>

#include "reader_util.h"
#include "ndpi_example.h"

u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t verbose = 0, enable_joy_stats = 0;
int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16;//8 is enough for most protocols, Signal requires more */
u_int8_t max_num_tcp_dissected_pkts = 80; /* due to telnet */

u_int8_t num_threads = 1;

struct port_stats *srcStats = NULL, *dstStats = NULL; 
struct receiver *receivers = NULL, *topReceivers = NULL;

#ifdef DEBUG_TRACE
FILE *trace = NULL;
#endif

/* function */
void sigproc(int sig) {
    int thread_id;

    if(sig_called) 
        return; 
    else 
        sig_called = 1;

    shutdown_app = 1;

    for(thread_id=0; thread_id<num_threads; thread_id++)
        breakPcapLoop(thread_id);
}


void extcap_interfaces() {
    printf("extcap {version=%s}\n", ndpi_revision());
    printf("interface {value=ndpi}{display=nDPI interface}\n");
    exit(0);
}

void extcap_dlts() {
    u_int dlts_number = DLT_EN10MB;
    printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi", "nDPI Interface");
    exit(0);
}

int cmpProto(const void *_a, const void *_b) {
    struct ndpi_proto_sorter *a = (struct ndpi_proto_sorter*)_a;
    struct ndpi_proto_sorter *b = (struct ndpi_proto_sorter*)_b;

    return(strcmp(a->name, b->name));
}

int cmpFlows(const void *_a, const void *_b) {
    struct ndpi_flow_info *fa = ((struct flow_info*)_a)->flow;
    struct ndpi_flow_info *fb = ((struct flow_info*)_b)->flow;
    uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
    uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
    if(a_size != b_size)
        return a_size < b_size ? 1 : -1;

    // copy from ndpi_workflow_node_cmp();

    if(fa->ip_version < fb->ip_version ) return(-1); else { if(fa->ip_version > fb->ip_version ) return(1); }
    if(fa->protocol   < fb->protocol   ) return(-1); else { if(fa->protocol   > fb->protocol   ) return(1); }
    if(htonl(fa->src_ip)   < htonl(fb->src_ip)  ) return(-1); else { if(htonl(fa->src_ip)   > htonl(fb->src_ip)  ) return(1); }
    if(htons(fa->src_port) < htons(fb->src_port)) return(-1); else { if(htons(fa->src_port) > htons(fb->src_port)) return(1); }
    if(htonl(fa->dst_ip)   < htonl(fb->dst_ip)  ) return(-1); else { if(htonl(fa->dst_ip)   > htonl(fb->dst_ip)  ) return(1); }
    if(htons(fa->dst_port) < htons(fb->dst_port)) return(-1); else { if(htons(fa->dst_port) > htons(fb->dst_port)) return(1); }
    return(0);
}

void extcap_config() {
    int i, argidx = 0;
    struct ndpi_proto_sorter *protos;
    u_int ndpi_num_supported_protocols = ndpi_get_ndpi_num_supported_protocols(ndpi_info_mod);
    ndpi_proto_defaults_t *proto_defaults = ndpi_get_proto_defaults(ndpi_info_mod);

    /* -i <interface> */
    printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}"
            "{tooltip=The interface name}\n", argidx++);
    printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}"
            "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);

    protos = (struct ndpi_proto_sorter*)malloc(sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
    if(!protos) exit(0);

    for(i=0; i<(int) ndpi_num_supported_protocols; i++) {
        protos[i].id = i;
        snprintf(protos[i].name, sizeof(protos[i].name), "%s", proto_defaults[i].protoName);
    }

    qsort(protos, ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmpProto);

    printf("arg {number=%d}{call=-9}{display=nDPI Protocol Filter}{type=selector}"
            "{tooltip=nDPI Protocol to be filtered}\n", argidx);

    printf("value {arg=%d}{value=%d}{display=%s}\n", argidx, -1, "All Protocols (no nDPI filtering)");

    for(i=0; i<(int)ndpi_num_supported_protocols; i++)
        printf("value {arg=%d}{value=%d}{display=%s (%d)}\n", argidx, protos[i].id,
                protos[i].name, protos[i].id);

    free(protos);

    exit(0);
}

void extcap_capture() {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

    if((extcap_dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */),
                    extcap_capture_fifo)) == NULL) {
        fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);

#ifdef DEBUG_TRACE
        if(trace) fprintf(trace, "Unable to open the pcap dumper on %s\n",
                extcap_capture_fifo);
#endif
        return;
    }

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Starting packet capture [%p]\n", extcap_dumper);
#endif
}

void printCSVHeader() {
    if(!csv_fp) return;

    fprintf(csv_fp, "#flow_id,protocol,first_seen,last_seen,duration,src_ip,src_port,dst_ip,dst_port,ndpi_proto_num,ndpi_proto,");
    fprintf(csv_fp, "src2dst_packets,src2dst_bytes,src2dst_goodput_bytes,dst2src_packets,dst2src_bytes,dst2src_goodput_bytes,");
    fprintf(csv_fp, "data_ratio,str_data_ratio,src2dst_goodput_ratio,dst2src_goodput_ratio,");

    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "iat_flow_min,iat_flow_avg,iat_flow_max,iat_flow_stddev,");
    fprintf(csv_fp, "iat_c_to_s_min,iat_c_to_s_avg,iat_c_to_s_max,iat_c_to_s_stddev,");
    fprintf(csv_fp, "iat_s_to_c_min,iat_s_to_c_avg,iat_s_to_c_max,iat_s_to_c_stddev,");

    /* Packet Length */
    fprintf(csv_fp, "pktlen_c_to_s_min,pktlen_c_to_s_avg,pktlen_c_to_s_max,pktlen_c_to_s_stddev,");
    fprintf(csv_fp, "pktlen_s_to_c_min,pktlen_s_to_c_avg,pktlen_s_to_c_max,pktlen_s_to_c_stddev,");

    /* Flow info */
    fprintf(csv_fp, "client_info,server_info,");
    fprintf(csv_fp, "tls_version,ja3c,tls_client_unsafe,");
    fprintf(csv_fp, "ja3s,tls_server_unsafe,");
    fprintf(csv_fp, "ssh_client_hassh,ssh_server_hassh");
    fprintf(csv_fp, "\n");
}

char* printUrlRisk(ndpi_url_risk risk) {
    switch(risk) {
        case ndpi_url_no_problem:
            return("");
            break;
        case ndpi_url_possible_xss:
            return(" ** XSS **");
            break;
        case ndpi_url_possible_sql_injection:
            return(" ** SQL Injection **");
            break;
    }

    return("");
}

void updateScanners(struct single_flow_info **scanners, u_int32_t saddr,
        u_int8_t version, u_int32_t dport) {
    struct single_flow_info *f;
    struct port_flow_info *p;

    HASH_FIND_INT(*scanners, (int *)&saddr, f);

    if(f == NULL) {
        f = (struct single_flow_info*)malloc(sizeof(struct single_flow_info));
        if(!f) return;
        f->saddr = saddr;
        f->version = version;
        f->tot_flows = 1;
        f->ports = NULL;

        p = (struct port_flow_info*)malloc(sizeof(struct port_flow_info));

        if(!p) {
            free(f);
            return;
        } else
            p->port = dport, p->num_flows = 1;

        HASH_ADD_INT(f->ports, port, p);
        HASH_ADD_INT(*scanners, saddr, f);
    } else{
        struct port_flow_info *pp;
        f->tot_flows++;

        HASH_FIND_INT(f->ports, (int *)&dport, pp);

        if(pp == NULL) {
            pp = (struct port_flow_info*)malloc(sizeof(struct port_flow_info));
            if(!pp) return;
            pp->port = dport, pp->num_flows = 1;

            HASH_ADD_INT(f->ports, port, pp);
        } else
            pp->num_flows++;
    }
}

int updateIpTree(u_int32_t key, u_int8_t version,
        addr_node **vrootp, const char *proto) {
    addr_node *q;
    addr_node **rootp = vrootp;

    if(rootp == (addr_node **)0)
        return 0;

    while(*rootp != (addr_node *)0) {
        /* Knuth's T1: */
        if((version == (*rootp)->version) && (key == (*rootp)->addr)) {
            /* T2: */
            return ++((*rootp)->count);
        }

        rootp = (key < (*rootp)->addr) ?
            &(*rootp)->left :		/* T3: follow left branch */
            &(*rootp)->right;		/* T4: follow right branch */
    }

    q = (addr_node *) malloc(sizeof(addr_node));	/* T5: key not found */
    if(q != (addr_node *)0) {	                /* make new node */
        *rootp = q;			                /* link new node to old */

        q->addr = key;
        q->version = version;
        strncpy(q->proto, proto, sizeof(q->proto));
        q->count = UPDATED_TREE;
        q->left = q->right = (addr_node *)0;

        return q->count;
    }

    return(0);
}

void freeIpTree(addr_node *root) {
    if(root == NULL)
        return;

    freeIpTree(root->left);
    freeIpTree(root->right);
    free(root);
}

void updateTopIpAddress(u_int32_t addr, u_int8_t version, const char *proto,
        int count, struct info_pair top[], int size) {
    struct info_pair pair;
    int min = count;
    int update = 0;
    int min_i = 0;
    int i;

    if(count == 0) return;

    pair.addr = addr;
    pair.version = version;
    pair.count = count;
    strncpy(pair.proto, proto, sizeof(pair.proto));

    for(i=0; i<size; i++) {
        /* if the same ip with a bigger
           count just update it     */
        if(top[i].addr == addr) {
            top[i].count = count;
            return;
        }
        /* if array is not full yet
           add it to the first empty place */
        if(top[i].count == 0) {
            top[i] = pair;
            return;
        }
    }

    /* if bigger than the smallest one, replace it */
    for(i=0; i<size; i++) {
        if(top[i].count < count && top[i].count < min) {
            min = top[i].count;
            min_i = i;
            update = 1;
        }
    }

    if(update)
        top[min_i] = pair;
}

/*
 * brief Traffic stats format
 */
char* formatTraffic(float numBits, int bits, char *buf) {
    char unit;

    if(bits)
        unit = 'b';
    else
        unit = 'B';

    if(numBits < 1024) {
        snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
    } else if(numBits < (1024*1024)) {
        snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
    } else {
        float tmpMBits = ((float)numBits)/(1024*1024);

        if(tmpMBits < 1024) {
            snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
        } else {
            tmpMBits /= 1024;

            if(tmpMBits < 1024) {
                snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
            } else {
                snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
            }
        }
    }

    return(buf);
}

/*
 * Packets stats format
 */
char* formatPackets(float numPkts, char *buf) {

    if(numPkts < 1000) {
        snprintf(buf, 32, "%.2f", numPkts);
    } else if(numPkts < (1000*1000)) {
        snprintf(buf, 32, "%.2f K", numPkts/1000);
    } else {
        numPkts /= (1000*1000);
        snprintf(buf, 32, "%.2f M", numPkts);
    }

    return(buf);
}

/*
 * Bytes stats format
 */
char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
    char unit = 'B';

    if(howMuch < 1024) {
        snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
    } else if(howMuch < (1024*1024)) {
        snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
    } else {
        float tmpGB = ((float)howMuch)/(1024*1024);

        if(tmpGB < 1024) {
            snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
        } else {
            tmpGB /= 1024;

            snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
        }
    }

    return(buf);
}

void printPortStats(struct port_stats *stats) {
    struct port_stats *s, *tmp;
    char addr_name[48];
    int i = 0, j = 0;

    HASH_ITER(hh, stats, s, tmp) {
        i++;
        printf("\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u bytes]\n\t\tTop IP Stats:\n",
                i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

        qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);

        for(j=0; j<MAX_NUM_IP_ADDRESS; j++) {
            if(s->top_ip_addrs[j].count != 0) {
                if(s->top_ip_addrs[j].version == IPVERSION) {
                    inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
                } else {
                    inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr),  addr_name, sizeof(addr_name));
                }

                printf("\t\t%-36s ~ %.2f%%\n", addr_name,
                        ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
            }
        }

        printf("\n");
        if(i >= 10) break;
    }
}

void * processing_thread(void *_thread_id) {
    long thread_id = (long) _thread_id;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    /* Set core affinity (bind thread on one core) */
#if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
    if(core_affinity[thread_id] >= 0) {
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(core_affinity[thread_id], &cpuset);

        if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
            fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
        else {
            if((!quiet_mode)) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
        }
    } else
#endif


        if((!quiet_mode)) printf("Running thread %ld...\n", thread_id);

#ifdef USE_DPDK        
    while(dpdk_run_capture) {
        /* Receive packets from each port */
        RTE_ETH_FOREACH_DEV(dpdk_port_id){
            struct rte_mbuf *bufs[BURST_SIZE];
            u_int16_t nb_rx = rte_eth_rx_burst(dpdk_port_id, 0, bufs, BURST_SIZE);
            u_int i;

            if (unlikely(nb_rx == 0))
                continue;

            
            /* for(i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++)
               rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *)); */

            /*
             * When receive packets, create pcap header
             * then process the packe
             */
            for(i = 0; i < nb_rx; i++) {
                char *data = rte_pktmbuf_mtod(bufs[i], char *);
                int pkt_len = rte_pktmbuf_pkt_len(bufs[i]);
                /* Get pcap format */
                struct pcap_pkthdr h;
                h.len = h.caplen = pkt_len;
                gettimeofday(&h.ts, NULL);

                /* Call the function to process the packets */
                ndpi_process_packet((u_char*)&thread_id, &h, (const u_char *)data);
            }

            /* Send burst of TX packets, to second port of pair. */
            const uint16_t nb_tx = rte_eth_tx_burst(dpdk_port_id^1, 0, bufs, nb_rx);

            /* Free any unsent packets. */
            if (unlikely(nb_tx < nb_rx)) {
                for (i = nb_tx; i < nb_rx; i++)
                    rte_pktmbuf_free(bufs[i]);
            }
        }
    }
#else
pcap_loop:
    runPcapLoop(thread_id);

    if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
        char filename[256];

        if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
                (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
            configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
            goto pcap_loop;
        }
    }
#endif

    return NULL;
}

/*
 * Begin, process, end detection process
 */
void test_lib() {
    struct timeval end;
    u_int64_t processing_time_usec, setup_time_usec;
    long thread_id;

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Num threads: %d\n", num_threads);
#endif

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        pcap_t *cap;

#ifdef DEBUG_TRACE
        if(trace) fprintf(trace, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

        cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
        setupDetection(thread_id, cap);
    }

    gettimeofday(&begin, NULL);

    int status;
    void * thd_res;

    /* Running processing threads */
    printf("This process will create %d threads...\n", num_threads);
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        printf("Create thread %ld\n", thread_id);

        /* Create pthread */
        status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
        /* check pthreade_create return value */
        if(status != 0) {
            fprintf(stderr, "error on create %ld thread\n", thread_id);
            exit(-1);
        }
    }
    /* Waiting for completion */
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
        /* check pthreade_join return value */
        if(status != 0) {
            fprintf(stderr, "error on join %ld thread\n", thread_id);
            exit(-1);
        }
        if(thd_res != NULL) {
            fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
            exit(-1);
        }
    }

    gettimeofday(&end, NULL);
    processing_time_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
    setup_time_usec = begin.tv_sec*1000000 + begin.tv_usec - (startup_time.tv_sec*1000000 + startup_time.tv_usec);

    /* Printing cumulative results */
    printResults(processing_time_usec, setup_time_usec);

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
            pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

        terminateDetection(thread_id);
    }
}

void automataUnitTest() {
    void *automa;

    assert((automa = ndpi_init_automa()));
    assert(ndpi_add_string_to_automa(automa, "hello") == 0);
    assert(ndpi_add_string_to_automa(automa, "world") == 0);
    ndpi_finalize_automa(automa);
    assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 1);
    ndpi_free_automa(automa);
}

void serializerUnitTest() {
    ndpi_serializer serializer, deserializer;
    int i;
    u_int8_t trace = 0;

    assert(ndpi_init_serializer(&serializer, ndpi_serialization_format_tlv) != -1);

    for(i=0; i<16; i++) {
        char kbuf[32], vbuf[32];
        assert(ndpi_serialize_uint32_uint32(&serializer, i, i*i) != -1);

        snprintf(kbuf, sizeof(kbuf), "Hello %u", i);
        snprintf(vbuf, sizeof(vbuf), "World %u", i);
        assert(ndpi_serialize_uint32_string(&serializer, i, "Hello") != -1);
        assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
        assert(ndpi_serialize_string_uint32(&serializer, kbuf, i*i) != -1);
        assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
    }

    if(trace)
        printf("Serialization size: %u\n", ndpi_serializer_get_buffer_len(&serializer));

    assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);

    while(1) {
        ndpi_serialization_type kt, et;
        et = ndpi_deserialize_get_item_type(&deserializer, &kt);

        if(et == ndpi_serialization_unknown)
            break;
        else {
            u_int32_t k32, v32;
            ndpi_string ks, vs;
            float vf;

            switch(kt) {
                case ndpi_serialization_uint32:
                    ndpi_deserialize_key_uint32(&deserializer, &k32);
                    if(trace) printf("%u=", k32);
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

            switch(et) {
                case ndpi_serialization_uint32:
                    assert(ndpi_deserialize_value_uint32(&deserializer, &v32) != -1);
                    if(trace) printf("%u\n", v32);
                    break;

                case ndpi_serialization_string:
                    assert(ndpi_deserialize_value_string(&deserializer, &vs) != -1);
                    if(trace) {
                        u_int8_t bkp = vs.str[vs.str_len];
                        vs.str[vs.str_len] = '\0';
                        printf("%s\n", vs.str);
                        vs.str[vs.str_len] = bkp;
                    }
                    break;

                case ndpi_serialization_float:
                    assert(ndpi_deserialize_value_float(&deserializer, &vf) != -1);
                    if(trace) printf("%f\n", vf);
                    break;

                default:
                    if (trace) printf("\n");
                    printf("serializerUnitTest: unsupported type %u detected!\n", et);
                    return;
                    break;
            }
        }

        ndpi_deserialize_next(&deserializer);
    }

    ndpi_term_serializer(&serializer);
}
void analyzeUnitTest() {
    struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
    u_int32_t i;

    for(i=0; i<256; i++) {
        ndpi_data_add_value(s, rand()*i);
        // ndpi_data_add_value(s, i+1);
    }

    // ndpi_data_print_window_values(s);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
    printf("Average: [all: %f][window: %f]\n",
            ndpi_data_average(s), ndpi_data_window_average(s));
    printf("Entropy: %f\n", ndpi_data_entropy(s));

    printf("Min/Max: %u/%u\n",
            ndpi_data_min(s), ndpi_data_max(s));
#endif

    ndpi_free_data_analysis(s);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
    exit(0);
#endif
}

/*
 * brief Initialize port array
 */
void bpf_filter_port_array_init(int array[], int size) {
    int i;
    for(i=0; i<size; i++)
        array[i] = INIT_VAL;
}

/*
 * Initialize host array
 */
void bpf_filter_host_array_init(const char *array[48], int size) {
    int i;
    for(i=0; i<size; i++)
        array[i] = NULL;
}

/*
 * Add host to host filter array
 */
void bpf_filter_host_array_add(const char *filter_array[48], int size, const char *host) {
    int i;
    int r;
    for(i=0; i<size; i++) {
        if((filter_array[i] != NULL) && (r = strcmp(filter_array[i], host)) == 0)
            return;
        if(filter_array[i] == NULL) {
            filter_array[i] = host;
            return;
        }
    }
    fprintf(stderr,"bpf_filter_host_array_add: max array size is reached!\n");
    exit(-1);
}

/*
 * Add port to port filter array
 */
void bpf_filter_port_array_add(int filter_array[], int size, int port) {
    int i;
    for(i=0; i<size; i++) {
        if(filter_array[i] == port)
            return;
        if(filter_array[i] == INIT_VAL) {
            filter_array[i] = port;
            return;
        }
    }
    fprintf(stderr,"bpf_filter_port_array_add: max array size is reached!\n");
    exit(-1);
}
