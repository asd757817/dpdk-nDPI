#ifndef _NDPI_INIT_H_
#define _NDPI_INIT_H_

/* User preferences */

/* Client parameters */
static char
    *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = {
    NULL}; /**< Ingress playlist */
static FILE *results_file = NULL;
static char *results_path = NULL;
static char *bpfFilter = NULL;      /**< bpf filter  */
static char *_protoFilePath = NULL; /**< Protocol file path  */
static char *_customCategoryFilePath =
    NULL;                   /**< Custom categories file path  */
static FILE *csv_fp = NULL; /**< for CSV export */

static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t num_threads = 1;

#endif
