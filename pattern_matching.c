#include "pattern_matching.h"
#include <hs/hs.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "snort_rule_parser.h"

/*
 * Return the ptr of a leaf whose msg matches the target.
 * This function will be called in finding patterns set.
 */
static leaf_t *find_leaf(char *target, leaf_t *start)
{
    if (!target || !start)
        return NULL;
    leaf_t *ret_node = start;
    /* Search for the node having target string. */
    while (ret_node) {
        if (!strcmp(ret_node->msg, target))
            return ret_node;
        else
            ret_node = ret_node->next;
    }
    return ret_node;
}

/*
 * Return the ptr of a leaf at 3-stage in patterns_tree.
 * To find the leaf having protocol, src_port and dst_port:
 * 1. Start from the root. Search for leaf whose msg == protocol in
 *    linked list(root->ptr) and return the ptr called proto.
 * 2. Search for src_port in the second linked list(proto->ptr) and return the
 *    ptr called sp.
 * 3. Search for dst_port in the third linked list(sp->ptr) and return the ptr.
 */
static void *find_patterns(leaf_t *root,
                           char *protocol,
                           char *src_port,
                           char *dst_port)
{
    /* Check if root is really thie root */
    if (!root || strncmp(root->msg, "root", 4) != 0)
        return NULL;

    leaf_t *proto, *sp, *dp;

    /* Find protocol node */
    proto = find_leaf(protocol, (leaf_t *) root->ptr);
    if (!proto)
        return NULL;

    /* Find src_port node */
    sp = find_leaf(src_port, (leaf_t *) proto->ptr);
    if (!sp)
        return NULL;

    /* Find dst_port node */
    dp = find_leaf(dst_port, (leaf_t *) sp->ptr);
    if (!dp)
        return NULL;

    return dp;
}


static void pcre_preprocess()
{
    /* Traverse all pattern_node */
    leaf_t *root = find_leaf("root", patterns_root);
    if (root) {
        leaf_t *proto = (leaf_t *) root->ptr;
        while (proto) {
            leaf_t *sp = (leaf_t *) proto->ptr;
            while (sp) {
                leaf_t *dp = (leaf_t *) sp->ptr;
                while (dp) {
                    pattern_node_t *pn = (pattern_node_t *) dp->ptr;
                    if (pn) {
                        /* Allocate memories for pcre * */
                        pn->regexp = malloc(sizeof(pcre *) * pn->elements);
                        for (int i = 0; i < pn->elements; i++) {
                            /*
                             * PCRE libray
                             */
                            const char *error;
                            int erroffset;
                            int option = 0;

                            for (int j = 0; j < strlen(pn->options[i]); j++) {
                                switch (pn->options[i][j]) {
                                case 'i':
                                    option |= PCRE_CASELESS;
                                    break;
                                case 'x':
                                    option |= PCRE_EXTENDED;
                                    break;
                                case 'm':
                                    option |= PCRE_MULTILINE;
                                    break;
                                }
                            }
                            if ((pn->regexp[i] = pcre_compile(
                                     pn->patterns[i], option, &error,
                                     &erroffset, NULL)) == NULL) {
                                fprintf(stderr,
                                        "PCRE compilation failed at offset %d:"
                                        "%s\n",
                                        erroffset, error);
                                exit(0);
                            }

                            /*
                             * Hyperscan
                             */
                            /* hs_compile_error_t *compile_err;
                            hs_error_t err;

                            if (hs_compile_multi(
                                    (const char *const *) pn->patterns,
                                    pn->flags, pn->ids, pn->elements,
                                    HS_MODE_BLOCK, NULL, &pn->database,
                                    &compile_err) != HS_SUCCESS) {
                                if (compile_err->expression < 0) {
                                    fprintf(stderr, "ERROR: %s \n",
                                            compile_err->message);
                                } else {
                                    fprintf(
                                        stderr,
                                        "ERROR pattern '%s'\nFailed "
                                        "compilation with: %s\n",
                                        pn->patterns[compile_err->expression],
                                        compile_err->message);
                                }
                                hs_free_compile_error(compile_err);
                            }
                            [>Allocate scratch<]
                            if (hs_alloc_scratch(pn->database, &pn->scratch) !=
                                HS_SUCCESS) {
                                fprintf(stderr,
                                        "ERROR Unable to allocate scratch.\n");
                                hs_free_database(pn->database);
                            } */
                        }
                    }
                    dp = dp->next;
                }
                sp = sp->next;
            }
            proto = proto->next;
        }
    }
}

/*
 * Pass the structure to eventHandler() when hs_scan matches
 * Display alert_msg in pattern_node.
 * Payload is not used now but may be used in the future.
 */
typedef struct matched_data_type {
    pattern_node_t *pn;
    char *payload;
} matched_t;

static int eventHandler(unsigned int id,
                        unsigned long long from,
                        unsigned long long to,
                        unsigned int flags,
                        void *ctx)
{
    matched_t *m = (matched_t *) ctx;
    char *alert_msg = m->pn->alert_msg;
    char *pattern = m->pn->patterns[id];
    printf("WARNING: %s\n", alert_msg);
    /* printf("Match for pattern \"%s\" at offset %llu\n", (char *) ctx, to); */
    return 1;
}

bool hs_search(uint8_t l3_protocol,
               uint16_t app_protocol,
               uint16_t sport,
               uint16_t dport,
               char *payload)
{
    /* Cast uint16_t to string */
    char src_port[6], dst_port[6];
    sprintf(src_port, "%u", sport);
    sprintf(dst_port, "%u", dport);

    /* to_be_checked->ptr points to a list storing patterns */
    leaf_t *to_be_checked[4] = {NULL, NULL, NULL, NULL};
    void *leaf;

    switch (l3_protocol) {
    case IPPROTO_TCP:
        to_be_checked[0] =
            (leaf_t *) find_patterns(patterns_root, "tcp", "any", "any");

        to_be_checked[1] =
            (leaf_t *) find_patterns(patterns_root, "tcp", "any", dst_port);

        to_be_checked[2] =
            (leaf_t *) find_patterns(patterns_root, "tcp", src_port, dst_port);

        to_be_checked[3] =
            (leaf_t *) find_patterns(patterns_root, "tcp", src_port, "any");
        break;
    case IPPROTO_UDP:
        to_be_checked[0] =
            (leaf_t *) find_patterns(patterns_root, "udp", "any", "any");

        to_be_checked[1] =
            (leaf_t *) find_patterns(patterns_root, "udp", "any", dst_port);

        to_be_checked[2] =
            (leaf_t *) find_patterns(patterns_root, "udp", src_port, dst_port);

        to_be_checked[3] =
            (leaf_t *) find_patterns(patterns_root, "udp", src_port, "any");
        break;
    case IPPROTO_ICMP:
        to_be_checked[0] =
            (leaf_t *) find_patterns(patterns_root, "icmp", "any", "any");

        to_be_checked[1] =
            (leaf_t *) find_patterns(patterns_root, "icmp", "any", dst_port);

        to_be_checked[2] =
            (leaf_t *) find_patterns(patterns_root, "icmp", src_port, dst_port);

        to_be_checked[3] =
            (leaf_t *) find_patterns(patterns_root, "icmp", src_port, "any");
        break;
    }

    for (int i = 0; i < 4; i++) {
        if (!to_be_checked[i])
            continue;

        matched_t m;
        pattern_node_t *pn = (pattern_node_t *) to_be_checked[i]->ptr;

        m.payload = payload;
        m.pn = pn;

        if (hs_scan(pn->database, payload, strlen(payload), 0, pn->scratch,
                    eventHandler, &m) != HS_SUCCESS) {
            fprintf(stderr, "ERROR: Unable to scan.\n");
            hs_free_scratch(pn->scratch);
            hs_free_database(pn->database);
        }
    }
}

bool pcre_search(uint8_t l3_protocol,
                 uint16_t app_protocol,
                 uint16_t sport,
                 uint16_t dport,
                 char *payload)
{
    /* Cast uint16_t to string */
    char src_port[6], dst_port[6];
    sprintf(src_port, "%u", sport);
    sprintf(dst_port, "%u", dport);

    /* to_be_checked->ptr points to a list storing patterns */
    leaf_t *to_be_checked[4] = {NULL, NULL, NULL, NULL};
    void *leaf;

    switch (l3_protocol) {
    case IPPROTO_TCP:
        to_be_checked[0] =
            (leaf_t *) find_patterns(patterns_root, "tcp", "any", "any");

        to_be_checked[1] =
            (leaf_t *) find_patterns(patterns_root, "tcp", "any", dst_port);

        to_be_checked[2] =
            (leaf_t *) find_patterns(patterns_root, "tcp", src_port, dst_port);

        to_be_checked[3] =
            (leaf_t *) find_patterns(patterns_root, "tcp", src_port, "any");

        break;
    case IPPROTO_UDP:
        to_be_checked[0] =
            (leaf_t *) find_patterns(patterns_root, "udp", "any", "any");

        to_be_checked[1] =
            (leaf_t *) find_patterns(patterns_root, "udp", "any", dst_port);

        to_be_checked[2] =
            (leaf_t *) find_patterns(patterns_root, "udp", src_port, dst_port);

        to_be_checked[3] =
            (leaf_t *) find_patterns(patterns_root, "udp", src_port, "any");

        break;
    case IPPROTO_ICMP:
        to_be_checked[0] =
            (leaf_t *) find_patterns(patterns_root, "icmp", "any", "any");

        to_be_checked[1] =
            (leaf_t *) find_patterns(patterns_root, "icmp", "any", dst_port);

        to_be_checked[2] =
            (leaf_t *) find_patterns(patterns_root, "icmp", src_port, dst_port);

        to_be_checked[3] =
            (leaf_t *) find_patterns(patterns_root, "icmp", src_port, "any");

        break;
    }

    /*
     * PCRE searching.
     * First for-loop for different patterns sets
     * Second for-loop for hazard level, only check the level higher than
     * threshold.
     */
    for (int i = 0; i < 4; i++) {
        if (!to_be_checked[i])
            continue;
        /* Find pattern node */
        pattern_node_t *pn = (pattern_node_t *) to_be_checked[i]->ptr;
        for (int j = 0; j < pn->elements; j++) {
            const char *error;
            int ret, erroffest, ovector[100], workspace[100];
            char buf[100];

            ret = pcre_exec(pn->regexp[j], NULL, payload, strlen(payload), 0, 0,
                            ovector, 100);
            if (ret >= 0) {
                printf("[Alert]:(tcp, %s, %s) %s\n", src_port, dst_port,
                       pn->alert_msg[j]);
                return true;
            }
        }
    }
    return false;
}

inline void pattern_search_module_init()
{
    /* Read and parse snort rules and build the patterns_tree */
    snort_rule_init();
    /* Compile PCRE expressions in all pattern node */
    pcre_preprocess();

    return;
}

void pattern_search_module_release() {}
