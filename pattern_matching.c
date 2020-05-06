#include "pattern_matching.h"
#include <hs/hs.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "snort_rule_parser.h"

/*
 * Use nDPI third-party library
 * Only call the APIs in nDPI.
 * To be refined ...
 */
void automata_PM_init()
{
    automata_patterns = ndpi_init_automa();
    char *file_name = "rules/snort_parsed.txt";
    /* Read patterns */
    FILE *fd = fopen(file_name, "r");
    char pat[1000];

    while (fgets(pat, sizeof(pat), fd)) {
        /* Ignore comments */
        if (pat[0] == '#' || pat[0] == '\n')
            ;
        /* Add patterns */
        else {
            strtok(pat, "\n");
            /* Add string to automata */
            ndpi_add_string_to_automa(automata_patterns, pat);
        }
    }
    ndpi_finalize_automa(automata_patterns);
}

inline void automata_PM_release()
{
    ndpi_free_automa(automata_patterns);
}

inline bool automata_PM_search(char *str)
{
    return ndpi_match_string(automata_patterns, str);
}

/*
 * Find the node whose msg matches target and return the ptr of node.
 * This function will be called in finding patterns set.
 */
static leaf_t *find_leaf(char *target, leaf_t *start)
{
    if (!target || !start)
        return NULL;
    leaf_t *ret_node = start;

    /*
     * Search for the node having target string.
     */
    while (ret_node) {
        if (!strcmp(ret_node->msg, target))
            return ret_node;
        else
            ret_node = ret_node->next;
    }
    return ret_node;
}

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

bool pcre_search(uint8_t ip_proto,
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

    switch (ip_proto) {
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

        pcre_node_t *pcre_node = (pcre_node_t *) to_be_checked[i]->ptr, *next;
        while (pcre_node != NULL) {
            pcre *expression = pcre_node->regexp;
            const char *error;
            int ret, erroffest, ovector[100], workspace[100];
            char buf[100];

            ret = pcre_exec(expression, NULL, payload, strlen(payload), 0, 0,
                            ovector, 100);
            if (ret >= 0) {
                printf("[Alert]:(tcp, %s, %s) %s\n", src_port, dst_port,
                       pcre_node->msg);
                return true;
            } else
                pcre_node = pcre_node->next;
        }
    }
    return false;
}

inline void pattern_search_module_init()
{
    /* Read snort rules and parse pcre */
    snort_rule_init();
    return;
}
