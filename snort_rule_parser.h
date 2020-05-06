#ifndef _SNORT_RULE_PARSER_H_
#define _SNORT_RULE_PARSER_H_

#include <hs/hs.h>
#include <pcre.h>
#include <stdlib.h>
#include <string.h>
/*
 * Store "content" in Snort rule option.
 * @ next -> the content of the next rule.
 * @ next_content -> there are multiple contents in this rule.
 */
typedef struct content_t {
    char *content;
    struct content_t *next;
    struct content_t *next_content;
} content_t;

/*
 * Store "PCRE" in Snort rule option.
 * Not support multiple PCRE in one rule
 * If there are multiple PCRE in one rule, refer to content_t.
 */
typedef struct pcre_node_t {
    char *msg;
    char *rule;
    struct pcre_node_t *next;
    pcre *regexp;
} pcre_node_t;

/*
 * There may be content and pcre in one rule.
 * Store them in this structure.
 */
typedef struct pattern_node_t {
    hs_database_t *hs_db;
    char **alert_msg;
    char **database;
    int *ids;
    unsigned *flags;
    int elements;
    int array_size;
    struct pcre_node_t *pcre_node;
} pattern_node_t;
/*
 * Structrues for payload checking.
 * Build a tree to stores all patterns.
 * There are 4 stages in this tree and each leaf has 2 pointers:
 *  @ ptr  -> point to next stage leaves.
 *  @ next -> point to next leaf in this stage.
 * Stages:
 *  1-stage leaves are protocol
 *  2-stage leaves are src_port
 *  3-stage leaves are dst_port
 *  4-stage leaves are patterns
 */
typedef struct leaf_t {
    char *msg;
    void *ptr;
    struct leaf_t *next;
} leaf_t;
leaf_t *patterns_root;

void snort_rule_init();
#endif
