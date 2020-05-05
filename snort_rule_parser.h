#ifndef _SNORT_RULE_PARSER_H_
#define _SNORT_RULE_PARSER_H_

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
    char *msg;
    struct content_t *content_node;
    struct pcre_node_t *pcre_node;
} pattern_node_t;

/*
 * Store a snort rule.
 */
typedef struct snort_rule {
    char *action;
    char *protocol;
    char *src_ip;
    char *src_port;
    char *dst_ip;
    char *dst_port;
    pattern_node_t *pattern;
    struct snort_rule *next;
} snort_rule;

/*
 * Use a linked list to store all the rules.
 */
typedef struct snort_rule_list {
    snort_rule *head;
    snort_rule *tail;
    int length;
} snort_rule_list;
snort_rule_list *snort_rule_q;

void snort_rule_init();
void snort_parser_release();

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
typedef struct patterns_tree_leaf_t {
    char *msg;
    void *ptr;
    struct patterns_tree_leaf_t *next;
} patterns_tree_leaf_t;
patterns_tree_leaf_t *patterns_root;
#endif
