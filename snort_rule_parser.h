#ifndef _SNORT_RULE_PARSER_H_
#define _SNORT_RULE_PARSER_H_

#include <pcre.h>
#include <stdlib.h>
#include <string.h>

/*
 * This structure stores contents which is malicious pattern used in payload
 * check. next_content means the rule contains multiple patterns that should be
 * checked.
 */
typedef struct c_node_t {
    struct c_node_t *next_content;
    char *content;
} c_node_t;

/*
 * This structure stores rule options.
 * For now, only store msg, content and pcre.
 */
typedef struct pcre_node_t {
    struct pcre_node_t *next_pcre_node;
    char *rule;
    pcre *re;
    struct pcre_node_t *next;
} pcre_node_t;

typedef struct pattern_node_t {
    char *msg;
    struct c_node_t *content_node;
    struct pcre_node_t *pcre_node;
} pattern_node_t;

/*
 * This structure stores a snort rule.
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
 * Use a list to record all rules.
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
 * Payload check module
 */
typedef struct patterns_leaf_t {
    void *ptr;
    char *msg;
    struct patterns_leaf_t *next;
} patterns_leaf_t;

patterns_leaf_t *patterns_root;


#endif
