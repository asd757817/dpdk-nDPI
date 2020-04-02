#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pattern_matching.h"
#include "snort_rule_parser.h"

/*
 * Use nDPI third-party library
 * Only call API.
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

static void show_rules()
{
    snort_rule *rule_node = snort_rule_q->head;

    while (rule_node) {
        /* Show action, protocol, ... , dst_port */
        printf("%s %s %s %s %s %s ", rule_node->action, rule_node->protocol,
               rule_node->src_ip, rule_node->src_port, rule_node->dst_ip,
               rule_node->dst_port);
        printf("Alert msg: \"%s\" ", rule_node->pattern->msg);

        /* Show content */
        c_node_t *cn = rule_node->pattern->content_node;
        if (cn != NULL) {
            printf("Content:\"%s", cn->content);
            while (cn->next_content != NULL) {
                cn = cn->next_content;
                printf(" -> %s", cn->content);
            }
            printf("\" ");
        }

        /* Show pcre */
        if (rule_node->pattern->pcre_node)
            printf("pcre:\"%s\"", rule_node->pattern->pcre_node->rule);

        printf("\n");
    }
    return;
}


/* Find the node whose msg is target and return the node. */
static patterns_tree_leaf_t *find_leaf(char *target,
                                       patterns_tree_leaf_t *start)
{
    if (!target || !start)
        return NULL;

    patterns_tree_leaf_t *ret_node = start;

    while (strcmp(ret_node->msg, target) != 0 && ret_node->next)
        ret_node = ret_node->next;

    if (strcmp(ret_node->msg, target) != 0)
        return NULL;

    return ret_node;
}

static void *find_patterns(patterns_tree_leaf_t *root,
                           char *protocol,
                           char *src_port,
                           char *dst_port)
{
    /* Check if root is really thie root */
    if (!root || strncmp(root->msg, "root", 4) != 0)
        return NULL;

    /* Find protocol node */
    patterns_tree_leaf_t *proto =
        find_leaf(protocol, (patterns_tree_leaf_t *) root->ptr);
    if (!proto)
        return NULL;

    /* Find src_port node */
    patterns_tree_leaf_t *sp =
        find_leaf(src_port, (patterns_tree_leaf_t *) proto->ptr);
    if (!sp)
        return NULL;

    /* Find dst_port node */
    patterns_tree_leaf_t *dp =
        find_leaf(dst_port, (patterns_tree_leaf_t *) sp->ptr);
    if (!dp)
        return NULL;

    return dp;
}

static inline void leaves_add(patterns_tree_leaf_t **start, void *new_leaf)
{
    if (*start == NULL && new_leaf)
        *start = (patterns_tree_leaf_t *) new_leaf;
    else {
        patterns_tree_leaf_t *node = *start;

        if (node->next == NULL)
            printf("123123\n");
        else
            printf("345345\n");
    }
    return;
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
    
    /* leaves_to_be_checked->ptr points to a list storing patterns */
    patterns_tree_leaf_t *leaves_to_be_checked[4];
    void *leaf;

    switch (ip_proto) {
    case IPPROTO_TCP:
        leaf = find_patterns(patterns_root, "tcp", "any", "any");
        leaves_to_be_checked[0] = (patterns_tree_leaf_t *) leaf;

        leaf = find_patterns(patterns_root, "tcp", src_port, dst_port);
        leaves_to_be_checked[1] = (patterns_tree_leaf_t *) leaf;

        leaf = find_patterns(patterns_root, "tcp", "any", dst_port);
        leaves_to_be_checked[2] = (patterns_tree_leaf_t *) leaf;

        leaf = find_patterns(patterns_root, "tcp", src_port, "any");
        leaves_to_be_checked[3] = (patterns_tree_leaf_t *) leaf;
        break;
    case IPPROTO_UDP:
        leaf = find_patterns(patterns_root, "udp", "any", "any");
        break;
    case IPPROTO_ICMP:
        leaf = find_patterns(patterns_root, "icmp", "any", "any");
        break;
    }

    /* Pattern matchiing */
    for (int i = 0; i < 4; i++) {
        if (!leaves_to_be_checked[i])
            continue;
        pcre_node_t *pcre_node = (pcre_node_t *) leaves_to_be_checked[i]->ptr,
                    *next;
        while (pcre_node != NULL) {
            pcre *expression = pcre_node->re;
            const char *error;
            int ret, erroffest, ovector[100], workspace[100];
            char buf[100];

            ret = pcre_exec(expression, NULL, payload, strlen(payload), 0, 0,
                            ovector, 100);
            /* Match for all stages means hits the rule */
            while ((ret >= 0) && (pcre_node->next_pcre_node != NULL)) {
                next = pcre_node->next_pcre_node;
                re = next->re;
                ret = pcre_exec(re, NULL, payload, strlen(payload), 0, 0,
                                ovector, 100);
            }
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
