#include <stdio.h>
#include <string.h>

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

void pattern_search_module_init()
{
    /* Read snort rules and parse pcre */
    snort_rule_init();

    /* call other algorithm init here */
    return;
}

/* Find the node which msg is target and return. */
static patterns_leaf_t *find_leaf(char *target, patterns_leaf_t *start)
{
    if (!target || !start)
        return NULL;
    patterns_leaf_t *ret_node = start;

    while (strncmp(ret_node->msg, target, strlen(target)) != 0 &&
           ret_node->next) {
        ret_node = ret_node->next;
    }
    return ret_node;
}

static patterns_leaf_t *find_patterns(char *protocol,
                                      char *src_port,
                                      char *dst_port)
{
    /* Start at root & check root */
    patterns_leaf_t *location = patterns_root;
    if (!location || strncmp(location->msg, "root", 4) != 0)
        return NULL;

    /* Find protocol node */
    patterns_leaf_t *proto =
        find_leaf(protocol, (patterns_leaf_t *) location->ptr);
    if (location->ptr == NULL) {
        /* printf("Add %s_leaf into the root\n", protocol); */
        location->ptr = proto;
    }

    /* Find src_port node */
    patterns_leaf_t *sp = find_leaf(src_port, (patterns_leaf_t *) proto->ptr);
    if (proto->ptr == NULL) {
        /* printf("Add %s_leaf into the %s_leaf\n", sp->msg, proto->msg); */
        proto->ptr = sp;
    }
    /* Find dst_port node */
    patterns_leaf_t *dp = find_leaf(dst_port, (patterns_leaf_t *) sp->ptr);
    if (sp->ptr == NULL) {
        /* printf("Add %s_leaf into the %s_%s_leaf\n", dp->msg, proto->msg,
         * sp->msg); */
        sp->ptr = dp;
    }
    return dp;
}

bool pcre_search(uint16_t protocol, uint16_t sport, uint16_t dport, char *text)
{
    /* printf("%u %u %u %s\n", protocol, sport, dport, text); */
    patterns_leaf_t *dport_leaf = find_patterns("tcp", "any", "any");

    pcre_node_t *pcre_node = (pcre_node_t *) dport_leaf->ptr, *next;

    while (pcre_node) {
        pcre *re = pcre_node->re;
        const char *error;
        int ret, erroffest, ovector[100], workspace[100];
        char buf[100];

        ret = pcre_exec(re, NULL, text, strlen(text), 0, 0, ovector, 100);

        while ((ret >= 0) && (pcre_node->next_pcre_node != NULL)) {
            next = pcre_node->next_pcre_node;
            re = next->re;
            ret = pcre_exec(re, NULL, text, strlen(text), 0, 0, ovector, 100);
        }
        if (ret >= 0) {
            /*printf("Alert: %s\n", rule_node->pattern->msg);*/
            /*printf("Rule is: %s\n", pcre_node->rule);*/
            return 1;
        } else {
            pcre_node = pcre_node->next;
        }
    }
    return 0;
    /* Search all nodes in the list */

    /* while (rule_node) { */
    /* if (rule_node->pattern->pcre_node) { */
    /* pcre_node_t *pcre_node = rule_node->pattern->pcre_node; */

    /* if (strcmp(rule_node->protocol, "tcp") == 0 && */
    /* strcmp(rule_node->dst_ip, "$HTTP_PORTS") == 0) { */
    /* pcre *re = pcre_node->re; */
    /* const char *error; */
    /* int ret, erroffest, ovector[100], workspace[100]; */
    /* char buf[100]; */

    /* int ret = pcre_dfa_exec(re, NULL, text, strlen(text), 0,
       0, ovector, 100, workspace, 100); */
    /* ret = */
    /* pcre_exec(re, NULL, text, strlen(text), 0, 0, ovector, 100); */

    /* int r = pcre_copy_substring(text, ovector, 100, 0, buf,
    100); printf("Rule:%s found, the pattern is %s\n",
           rule_node->pattern->pcre_node->rule, buf); */

    /* [> Found && multi-statge search <] */
}
/* rule_node = rule_node->next; */
/* } */
