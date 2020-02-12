#include "pattern_matching.h"
#include <stdio.h>
#include <string.h>

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

bool pcre_PS_search(char *text)
{
    snort_rule *rule_node = snort_rule_q->head;
    /* Check src_port and dst_port to find pcre list */

    /* Search all nodes in the list */
    while (rule_node) {
        if (rule_node->pattern->pcre_node) {
            pcre_node_t *pcre_node = rule_node->pattern->pcre_node;

            if (strcmp(rule_node->protocol, "tcp") == 0 && strcmp(rule_node->dst_ip, "$HTTP_PORTS") == 0) {
                pcre *re = pcre_node->re;
                const char *error;
                int ret, erroffest, ovector[100], workspace[100];
                char buf[100];

                /* int ret = pcre_dfa_exec(re, NULL, text, strlen(text), 0,
                   0, ovector, 100, workspace, 100); */
                ret =
                    pcre_exec(re, NULL, text, strlen(text), 0, 0, ovector, 100);

                /* int r = pcre_copy_substring(text, ovector, 100, 0, buf,
                100); printf("Rule:%s found, the pattern is %s\n",
                       rule_node->pattern->pcre_node->rule, buf); */

                /* Found && multi-statge search */
                while ((ret >= 0) && (pcre_node->next_pcre_node != NULL)) {
                    pcre_node = pcre_node->next_pcre_node;
                    re = pcre_node->re;
                    ret = pcre_exec(re, NULL, text, strlen(text), 0, 0, ovector,
                                    100);
                }
                if (ret >= 0) {
                    printf("Alert: %s\n", rule_node->pattern->msg);
                    printf("Rule is: %s\n", pcre_node->rule);

                    return 1;
                } else {
                    rule_node = rule_node->next;
                }
            }
        }
        rule_node = rule_node->next;
    }
    return 0;
}
