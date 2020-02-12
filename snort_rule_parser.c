#include <pcre.h>
#include <stdint.h>
#include <stdio.h>

#include "snort_rule_parser.h"

/* Create a new content node */
static struct c_node_t *c_node_new()
{
    c_node_t *node = malloc(sizeof(c_node_t));
    if (node) {
        node->next_content = NULL;
        node->content = NULL;
    }
    return node;
}

/* Create a new pcre node */
static struct pcre_node_t *pcre_node_new()
{
    pcre_node_t *node = malloc(sizeof(pcre_node_t));
    if (node) {
        node->next_pcre_node = NULL;
        node->rule = NULL;
        node->re = NULL;
    }
    return node;
}

/* Create a new pattern node */
static struct pattern_node_t *pattern_node_new()
{
    pattern_node_t *node = malloc(sizeof(pattern_node_t));
    if (node) {
        node->msg = NULL;
        node->content_node = NULL;
        node->pcre_node = NULL;
    }
    return node;
}

/* Create a new snor_rule node*/
static struct snort_rule *r_node_new()
{
    snort_rule *r_node = malloc(sizeof(snort_rule));
    if (r_node) {
        r_node->action = NULL;
        r_node->protocol = NULL;
        r_node->src_ip = NULL;
        r_node->src_port = NULL;
        r_node->dst_ip = NULL;
        r_node->dst_port = NULL;
        r_node->pattern = NULL;
        r_node->next = NULL;
    }
    return r_node;
}

/* Create a queue to store snore_rule nodes */
static struct snort_rule_queue *rule_queue_create()
{
    snort_rule_queue *q = malloc(sizeof(snort_rule));
    if (q) {
        q->head = NULL;
        q->tail = NULL;
        q->length = 0;
    }
    return q;
}

/* Insert a rule_node into rule_queue */
static void rule_queue_insert(snort_rule_queue *q, snort_rule *r_node_new)
{
    if (!q || !r_node_new)
        return;
    else {
        if (!q->head) {
            q->head = r_node_new;
            q->tail = r_node_new;
        } else {
            q->tail->next = r_node_new;
            q->tail = r_node_new;
        }
    }
}

/* Remove space at head and tail */
static char *mystrip(char *str)
{
    char *end;
    end = str + strlen(str) - 1;

    while (end >= str && (end[0] == ' '))
        end--;
    *(end + 1) = '\0';

    while (str <= end && str[0] == ' ')
        str++;

    return str;
}

static void pattern_search(pcre *re, char *text)
{
    const char *error;
    int erroffest;
    int ovector[100];
    int workspace[100];

    int ret = pcre_dfa_exec(re, NULL, text, strlen(text), 0, 0, ovector, 100,
                            workspace, 100);
    if (ret >= 0)
        printf("Pattern found!\n");
    else
        printf("Not found!\n");
}

/*
   snort3 rule format
   action protocol src_ip src_port -> dst_ip dst_port (msg:"";xxxx;
   content:"....";pcre:""; )
*/
static void parse_rule(char *str)
{
    /* Create rule node for each line */
    snort_rule *rule_node = r_node_new();
    pattern_node_t *pattern_node = pattern_node_new();

    rule_node->pattern = pattern_node;

    int c = 0;     // count for location of the rule
    char *buf[7];  // store action, protocol, src_ip ... dst_port
    char *space = " ", *semicolon = ";", *delim, *token;

    delim = space;
    token = strtok(str, delim);

    while (token) {
        /* Parse options */
        if (c > 6) {
            delim = semicolon;

            if (token[0] == '(' || token[0] == ')') {
                token = strtok(NULL, delim);
                continue;
            } else if (!strncmp(token, "msg", 3)) {
                /* Remove redudent marks */
                token += 5;
                int i = 0;
                while (token[i] != '"')
                    i++;
                token[i] = '\0';

                /* Copy msg to pattern_node */
                char *str = malloc(sizeof(char) * strlen(token));
                strncpy(str, token, strlen(token));
                pattern_node->msg = str;

            } else if (!strncmp(token, "content:", 7)) {
                /* Remove redudent marks */
                token += 9;
                int i = 0;
                while (token[i] != '"')
                    i++;
                token[i] = '\0';

                /* Create content_node and string */
                c_node_t *content_node = c_node_new();
                char *str = malloc(sizeof(char) * strlen(token));

                /* Copy content string to content_node */
                strncpy(str, token, strlen(token));
                content_node->content = str;

                /* Insert content_node into pattern_node */
                c_node_t *end_node = pattern_node->content_node;
                if (end_node == NULL) {  // There is no content_node
                    pattern_node->content_node = content_node;
                } else {  // There is content_node, find the last one.
                    while (end_node->next_content != NULL)
                        end_node = end_node->next_content;
                    end_node->next_content = content_node;
                }
            } else if (!strncmp(token, "pcre", 4)) {
                /* Remove redudent marks */
                token += 7;
                int i = 0, j = strlen(token);
                while (token[j] != '/')
                    j--;
                token[j] = '\0';

                /* Save rule */
                pcre_node_t *pcre_node = pcre_node_new();
                char *str = malloc(sizeof(char) * (strlen(token) + 1));
                strncpy(str, token, strlen(token) + 1);
                pcre_node->rule = str;

                /* pcre parameters */
                const char *error;
                int erroffset;

                /* pcre compilation */
                pcre_node->re = pcre_compile(str, 0, &error, &erroffset, NULL);
                if (pcre_node->re == NULL) {
                    fprintf(stderr,
                            "PCRE compilation failed at offset %d: %s\n",
                            erroffset, error);
                    fprintf(stderr, "Pattern is: %s\n", str);
                    exit(1);
                }

                /* Insert */
                pcre_node_t *end_node = pattern_node->pcre_node;
                if (end_node == NULL) {
                    pattern_node->pcre_node = pcre_node;
                } else {
                    while (end_node->next_pcre_node != NULL)
                        end_node = end_node->next_pcre_node;
                    end_node->next_pcre_node = pcre_node;
                }
            }
            token = mystrip(strtok(NULL, delim));
        }

        /* Parse action, protocol, srcip... */
        else {
            buf[c] = malloc(sizeof(char) * strlen(token));
            strncpy(buf[c], token, strlen(token));
            token = strtok(NULL, delim);
            c++;
        }
    }
    /* Assign action, protocol, src_ip ... */
    rule_node->action = buf[0];
    rule_node->protocol = buf[1];
    rule_node->src_ip = buf[2];
    rule_node->src_port = buf[3];
    rule_node->dst_ip = buf[5];
    rule_node->dst_port = buf[6];

    /* Insert rule_node into rule_queue */
    rule_queue_insert(snort_rule_q, rule_node);

    return;
}

static void read_snort_rule()
{
    /* Read snort rule file */
    FILE *fd = fopen("rules/snort3-community.rules", "r");
    char buf[2000];
    int count = 0;

    while (fgets(buf, sizeof(buf), fd)) {
        if (buf[0] == '#' || buf[0] == '\n')
            ;
        else
            parse_rule(buf);
    }
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
            printf("pcre:\"%s", rule_node->pattern->pcre_node->rule);

        printf("\n");
        rule_node = rule_node->next;
    }
}

void snort_rule_init()
{
    /* Parameters declaration. */
    snort_rule_q = rule_queue_create();

    /* Read rule file & parse. */
    read_snort_rule();

    /* show_rules(); */

    return;
}

void snort_parser_release(snort_rule_queue *q)
{
    snort_rule *r_node = q->head;
    while (r_node) {
        snort_rule *next = r_node->next;
        free(r_node);
        r_node = next;
    }
    return;
}

