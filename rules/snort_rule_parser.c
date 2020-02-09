#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* content node to store contents(patterns) */
typedef struct c_node {
    struct c_node *next_content;
    char *content;
} c_node;
static inline struct c_node *c_node_new()
{
    c_node *node = malloc(sizeof(c_node));
    if (node) {
        node->next_content = NULL;
        node->content = NULL;
    }
    return node;
}

/* Node to stroe all info (alert msg, contents, pcre) */
typedef struct p_node {
    char *msg;
    struct c_node *content_node;
    char *pcre;
} p_node;
static inline struct p_node *p_node_new()
{
    p_node *node = malloc(sizeof(p_node));
    if (node) {
        node->msg = NULL;
        node->content_node = NULL;
        node->pcre = NULL;
    }
    return node;
}

/* Each rule corresponds to a struct */
typedef struct snort_rule {
    char *action;
    char *protocol;
    char *src_ip;
    char *src_port;
    char *dst_ip;
    char *dst_port;
    p_node *pattern;
    struct snort_rule *next;
} snort_rule;
static inline struct snort_rule *rule_node_new()
{
    snort_rule *node = malloc(sizeof(snort_rule));
    if (node) {
        node->action = NULL;
        node->protocol = NULL;
        node->src_ip = NULL;
        node->src_port = NULL;
        node->dst_ip = NULL;
        node->dst_port = NULL;
        node->pattern = NULL;
        node->next = NULL;
    }
    return node;
}
/* All rules will be stored in a rule_queue */
typedef struct snort_rule_queue {
    snort_rule *head;
    snort_rule *tail;
    int length;
} snort_rule_queue;
snort_rule_queue *q;

/* Create rule_node*/
static inline struct snort_rule *r_node_new()
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
/* Create rule queue */
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
static inline void rule_queue_insert(snort_rule_queue *q,
                                     snort_rule *r_node_new)
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

static inline void rule_queue_release(snort_rule_queue *q)
{
    snort_rule *r_node = q->head;
    while (r_node) {
        snort_rule *next = r_node->next;
        free(r_node);
        r_node = next;
    }
    return;
}

static char *mystrip(char *str)
{
    char *end;
    end = str + strlen(str) - 1;

    while (end >= str && (end[0] == ' ')) {
        end--;
    }
    *(end + 1) = '\0';

    while (str <= end && str[0] == ' ') {
        str++;
    }
    return str;
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
    p_node *pattern_node = p_node_new();

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
                c_node *content_node = c_node_new();
                char *str = malloc(sizeof(char) * strlen(token));

                /* Copy content string to content_node */
                strncpy(str, token, strlen(token));
                content_node->content = str;

                /* Insert content_node into pattern_node */
                c_node *end_node = pattern_node->content_node;
                if (end_node == NULL) {  // There is no content_node
                    pattern_node->content_node = content_node;
                } else {  // There is content_node, find the last one.
                    while (end_node->next_content != NULL)
                        end_node = end_node->next_content;
                    end_node->next_content = content_node;
                }
            } else if (!strncmp(token, "pcre", 4)) {
                /* Remove redudent marks */
                token += 6;
                int i = 0;
                while (token[i] != '"')
                    i++;
                token[i] = '\0';

                /* Copy pcre to pattern_node */
                char *str = malloc(sizeof(char) * strlen(token));
                strncpy(str, token, strlen(token));
                pattern_node->pcre = str;
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
    rule_node->action = buf[0];
    rule_node->protocol = buf[1];
    rule_node->src_ip = buf[2];
    rule_node->src_port = buf[3];
    rule_node->dst_ip = buf[5];
    rule_node->dst_port = buf[6];

    /* Insert rule_node into rule_queue */
    rule_queue_insert(q, rule_node);


    /* printf("%s %s %s %s %s %s ", rule_node->action, rule_node->protocol,
    rule_node->src_ip, rule_node->src_port, rule_node->dst_ip,
    rule_node->dst_port); printf("msg: %s ", rule_node->pattern->msg); if
    (rule_node->pattern->content_node) printf("content: %s ",
    rule_node->pattern->content_node->content); if (rule_node->pattern->pcre)
        printf("pcre: %s ", rule_node->pattern->pcre);
    printf("\n\n"); */

    return;
}
static void read_snort_rule()
{
    /* Read patterns */
    FILE *fd = fopen("snort3-community.rules", "r");
    char buf[2000];
    int count = 0;

    while (fgets(buf, sizeof(buf), fd)) {
        if (buf[0] == '#' || buf[0] == '\n') {
            ;
        } else {
            parse_rule(buf);
            /* break; */
        }
    }
}
int main()
{
    /* Create a queue to store contents */
    q = rule_queue_create();
    read_snort_rule();

    snort_rule *rule_node = q->head;
    while (rule_node) {
        printf("%s %s %s %s %s %s ", rule_node->action, rule_node->protocol,
               rule_node->src_ip, rule_node->src_port, rule_node->dst_ip,
               rule_node->dst_port);

        printf("Alert msg: \"%s\" ", rule_node->pattern->msg);

        c_node *cn = rule_node->pattern->content_node;
        if (cn != NULL) {
            printf("Content:\"%s", cn->content);
            while (cn->next_content != NULL) {
                cn = cn->next_content;
                printf(" -> %s", cn->content);
            }
            printf("\"");
        }
        printf("\n");

        rule_node = rule_node->next;
    }

    rule_queue_release(q);
    return 0;
}

