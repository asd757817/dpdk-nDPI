#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* myqueue struct & functions */
typedef struct q_node {
    struct q_node *next;
    char *content;
} q_node;

typedef struct myqueue {
    q_node *head;
    q_node *tail;
    int length;
} myqueue;

myqueue *q;

static myqueue *q_create()
{
    myqueue *q = malloc(sizeof(myqueue));
    if (q) {
        q->head = NULL;
        q->tail = NULL;
        q->length = 0;
    }
    return q;
}

static void q_insert(myqueue *q, char *str)
{
    if (!q || !str)
        return;
    else {
        q_node *node = malloc(sizeof(q_node));
        char *s_cpy = malloc(strlen(str) + 1);

        if (node && s_cpy) {
            strcpy(s_cpy, str);
            node->content = s_cpy;
        }

        if (!q->head) {  // if head is NULL -> tail must be NULL too.
            q->head = node;
            q->tail = node;
        } else if (q->head == q->tail) {
            q->head->next = node;
            q->tail = node;
        } else {
            q->tail->next = node;
            q->tail = node;
        }
        q->length++;
    }
}


/*
   snort3 rule format
   action protocol src_ip src_port -> dst_ip dst_port (msg:"";xxxx;
   content:"....";pcre:""; )
*/

/* Not used now. TODO.... */
typedef struct snort_rule {
    char *action;
    uint32_t protocol;
    uint32_t src_ip;
    uint32_t src_port;
    uint32_t dst_ip;
    uint32_t dst_port;
    char *event_type;
    char *malicious_pattern;
    char *malicious_regex;
} snort_rule;

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

static void parse_rule(char *str)
{
    char *space = " ", *semicolon = ";", *delim, *token;

    delim = space;
    token = strtok(str, delim);

    while (token != NULL) {
        if (token[0] == '(')
            delim = semicolon;

        else if (token[0] == ')')
            break;

        /* Parse contents and pcre then add into the queue */
        if (!strncmp(token, "content:", 8)) {
            q_insert(q, token);
        }

        token = mystrip(strtok(NULL, delim));
    }
    return;
}

static void parse_content(myqueue *q)
{
    q_node *node = q->head;

    while (node){
        char *buf = node->content;
        if (buf[strlen(buf)-1] == '"'){
            *(buf + strlen(buf) - 1) = '\0';
            buf += 9;
            
            char* new_content = malloc(strlen(buf)+1);

            strcpy(new_content, buf);
            free(node->content);
            node->content = new_content;            
            /* printf("%s\n", buf); */
        }
        else{
            char* tmp;
            tmp = strtok(buf, "\"");
            tmp = strtok(NULL, "\"");

            char* new_content = malloc(strlen(tmp)+1);
            strcpy(new_content, tmp);
            free(node->content);
            node->content = new_content;            
            /* printf("%s\n", buf); */
        }
        node = node->next;
    }
}

int main()
{
    /* Create a queue to store contents */
    q = q_create();

    /* Read patterns */
    FILE *fd = fopen("snort3-community.rules", "r");
    char buf[2000];
    int count = 0;

    while (fgets(buf, sizeof(buf), fd)) {
        if (buf[0] == '#' || buf[0] == '\n')
            ;
        else {
            parse_rule(buf);
        }
    }

    /* 
        Parse content stored in queue again.
        Delete semicolon, comma, quotation... 
    */

    parse_content(q);

    q_node *node = q->head;

    FILE *output = fopen("snort_parsed.txt", "w");
    while (node){
        char *tmp = node->content;
        fprintf(output, "%s\n", tmp);
        node = node->next;
    }
    return 0;
}

