#include "snort_rule_parser.h"
#include <hs/hs.h>
#include <pcre.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Create a new content node */
static struct content_t *c_node_new()
{
    content_t *node = malloc(sizeof(content_t));
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
        node->rule = NULL;
        node->msg = NULL;
        node->regexp = NULL;
        node->next = NULL;
    }
    return node;
}

/* Create a new pattern node */
#define default_array_size 20
static struct pattern_node_t *pattern_node_new()
{
    pattern_node_t *node = malloc(sizeof(pattern_node_t));
    if (node) {
        node->elements = 0;
        node->array_size = default_array_size;
        node->alert_msg = malloc(sizeof(char *) * default_array_size);
        node->patterns = malloc(sizeof(char *) * default_array_size);
        node->ids = malloc(sizeof(int) * default_array_size);
        node->flags = malloc(sizeof(unsigned) * default_array_size);
        node->options = malloc(sizeof(unsigned) * default_array_size);
        node->pcre_node = NULL;
        node->scratch = NULL;
    }
    return node;
}

/* Create a new leaf */
static struct leaf_t *tree_leaf_new(char *str)
{
    leaf_t *node = malloc(sizeof(leaf_t));
    if (node) {
        node->ptr = NULL;
        node->next = NULL;
        if (str) {
            node->msg = malloc(sizeof(char) * strlen(str) + 1);
            strncpy(node->msg, str, strlen(str));
            node->msg[strlen(str)] = '\0';
        } else
            node->msg = NULL;
    }
    return node;
}

/* Remove space at head and tail */
static char *mystrip(char *str)
{
    char *end;

    end = str + strlen(str) - 1;
    while (str[0] == ' ')
        str++;
    while (end >= str && (end[0] == ' '))
        end--;
    *(end + 1) = '\0';

    return str;
}

/* Find the node which msg is target and return. */
static leaf_t *find_leaf(char *target, leaf_t *start)
{
    if (!target || !start)
        return NULL;

    leaf_t *ret_node = start;
    while (ret_node) {
        if (!strcmp(ret_node->msg, target))
            return ret_node;
        else
            ret_node = ret_node->next;
    }
    return ret_node;
}

/*
 * Search for target leaf.
 * Start from root -> src_port ... -> dst_port.
 * If leaf dosen't exist, create a leaf.
 * Return the dst_port leaf.
 */
static void *find_patterns(leaf_t *root,
                           char *protocol,
                           char *src_port,
                           char *dst_port)
{
    /* Check if root is really thie root */
    if (!root || strncmp(root->msg, "root", 4) != 0)
        return NULL;

    /* Find protocol node */
    leaf_t *proto = find_leaf(protocol, (leaf_t *) root->ptr);

    /* if return node is NULL then create one */
    if (!proto) {
        proto = tree_leaf_new(protocol);
        if (root->ptr) {
            leaf_t *node = (leaf_t *) root->ptr;
            while (node->next)
                node = node->next;
            node->next = (void *) proto;
        } else {
            root->ptr = (void *) proto;
        }
    }

    /* Find src_port node */
    leaf_t *sp = find_leaf(src_port, (leaf_t *) proto->ptr);
    if (!sp) {
        sp = tree_leaf_new(src_port);
        if (proto->ptr) {
            leaf_t *node = (leaf_t *) proto->ptr;
            while (node->next)
                node = node->next;
            node->next = (void *) sp;
        } else {
            proto->ptr = (void *) sp;
        }
    }

    /* Find dst_port node */
    leaf_t *dp = find_leaf(dst_port, (leaf_t *) sp->ptr);
    if (!dp) {
        dp = tree_leaf_new(dst_port);
        if (sp->ptr) {
            leaf_t *node = (leaf_t *) sp->ptr;
            while (node->next)
                node = node->next;
            node->next = (void *) dp;
        } else {
            sp->ptr = (void *) dp;
        }
    }
    return dp;
}

/*
 * If pattern_node dosen't exitst, create one.
 * Else update new rule into pattern_node.
 * If array in pattern_node is full, resize it.
 */
static void tree_add_node(leaf_t *root,
                          char **buf,
                          char *alert_msg,
                          char *pcre_rule,
                          char *pcre_flag)
{
    /* Search for leaf and get the pcre_node */
    leaf_t *dp_leaf = find_patterns(root, buf[1], buf[3], buf[6]);
    pattern_node_t *pn = (pattern_node_t *) dp_leaf->ptr;

    if (!pn)
        pn = pattern_node_new();

    /* If the array is full, double its size. */
    if (pn->array_size == pn->elements) {
        /* Copy all values in array to a tmp */
        int size = pn->array_size;
        char **tmp_alert_msg = malloc(sizeof(char *) * size);
        char **tmp_patterns = malloc(sizeof(char *) * size);
        char **tmp_options = malloc(sizeof(char *) * size);
        int *tmp_ids = malloc(sizeof(char *) * size);
        unsigned *tmp_flags = malloc(sizeof(char *) * size);

        for (int i = 0; i < size; i++) {
            tmp_alert_msg[i] = pn->alert_msg[i];
            tmp_patterns[i] = pn->patterns[i];
            tmp_options[i] = pn->options[i];
            tmp_ids[i] = pn->ids[i];
            tmp_flags[i] = pn->flags[i];
        }

        /* Free and Resize */
        free(pn->alert_msg);
        free(pn->patterns);
        free(pn->options);
        free(pn->ids);
        free(pn->flags);

        int new_size = pn->array_size * 2;
        pn->alert_msg = malloc(sizeof(char *) * new_size);
        pn->patterns = malloc(sizeof(char *) * new_size);
        pn->options = malloc(sizeof(char *) * new_size);
        pn->ids = malloc(sizeof(char *) * new_size);
        pn->flags = malloc(sizeof(char *) * new_size);

        for (int i = 0; i < size; i++) {
            pn->alert_msg[i] = tmp_alert_msg[i];
            pn->patterns[i] = tmp_patterns[i];
            pn->options[i] = tmp_options[i];
            pn->ids[i] = tmp_ids[i];
            pn->flags[i] = tmp_flags[i];
        }
        pn->array_size = new_size;
    }

    /* Update */
    int elements = pn->elements;
    pn->alert_msg[elements] = alert_msg;
    pn->patterns[elements] = pcre_rule;
    pn->options[elements] = pcre_flag;
    pn->ids[elements] = elements;

    /* PCRE flags */
    int flag = HS_FLAG_PREFILTER | HS_FLAG_ALLOWEMPTY;
    for (int i = 0; i < strlen(pcre_flag); i++) {
        switch (pcre_flag[i]) {
        case 'i':
            flag |= HS_FLAG_CASELESS;
            break;
        case 'x':
            flag |= PCRE_EXTENDED;
            break;
        case 'm':
            flag |= HS_FLAG_MULTILINE;
            break;
        case 's':
            flag |= HS_FLAG_DOTALL;
            break;
        }
    }
    pn->flags[elements] = flag;
    pn->elements += 1;
    dp_leaf->ptr = (void *) pn;

    return;
}

/* Return the first location of specific char */
static inline int find_char(char target, char *str)
{
    int i = 0;
    while (target != str[i])
        i += 1;
    return i;
}


/*
 * Parse snort rules.
 * Only extract rules that contain PCRE expression.
 * Not record `content`!!
 */
static void parse_rule(char *str)
{
    int c = 0;     // count for location of the rule
    char *buf[7];  // action, protocol, src_ip ... dst_port
    char *alert_msg = NULL, *pcre_rule = NULL, *pcre_flag = NULL;
    char *space = " ", *semicolon = ";", *delim, *token;

    delim = space;
    token = strtok(str, delim);

    while (token) {
        /* Parse Snort rule options */
        if (c > 6) {
            delim = semicolon;

            if (token[0] == '(' || token[0] == ')') {
                token = strtok(NULL, delim);
                continue;
            } else if (!strncmp(token, "msg", 3)) {
                /* Remove redundant marks */
                token += find_char('"', token) + 1;
                token[find_char('"', token)] = '\0';

                /* Copy msg to pattern_node */
                char *msg = malloc(sizeof(char) * strlen(token));
                strncpy(msg, token, strlen(token));
                alert_msg = msg;
            } else if (!strncmp(token, "pcre", 4)) {
                /* Remove redudent marks */
                token += find_char('"', token) + 1;
                token[find_char('"', token)] = '\0';

                /*
                 * The remaining rule will look like /[test]/i
                 * String between two '/'     -> PCRE rule
                 * String after the second '/'-> PCRE options
                 */
                int start = find_char('/', token);
                int end = strlen(token);
                while (token[end] != '/')
                    end -= 1;

                int len_rule = end - start - 1;
                int len_flag = strlen(token) - end - 1;

                char *tmp_pcre_rule = malloc(len_rule);
                char *tmp_pcre_flag = malloc(len_flag);

                strncpy(tmp_pcre_rule, token + start + 1, len_rule);
                strncpy(tmp_pcre_flag, token + end + 2, len_flag);

                pcre_rule = tmp_pcre_rule;
                pcre_flag = tmp_pcre_flag;
            }
            token = mystrip(strtok(NULL, delim));
        }
        /* Parse action, protocol, src_ip and ... */
        else {
            buf[c] = malloc(sizeof(char) * strlen(token));
            strncpy(buf[c], token, strlen(token));
            buf[c][strlen(token)] = '\0';
            token = strtok(NULL, delim);
            c++;
        }
    }
    /*
     * If the rule contains PCRE rule, save it.
     * 1. Find the leaf in patterns_tree.
     * 2. Add the rule into leaf->patterns ...
     */
    if (pcre_rule) {
        tree_add_node(patterns_root, buf, alert_msg, pcre_rule, pcre_flag);
    }
    return;
}

/* Read snort rule file line by line and call parser */
static void read_snort_rule()
{
    /* Read file */
    FILE *fd = fopen("rules/snort3-community.rules", "r");
    char buf[2000];
    int count = 0;

    /* Parse rules line by line */
    while (fgets(buf, sizeof(buf), fd)) {
        if (buf[0] == '#' || buf[0] == '\n')
            continue;
        else
            parse_rule(buf);
    }
}

/* Create the root of patterns tree */
bool patterns_tree_init()
{
    patterns_root = tree_leaf_new("root");
    if (patterns_root)
        return true;
    return false;
}

/* Display the tree */
static void show_tree()
{
    leaf_t *root = find_leaf("root", patterns_root);
    if (root) {
        printf("%s\n", patterns_root->msg);
        leaf_t *proto = (leaf_t *) root->ptr;
        while (proto) {
            printf("|-----%s\n", proto->msg);
            leaf_t *sp = (leaf_t *) proto->ptr;
            while (sp) {
                printf("\t|-----%s\n", sp->msg);
                leaf_t *dp = (leaf_t *) sp->ptr;

                while (dp) {
                    printf("\t\t|-----%s\n", dp->msg);
                    pattern_node_t *pn = (pattern_node_t *) dp->ptr;
                    if (pn) {
                        for (int i = 0; i < pn->elements; i++) {
                            printf("\t\t\t|-----%s\n", pn->alert_msg[i]);
                            /* printf("\t\t\t\t|-----%s\n", pn->patterns[i]); */
                        }
                    }
                    dp = dp->next;
                }
                sp = sp->next;
            }
            proto = proto->next;
        }
    }
}


void snort_rule_init()
{
    /* Parameters declaration. */
    int ret = patterns_tree_init();
    if (!ret)
        fprintf(stderr, "payload check module initialization error!\n");

    /* Read rule file & parse. */
    read_snort_rule();

    /* For debuggin */
    /* show_tree(); */
    return;
}
