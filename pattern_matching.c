#include "pattern_matching.h"
#include <stdio.h>
#include <string.h>

/*
 * automata search
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
            printf("add string: %s\n", pat);
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


/*
 * Regular expression
 */
void regex_PM_init()
{
    regex_patterns = malloc(MAX_PATTERNS * sizeof(regex_t));
    int ret;
    nb_real_patterns = 0;
    char *file_name = "rules/snort_parsed.txt";
    /* Read patterns */
    FILE *fd = fopen(file_name, "r");
    char regexp[1000];

    while (fgets(regexp, sizeof(regexp), fd)) {
        /* Ignore comments */
        if (regexp[0] == '#' || regexp[0] == '\n')
            ;
        /* Add patterns */
        else {
            if (nb_real_patterns >= MAX_PATTERNS)
                break;

            strtok(regexp, "\n");
            ret =
                regcomp(&regex_patterns[nb_real_patterns], regexp, REG_NEWLINE);
            if (ret) {
                fprintf(stderr, "Regex init error.\n");
                exit(0);
            }
            nb_real_patterns++;
        }
    }
}

inline void regex_PM_release()
{
    for (int i = 0; i < MAX_PATTERNS; i++)
        regfree(&regex_patterns[i]);
}

inline bool regex_PM_search(char *target)
{
    int ret;
    for (int i = 0; i < nb_real_patterns; i++) {
        ret = regexec(&regex_patterns[i], target, 0, NULL, 0);
        if (!ret) {
            return true;
        }
    }
    return false;
}
