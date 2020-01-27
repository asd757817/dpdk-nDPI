#include "pattern_matching.h"
#include <stdio.h>
#include <string.h>


void regex_PM_init()
{
    regex_patterns = malloc(MAX_PATTERNS * sizeof(regex_t));

    int ret;
    nb_real_patterns = 0;

    /* Read patterns */
    FILE *fd = fopen("patterns_regex.txt", "r");
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
