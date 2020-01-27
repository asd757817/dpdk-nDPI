#ifndef _PATTERN_MATCHING_H_
#define _PATTERN_MATCHING_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "ndpi_api.h"
#include "ndpi_config.h"

/* Regular expression  */
#include <regex.h>

#define MAX_PATTERNS 100

regex_t *regex_patterns;
int nb_real_patterns;

void regex_PM_init();
void regex_PM_release();
bool regex_PM_search(char *str);

/* automata + regular expression */
#endif
