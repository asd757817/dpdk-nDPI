#ifndef _PATTERN_MATCHING_H_
#define _PATTERN_MATCHING_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "ndpi_api.h"
#include "ndpi_config.h"
#include "snort_rule_parser.h"

/*
 * Automaton pattern search algorithm. (AC algorithm)
 * nDPI third-party library
 */
void *automata_patterns;
void automata_PM_init();
void automata_PM_release();
bool automata_PM_search(char *str);

/*
 * Include pcre library.
 * Use dfa mode for pattern searching.
 */
#include <pcre.h>
pcre *re;
int nb_real_patterns;
void pcre_PS_init();
void pcre_PS_release();
bool pcre_PS_search(char *str);

/* Initialize all modules */
void pattern_search_module_init();

#endif
