#ifndef _PATTERN_MATCHING_H_
#define _PATTERN_MATCHING_H_

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ndpi_api.h"
#include "ndpi_config.h"
#include "snort_rule_parser.h"

/*
 * Include PCRE2 library.
 * Use DFA mode for pattern searching.
 */
#include <pcre.h>
pcre *re;
void pcre2_init();
void pcre_PS_release();
bool pcre_search(uint8_t l3_protocol,
                 uint16_t app_protocol,
                 uint16_t sport,
                 uint16_t dport,
                 char *payload);


/*
 * Include hyperscan library
 */
#include <hs/hs.h>
bool hs_search(uint8_t l3_protocol,
               uint16_t app_protocol,
               uint16_t sport,
               uint16_t dport,
               char *payload);

/*
 * Initialize all for PCRE2 and hyperscan.
 * Traverse all dst_port leaves in patterns_tree and
 * compile PCRE expressions on that node.
 */
void pattern_search_module_init();

/*
 * Release all memeories used in searching.
 * Free pattern_node, patterns_tree.
 */
void pattern_search_module_release();

#endif
