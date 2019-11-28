/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-19 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_config.h"
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>
#include <math.h>
#include "ndpi_api.h"
#include "uthash.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libgen.h>

#include "reader_util.h"
#include "ndpi_example.h"

/* MAIN FUNCTION */
int main(int argc, char **argv) {
    int i;

    if(ndpi_get_api_version() != NDPI_API_VERSION) {
        printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
        return(-1);
    }

    /* Internal checks */
    automataUnitTest();
    serializerUnitTest();
    analyzeUnitTest();

    gettimeofday(&startup_time, NULL);
    ndpi_info_mod = ndpi_init_detection_module(ndpi_no_prefs);

    if(ndpi_info_mod == NULL) return -1;

    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

    parseOptions(argc, argv);

    if(!quiet_mode) {
        printf("\n-----------------------------------------------------------\n"
                "* NOTE: This is demo app to show *some* nDPI features.\n"
                "* In this demo we have implemented only some basic features\n"
                "* just to show you what you can do with the library. Feel \n"
                "* free to extend it and send us the patches for inclusion\n"
                "------------------------------------------------------------\n\n");

        printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);
    }

    signal(SIGINT, sigproc);

    for(i=0; i<num_loops; i++)
        test_lib();

    if(results_path)  free(results_path);
    if(results_file)  fclose(results_file);
    if(extcap_dumper) pcap_dump_close(extcap_dumper);
    if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod);
    if(csv_fp)        fclose(csv_fp);

    return 0;
}

#if 0
/**
 * @brief A faster replacement for inet_ntoa().
 */
char* intoaV4(u_int32_t addr, char* buf, u_int16_t bufLen) {
  char *cp;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    if(n > 1)
      *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  return(cp);
}

/**
 * @brief Print debug
 */
static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) {
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  if(log_level <= nDPI_LogLevel) {
    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else
      extra_msg = "DEBUG: ";

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);
  }

  va_end(va_ap);
}
#endif
