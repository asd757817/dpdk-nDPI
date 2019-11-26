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
#include "api_test.c"


void test_lib() {
	struct timeval end;
	u_int64_t processing_time_usec, setup_time_usec;
	long thread_id;

#ifdef DEBUG_TRACE
	if(trace) fprintf(trace, "Num threads: %d\n", num_threads);
#endif

	for(thread_id = 0; thread_id < num_threads; thread_id++) {
		pcap_t *cap;

#ifdef DEBUG_TRACE
		if(trace) fprintf(trace, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

		cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
		setupDetection(thread_id, cap);
	}

	gettimeofday(&begin, NULL);

	int status;
	void * thd_res;

	/* Running processing threads */
	for(thread_id = 0; thread_id < num_threads; thread_id++) {
		status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
		/* check pthreade_create return value */
		if(status != 0) {
			fprintf(stderr, "error on create %ld thread\n", thread_id);
			exit(-1);
		}
	}
	/* Waiting for completion */
	for(thread_id = 0; thread_id < num_threads; thread_id++) {
		status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
		/* check pthreade_join return value */
		if(status != 0) {
			fprintf(stderr, "error on join %ld thread\n", thread_id);
			exit(-1);
		}
		if(thd_res != NULL) {
			fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
			exit(-1);
		}
	}

	gettimeofday(&end, NULL);
	processing_time_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
	setup_time_usec = begin.tv_sec*1000000 + begin.tv_usec - (startup_time.tv_sec*1000000 + startup_time.tv_usec);

	/* Printing cumulative results */
	printResults(processing_time_usec, setup_time_usec);

	for(thread_id = 0; thread_id < num_threads; thread_id++) {
		if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
			pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

		terminateDetection(thread_id);
	}
}

