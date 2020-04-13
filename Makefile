ifeq ($(RTE_SDK),)
	RTE_SDK = $(HOME)/DPDK
	RTE_TARGET = build
endif

RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

APP = nDPIexe
LIBNDPI = $(nDPI_src)/src/lib/libndpi.a

SRCS-y := ndpiReader.c reader_util.c intrusion_detection.c l3fwd_em.c l3fwd_lpm.c ndpi_detection.c pattern_matching.c snort_rule_parser.c

CFLAGS += -g
CFLAGS += -Wno-strict-prototypes -Wno-missing-prototypes -Wno-missing-declarations -Wno-unused-parameter -I $(nDPI_src)/src/include -g -O2 -DUSE_DPDK -DUSE_NQUEUE

LDLIBS = $(LIBNDPI) -lpcap -lpcre -lgcc_s
include $(RTE_SDK)/mk/rte.extapp.mk

