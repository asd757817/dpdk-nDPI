C=gcc
CXX=g++
CFLAGS=-g -I$(nDPI_src)/src/include -g -O2
LIBNDPI=$(nDPI_src)/src/lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lpcap -lpthread -lm

all: test

test: $(LIBNDPI)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS) Makefile
    $(CC) $(CFLAGS) -c $< -o $@

dpdk:
	make -f Makefile.dpdk

