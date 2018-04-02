CC ?= gcc
CFLAGS += -std=c99 -Wall -Wextra -O2

OBJECTS  = ipv4.o
OBJECTS += ipv6.o
OBJECTS += tcp.o
OBJECTS += udp.o
OBJECTS += lookup3.o
OBJECTS += pool.o
OBJECTS += conntrack.o
OBJECTS += tun2sock.o

HEADERS  = protocol.h
HEADERS += ipv4.h
HEADERS += ipv6.h
HEADERS += tcp.h
HEADERS += udp.h
HEADERS += pool.h
HEADERS += conntrack.h
HEADERS += tun2sock.h

all: tun10

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

tun10: tun10.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-rm -f *.o tun10
