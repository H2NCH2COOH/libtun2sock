AM_CFLAGS = -O2 -g -Wall -Wextra
AM_CPPFLAGS = -I../include

lib_LTLIBRARIES = libtun2sock.la
libtun2sock_la_LDFLAGS = -version-info @VERSION_MAJOR@:@VERSION_MINOR@

libtun2sock_la_SOURCES = conntrack.c \
    conntrack.h \
    icmp.c \
    icmp.h \
    ipv4.c \
    ipv4.h \
    ipv6.c \
    ipv6.h \
    lookup3.c \
    pool.c \
    pool.h \
    protocol.h \
    tcp.c \
    tcp.h \
    tun2sock.c \
    udp.c \
    udp.h
