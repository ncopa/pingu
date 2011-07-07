
TARGETS = mtu pingu
VERSION = 0.5

CFLAGS ?= -g
CFLAGS += -DPINGU_VERSION=\"$(VERSION)\"
CFLAGS += -Wall -Wstrict-prototypes -D_GNU_SOURCE -std=gnu99

prefix = /usr
BINDIR = $(prefix)/bin
DESTDIR ?=

INSTALL = install
INSTALLDIR = $(INSTALL) -d

pingu_OBJS = \
	icmp.o \
	log.o \
	pingu.o \
	xlib.o \
	pingu_burst.o \
	pingu_iface.o \
	pingu_ping.o \
	pingu_host.o

pingu_LIBS = -lev

mtu_OBJS = \
	mtu.o \
	netlink.o \
	icmp.o

ALL_OBJS= $(pingu_OBJS) $(mtu_OBJS)

all: $(TARGETS)

pingu: $(pingu_OBJS)
	$(CC) $(LDFLAGS) $(pingu_OBJS) $(pingu_LIBS) -o $@

mtu: $(mtu_OBJS)

install: $(TARGETS)
	$(INSTALLDIR) $(DESTDIR)/$(BINDIR)
	$(INSTALL) $(TARGETS) $(DESTDIR)/$(BINDIR)
	
clean:
	rm -f $(TARGETS) $(ALL_OBJS)
